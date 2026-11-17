"""Pluggable LLM providers called over plain HTTP (no vendor SDKs).

Supported: OpenAI (and any OpenAI-compatible endpoint - Azure OpenAI proxy,
OpenRouter, LM Studio, vLLM...), Anthropic, Google Gemini, Ollama, plus an
offline ``heuristic`` mode that needs no model at all.

Determinism: every call uses temperature 0 and a fixed seed where the provider
supports it, and responses are cached per workspace in Postgres keyed by a hash of
(provider, model, prompt version, system, user, attachment hashes). Asking the
same question about the same inputs therefore always returns the same answer
unless the caller explicitly forces a refresh.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import itertools
import json
import logging
import re
import time
from dataclasses import dataclass, field

import httpx

from ..config import AI_READ_TIMEOUT, DEFAULT_MODELS

log = logging.getLogger("sentinel.ai")
_call_ids = itertools.count(1)
TRUNCATED = {"max_tokens", "length", "MAX_TOKENS"}

PROVIDERS = ["heuristic", "openai", "anthropic", "gemini", "ollama"]
TIMEOUT = httpx.Timeout(AI_READ_TIMEOUT, connect=15.0)
SEED = 7
PROMPT_VERSION = "2"

# Rough prompt budgets (characters) so large inputs (documents / code) fit the model context.
CONTEXT_CHARS = {"gemini": 900_000, "anthropic": 500_000, "openai": 350_000, "ollama": 40_000}
# Which attachment types each provider can read natively.
MEDIA_SUPPORT = {
    "gemini": {"image", "pdf"},
    "anthropic": {"image", "pdf"},
    "openai": {"image"},
    "ollama": {"image"},
}


class ProviderError(RuntimeError):
    pass


@dataclass
class Attachment:
    mime: str
    data: bytes
    name: str = ""

    @property
    def kind(self) -> str:
        return "pdf" if self.mime == "application/pdf" else "image" if self.mime.startswith("image/") else "other"

    @property
    def b64(self) -> str:
        return base64.b64encode(self.data).decode()

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def extract_json(text: str) -> dict:
    """Parse a JSON object from model output, tolerating code fences / chatter."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start:end + 1])
        raise


def extract_json_object(content: str) -> dict | None:
    """Fallback recovery: strip a leading fence, else take the first '{' to the last '}' of the raw output."""
    if not content:
        return None
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned
        cleaned = cleaned[:-3] if cleaned.endswith("```") else cleaned
    candidates = [cleaned.strip()]
    start, end = content.find("{"), content.rfind("}")
    if start != -1 and end > start:
        candidates.append(content[start:end + 1])
    for c in candidates:
        try:
            parsed = json.loads(c)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def parse_json_output(text: str) -> dict | None:
    if not text:
        return None
    try:
        result = extract_json(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, ValueError):
        pass
    return extract_json_object(text)


RETRY_NUDGE = "\n\nReturn only valid JSON: a single JSON object, with no prose and no code fences."


@dataclass
class LLM:
    provider: str
    model: str
    api_key: str = ""
    base_url: str = ""
    last_cached: bool = field(default=False, compare=False)

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.model}"

    @property
    def context_chars(self) -> int:
        return CONTEXT_CHARS.get(self.provider, 100_000)

    def supports(self, kind: str) -> bool:
        return kind in MEDIA_SUPPORT.get(self.provider, set())

    def cache_key(self, system: str, user: str, attachments: list[Attachment]) -> str:
        h = hashlib.sha256()
        for part in (self.provider, self.model, PROMPT_VERSION, system, user, *[a.digest for a in attachments]):
            h.update(part.encode())
            h.update(b"\x00")
        return h.hexdigest()

    async def complete_json(self, system: str, user: str, attachments: list[Attachment] | None = None,
                            use_cache: bool = True, tag: str = "") -> dict:
        from .. import db  # local import: db has no dependency on providers

        call = f"call-{next(_call_ids)}" + (f" {tag}" if tag else "")
        attachments = [a for a in (attachments or []) if self.supports(a.kind)]
        key = self.cache_key(system, user, attachments)
        if use_cache:
            with db.tx() as conn:
                row = conn.execute("SELECT value FROM ai_cache WHERE workspace_id = %s AND key = %s",
                                   (db.workspace_id(), key)).fetchone()
            if row:
                self.last_cached = True
                log.info("[%s] %s cache hit (key %s)", call, self.label, key[:12])
                return json.loads(row["value"])
        self.last_cached = False
        fn = {
            "openai": self._openai, "anthropic": self._anthropic,
            "gemini": self._gemini, "ollama": self._ollama,
        }.get(self.provider)
        if fn is None:
            raise ProviderError(f"Unknown provider '{self.provider}'")
        text = await self._send(fn, system, user, attachments, call)
        result = parse_json_output(text)
        if result is None:  # one retry with an explicit nudge; cached under the original key
            log.warning("[%s] %s response was not valid JSON - retrying once", call, self.label)
            text = await self._send(fn, system, user + RETRY_NUDGE, attachments, call + " retry")
            result = parse_json_output(text)
        if result is None:
            log.error("[%s] %s gave up: no valid JSON after retry", call, self.label)
            raise ProviderError(f"{self.provider} did not return valid JSON: {text[:300]}")
        with db.tx() as conn:
            conn.execute("INSERT INTO ai_cache (workspace_id, key, provider, value, created_at) "
                         "VALUES (%s, %s, %s, %s, %s) "
                         "ON CONFLICT (workspace_id, key) DO UPDATE SET provider = excluded.provider, "
                         "value = excluded.value, created_at = excluded.created_at",
                         (db.workspace_id(), key, self.label, json.dumps(result), db.now()))
        return result

    async def _send(self, fn, system: str, user: str, attachments: list[Attachment], call: str = "") -> str:
        from .. import jobs  # local import: jobs has no dependency on providers

        await asyncio.to_thread(jobs.check_ai_budget)
        t0 = time.monotonic()
        log.info("[%s] -> %s request: system=%d chars, user=%d chars, attachments=%d", call, self.label,
                 len(system), len(user), len(attachments))
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                text, meta = await fn(client, system, user, attachments)
        except httpx.HTTPStatusError as e:
            body = e.response.text[:400]
            log.warning("[%s] <- %s HTTP %s after %.1fs: %s", call, self.label, e.response.status_code,
                        time.monotonic() - t0, body)
            raise ProviderError(f"{self.provider} returned HTTP {e.response.status_code}: {body}") from e
        except httpx.HTTPError as e:
            log.warning("[%s] <- %s failed after %.1fs: %r", call, self.label, time.monotonic() - t0, e)
            raise ProviderError(f"{self.provider} request failed: {e!r}") from e
        log.info("[%s] <- %s %.1fs, response=%d chars, stop=%s, usage=%s", call, self.label,
                 time.monotonic() - t0, len(text), meta.get("stop"), meta.get("usage"))
        await asyncio.to_thread(jobs.record_ai_call, total_tokens(meta.get("usage")))
        if meta.get("stop") in TRUNCATED:
            log.warning("[%s] %s output hit the max-token limit - response is truncated", call, self.label)
        return text

    # ------------------------------------------------------------------ vendors
    # Each returns (text, {"stop": stop/finish reason, "usage": token usage}) for logging.
    async def _openai(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> tuple:
        if not self.api_key and "api.openai.com" in self.base_url:
            raise ProviderError("OpenAI API key is not configured")
        content: str | list = user
        if att:
            content = [{"type": "text", "text": user}] + [
                {"type": "image_url", "image_url": {"url": f"data:{a.mime};base64,{a.b64}"}} for a in att]
        r = await client.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"} if self.api_key else {},
            json={
                "model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}],
                "response_format": {"type": "json_object"},
                "temperature": 0,
                "seed": SEED,
            },
        )
        r.raise_for_status()
        j = r.json()
        choice = j["choices"][0]
        return choice["message"]["content"], {"stop": choice.get("finish_reason"), "usage": j.get("usage")}

    async def _anthropic(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> tuple:
        if not self.api_key:
            raise ProviderError("Anthropic API key is not configured")
        blocks: list[dict] = []
        for a in att:
            typ = "document" if a.kind == "pdf" else "image"
            blocks.append({"type": typ, "source": {"type": "base64", "media_type": a.mime, "data": a.b64}})
        blocks.append({"type": "text", "text": user})
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            json={
                "model": self.model,
                "max_tokens": 16000,
                "temperature": 0,
                "system": system + "\nRespond with a single JSON object only.",
                "messages": [{"role": "user", "content": blocks}],
            },
        )
        r.raise_for_status()
        j = r.json()
        return ("".join(b.get("text", "") for b in j.get("content", [])),
                {"stop": j.get("stop_reason"), "usage": j.get("usage")})

    async def _gemini(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> tuple:
        if not self.api_key:
            raise ProviderError("Gemini API key is not configured")
        parts: list[dict] = [{"inline_data": {"mime_type": a.mime, "data": a.b64}} for a in att]
        parts.append({"text": user})
        # Streamed (SSE) so long generations keep the connection active instead of hitting the read timeout.
        # Thought summaries are requested only to keep data flowing while the model thinks; they are discarded.
        config: dict = {"responseMimeType": "application/json", "temperature": 0, "topK": 1,
                        "seed": SEED, "maxOutputTokens": 32768}
        if not re.match(r"gemini-(1\.|2\.0)", self.model):
            config["thinkingConfig"] = {"includeThoughts": True}
        texts: list[str] = []
        stop = usage = None
        last = ""
        async with client.stream(
            "POST",
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:streamGenerateContent",
            params={"alt": "sse"},
            headers={"x-goog-api-key": self.api_key},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": parts}],
                "generationConfig": config,
            },
        ) as r:
            if r.is_error:
                await r.aread()
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                last = line[5:].strip()
                j = json.loads(last)
                usage = j.get("usageMetadata") or usage
                for c in (j.get("candidates") or [])[:1]:
                    texts.extend(p.get("text", "") for p in c.get("content", {}).get("parts", [])
                                 if not p.get("thought"))
                    stop = c.get("finishReason") or stop
        if not texts and stop is None:
            raise ProviderError(f"Gemini returned no candidates: {last[:300]}")
        return "".join(texts), {"stop": stop, "usage": usage}

    async def _ollama(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> tuple:
        msg: dict = {"role": "user", "content": user}
        if att:
            msg["images"] = [a.b64 for a in att]
        r = await client.post(
            f"{self.base_url.rstrip('/')}/api/chat",
            json={
                "model": self.model,
                "messages": [{"role": "system", "content": system}, msg],
                "format": "json",
                "stream": False,
                "options": {"temperature": 0, "seed": SEED},
            },
        )
        r.raise_for_status()
        j = r.json()
        return j["message"]["content"], {
            "stop": j.get("done_reason"),
            "usage": {"prompt_tokens": j.get("prompt_eval_count"), "output_tokens": j.get("eval_count")}}


def total_tokens(usage) -> int:
    """Total tokens from any provider's usage block (OpenAI, Anthropic, Gemini, Ollama)."""
    if not isinstance(usage, dict):
        return 0
    for key in ("total_tokens", "totalTokenCount"):
        if isinstance(usage.get(key), int):
            return usage[key]
    return sum(v for k, v in usage.items() if isinstance(v, int) and k in (
        "prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "output_tokens_count"))


def build_llm(settings: dict) -> LLM | None:
    """Return an LLM for the configured provider, or None for heuristic mode."""
    provider = (settings.get("ai_provider") or "heuristic").lower()
    if provider == "heuristic":
        return None
    model = settings.get("ai_model") or DEFAULT_MODELS.get(provider, "")
    if provider == "openai":
        return LLM(provider, model, settings.get("openai_api_key", ""), settings.get("openai_base_url", ""))
    if provider == "anthropic":
        return LLM(provider, model, settings.get("anthropic_api_key", ""))
    if provider == "gemini":
        return LLM(provider, model, settings.get("gemini_api_key", ""))
    if provider == "ollama":
        return LLM(provider, model, base_url=settings.get("ollama_base_url", "http://localhost:11434"))
    raise ProviderError(f"Unknown provider '{provider}'")
