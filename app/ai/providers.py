"""Pluggable LLM providers called over plain HTTP (no vendor SDKs).

Supported: OpenAI (and any OpenAI-compatible endpoint - Azure OpenAI proxy,
OpenRouter, LM Studio, vLLM...), Anthropic, Google Gemini, Ollama, plus an
offline ``heuristic`` mode that needs no model at all.

Determinism: every call uses temperature 0 and a fixed seed where the provider
supports it, and responses are cached in SQLite keyed by a hash of
(provider, model, prompt version, system, user, attachment hashes). Asking the
same question about the same inputs therefore always returns the same answer
unless the caller explicitly forces a refresh.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field

import httpx

from ..config import DEFAULT_MODELS

PROVIDERS = ["heuristic", "openai", "anthropic", "gemini", "ollama"]
TIMEOUT = httpx.Timeout(300.0, connect=15.0)
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
                            use_cache: bool = True) -> dict:
        from .. import db  # local import: db has no dependency on providers

        attachments = [a for a in (attachments or []) if self.supports(a.kind)]
        key = self.cache_key(system, user, attachments)
        if use_cache:
            with db.tx() as conn:
                row = conn.execute("SELECT value FROM ai_cache WHERE key = ?", (key,)).fetchone()
            if row:
                self.last_cached = True
                return json.loads(row["value"])
        self.last_cached = False
        fn = {
            "openai": self._openai, "anthropic": self._anthropic,
            "gemini": self._gemini, "ollama": self._ollama,
        }.get(self.provider)
        if fn is None:
            raise ProviderError(f"Unknown provider '{self.provider}'")
        text = await self._send(fn, system, user, attachments)
        result = parse_json_output(text)
        if result is None:  # one retry with an explicit nudge; cached under the original key
            text = await self._send(fn, system, user + RETRY_NUDGE, attachments)
            result = parse_json_output(text)
        if result is None:
            raise ProviderError(f"{self.provider} did not return valid JSON: {text[:300]}")
        with db.tx() as conn:
            conn.execute("INSERT OR REPLACE INTO ai_cache (key, provider, value, created_at) VALUES (?, ?, ?, ?)",
                         (key, self.label, json.dumps(result), db.now()))
        return result

    async def _send(self, fn, system: str, user: str, attachments: list[Attachment]) -> str:
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                return await fn(client, system, user, attachments)
        except httpx.HTTPStatusError as e:
            body = e.response.text[:400]
            raise ProviderError(f"{self.provider} returned HTTP {e.response.status_code}: {body}") from e
        except httpx.HTTPError as e:
            raise ProviderError(f"{self.provider} request failed: {e!r}") from e

    # ------------------------------------------------------------------ vendors
    async def _openai(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> str:
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
        return r.json()["choices"][0]["message"]["content"]

    async def _anthropic(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> str:
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
        return "".join(b.get("text", "") for b in r.json().get("content", []))

    async def _gemini(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> str:
        if not self.api_key:
            raise ProviderError("Gemini API key is not configured")
        parts: list[dict] = [{"inline_data": {"mime_type": a.mime, "data": a.b64}} for a in att]
        parts.append({"text": user})
        r = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            headers={"x-goog-api-key": self.api_key},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": parts}],
                "generationConfig": {"responseMimeType": "application/json", "temperature": 0, "topK": 1,
                                     "seed": SEED, "maxOutputTokens": 32768},
            },
        )
        r.raise_for_status()
        cands = r.json().get("candidates") or []
        if not cands:
            raise ProviderError(f"Gemini returned no candidates: {r.text[:300]}")
        return "".join(p.get("text", "") for p in cands[0].get("content", {}).get("parts", []))

    async def _ollama(self, client: httpx.AsyncClient, system: str, user: str, att: list[Attachment]) -> str:
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
        return r.json()["message"]["content"]


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
