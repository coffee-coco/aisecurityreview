"""Reference cards (markdown + YAML frontmatter in ./cards) loaded into threat-model prompts on demand.

Progressive disclosure: only the cards whose ``app_types`` match the system are put in the prompt, and
every framework identifier the model returns (OWASP codes, ATT&CK / ATLAS technique ids) is validated
against the catalogue in the loaded cards - unknown ids are dropped. Adding a card is a single-file change.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

CARD_DIR = Path(__file__).resolve().parent / "cards"
ORDER = ("owasp_web", "genai", "agentic", "insider_threat", "mitre_enterprise", "mitre_atlas")

# threat field -> pattern that finds the catalogued ids in a card body
CATALOGUE_RE = {
    "owasp_top10": re.compile(r"\b(A(?:0[1-9]|10):2025)\b"),
    "owasp_llm": re.compile(r"\b(LLM(?:0[1-9]|10))\b"),
    "owasp_asi": re.compile(r"\b(ASI(?:0[1-9]|10))\b"),
    "mitre_attack": re.compile(r"\*\*(T\d{4})\*\*"),
    "mitre_atlas": re.compile(r"\*\*(AML\.T\d{4})\*\*"),
}


def _split(text: str) -> tuple[dict, str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, text
    meta = yaml.safe_load(text[4:end]) or {}
    return (meta if isinstance(meta, dict) else {}), text[end + 5:].lstrip("\n")


@lru_cache(maxsize=1)
def cards() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(CARD_DIR.glob("*.md")):
        meta, body = _split(p.read_text(encoding="utf-8"))
        if not meta.get("name"):
            continue
        name = str(meta["name"])
        out[name] = {
            "name": name, "title": str(meta.get("title") or name), "when_to_load": str(meta.get("when_to_load") or ""),
            "app_types": [str(a) for a in meta.get("app_types") or []],
            "adds_fields": [str(f) for f in meta.get("adds_fields") or []],
            "version": str(meta.get("version") or ""), "source": str(meta.get("source") or ""), "body": body,
        }
    return dict(sorted(out.items(), key=lambda kv: ORDER.index(kv[0]) if kv[0] in ORDER else len(ORDER)))


def select_cards(app_type: str) -> list[str]:
    return [n for n, c in cards().items() if app_type in c["app_types"]]


def prompt_section(names: list[str]) -> str:
    parts = []
    for n in names:
        c = cards()[n]
        parts.append(f"\n\n## Reference card: {c['title']} ({c['version']})\n\n{c['body'].strip()}")
    return "".join(parts)


def allowed_ids(names: list[str]) -> dict[str, set[str]]:
    """Catalogued identifiers per threat field, from the loaded cards only."""
    out: dict[str, set[str]] = {f: set() for f in CATALOGUE_RE}
    for n in names:
        c = cards().get(n)
        if not c:
            continue
        for f in c["adds_fields"]:
            if f in CATALOGUE_RE:
                out[f] |= set(CATALOGUE_RE[f].findall(c["body"]))
    return out


def _norm_one(field: str, value) -> str | None:
    s = str(value or "").upper()
    if field == "owasp_top10":
        m = re.search(r"\bA(0?[1-9]|10)\b", s)
        return f"A{int(m.group(1)):02d}:2025" if m else None
    if field == "owasp_llm":
        m = re.search(r"LLM\s*0?(\d{1,2})", s)
        return f"LLM{int(m.group(1)):02d}" if m else None
    if field == "owasp_asi":
        m = re.search(r"ASI\s*0?(\d{1,2})", s)
        return f"ASI{int(m.group(1)):02d}" if m else None
    if field == "mitre_atlas":
        m = re.search(r"AML\.T\d{4}", s)
        return m.group(0) if m else None
    if field == "mitre_attack":
        m = re.search(r"(?<![A-Z.])T\d{4}", s)  # parent technique; sub-technique suffix dropped
        return m.group(0) if m else None
    return None


def clean_code(field: str, value, allowed: dict[str, set[str]]) -> str | None:
    code = _norm_one(field, value)
    return code if code and code in allowed.get(field, set()) else None


def clean_codes(field: str, values, allowed: dict[str, set[str]], limit: int = 6) -> list[str]:
    if isinstance(values, (str, dict)):
        values = [values]
    out: list[str] = []
    for v in values if isinstance(values, list) else []:
        code = _norm_one(field, v.get("id") if isinstance(v, dict) else v)
        if code and code in allowed.get(field, set()) and code not in out:
            out.append(code)
    return out[:limit]
