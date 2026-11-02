"""Loads the risk and mitigating-control libraries and evaluates them against a review profile.

Everything here is deterministic: same review profile -> same suggestions, same order.
"""
from __future__ import annotations

from functools import lru_cache

import yaml

from .config import ROOT
from .profile import CLASS_IMPACT, effective_class, profile_text, profile_tokens, risk_rating

LIB_DIR = ROOT / "catalog"


@lru_cache(maxsize=1)
def mitigation_library() -> dict[str, dict]:
    data = yaml.safe_load((LIB_DIR / "mitigation_library.yaml").read_text()) or []
    return {m["id"]: {**m, "nist": m.get("nist", []), "keywords": m.get("keywords", [])} for m in data}


@lru_cache(maxsize=1)
def risk_library() -> list[dict]:
    return yaml.safe_load((LIB_DIR / "risk_library.yaml").read_text()) or []


def _token_ok(tok: str, tokens: set[str], text: str) -> bool:
    if tok.startswith("kw:"):
        return tok[3:].lower() in text
    return tok in tokens


def condition_matches(when: dict, tokens: set[str], text: str) -> tuple[bool, list[str]]:
    """Return (matched, tokens that triggered it)."""
    hits: list[str] = []
    for tok in when.get("all", []):
        if not _token_ok(tok, tokens, text):
            return False, []
        hits.append(tok)
    anys = when.get("any", [])
    if anys:
        found = [t for t in anys if _token_ok(t, tokens, text)]
        if not found:
            return False, []
        hits += found
    if any(_token_ok(t, tokens, text) for t in when.get("none", [])):
        return False, []
    return True, hits


TOKEN_LABEL = {
    "exposure": "exposure", "class": "classification", "class>": "classification", "data": "data",
    "system": "system type", "tech": "platform", "service": "service", "flag": "", "code": "code finding",
}


def explain(hits: list[str]) -> str:
    nice = []
    for h in hits:
        if h.startswith("kw:"):
            nice.append(f"mentions “{h[3:]}”")
            continue
        k, _, v = h.partition(":") if ":" in h else h.partition(">=")
        if h.startswith("class>="):
            nice.append(f"classification ≥ {h[7:]}")
        elif k == "flag":
            nice.append(v.replace("_", " "))
        elif k in ("new", "change") or not v:
            nice.append("new initiative" if h == "new" else "change to existing system" if h == "change" else h)
        else:
            nice.append(f"{TOKEN_LABEL.get(k, k)} {v.replace('_', ' ')}".strip())
    return "Matched: " + ", ".join(dict.fromkeys(nice))


def library_risks(review: dict) -> list[dict]:
    """All library risks that apply to this review profile, in library order."""
    tokens, text = profile_tokens(review), profile_text(review)
    cls = effective_class(review)
    out = []
    for r in risk_library():
        ok, hits = condition_matches(r.get("when", {}), tokens, text)
        if not ok:
            continue
        impact = CLASS_IMPACT[cls] if r.get("impact") == "by_class" else r.get("impact", "moderate")
        likelihood = r.get("likelihood", "possible")
        out.append({
            "key": f"lib:{r['id']}", "library_ref": r["id"], "title": r["title"], "risk": r["risk"],
            "likelihood": likelihood, "impact": impact, "rating": risk_rating(likelihood, impact),
            "recommendation": r.get("recommendation", ""), "csf": r.get("csf", []),
            "mitigations": [m for m in r.get("mitigations", []) if m in mitigation_library()],
            "rationale": explain(hits), "source": "library",
        })
    return out
