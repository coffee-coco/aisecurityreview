"""AI assistance for reviewers: wording, per-item suggestions and new-risk discovery.

Every function has a deterministic offline path. When an LLM is configured it is called with
temperature 0 / fixed seed and its JSON is cached (see providers.py), then validated against the
libraries and the review's register - so suggestions are reproducible and always reference real
controls.
"""
from __future__ import annotations

import json
import re

from ..catalog import Catalog, base_control
from ..items import item_controls
from ..library import library_risks, mitigation_library
from ..profile import (
    CLASS_IMPACT, CLASSIFICATIONS, DATA_TYPES, IMPACT, LIKELIHOOD, SEVERITY_TO_LI, data_phrase, effective_class,
    profile_summary, risk_rating, similarity, tokens,
)
from .providers import LLM, ProviderError

# --------------------------------------------------------------------------- writing
FIELD_GUIDE = {
    "answer": "the project team's response explaining how the requirement is met (design, controls, evidence). "
              "Factual and specific.",
    "notes": "security reviewer notes: findings, conditions of approval and required actions.",
    "risk": "a risk statement structured as: 'There is a risk that <threat event> caused by <cause/vulnerability>, "
            "resulting in <consequence>.'",
    "impact_description": "the business impact if the risk occurs: confidentiality/integrity/availability, data "
                          "and classification affected, customers, regulatory and financial consequences.",
    "recommendation": "an actionable security recommendation: imperative voice, specific, testable, starting with "
                      "a verb.",
    "title_question": "a single, clear review question ending with a question mark.",
    "title_risk": "a short risk title (max 12 words) naming the threat and asset.",
    "title_recommendation": "a short imperative recommendation title (max 12 words).",
    "description": "a clear description of the system/change: purpose, users, data, hosting, integrations.",
    "mitigation_description": "a mitigating control description: what is implemented, where, who operates it and "
                              "how it is verified.",
    "decision_notes": "a review decision with numbered conditions of approval and accepted risks.",
}

WRITE_SYSTEM = """You are a principal security architect editing text in a security design review.
Mode "improve": restructure and improve the wording of the provided text so it is clear, concise and uses
standard security terminology. Preserve every fact and intent from the original. Do NOT invent new facts,
systems, numbers, dates or commitments. Keep roughly the same length unless the structure requires otherwise.
Mode "draft": write the text from the context provided. Where a fact is unknown, insert a [placeholder] for
the project team to complete rather than guessing.
Return ONLY JSON: {"text": "..."}"""

TERMS = {
    "aws": "AWS", "gcp": "GCP", "mfa": "MFA", "sso": "SSO", "tls": "TLS", "ssl": "SSL", "api": "API", "apis": "APIs",
    "iam": "IAM", "kms": "KMS", "pii": "PII", "s3": "S3", "rds": "RDS", "vpc": "VPC", "waf": "WAF", "siem": "SIEM",
    "soc": "SOC", "rbac": "RBAC", "oidc": "OIDC", "saml": "SAML", "jwt": "JWT", "https": "HTTPS", "http": "HTTP",
    "pci": "PCI", "dss": "DSS", "ddos": "DDoS", "sftp": "SFTP", "vpn": "VPN", "cmk": "CMK", "eks": "EKS",
    "aks": "AKS", "gke": "GKE", "llm": "LLM", "ai": "AI", "url": "URL", "sql": "SQL", "xss": "XSS", "csrf": "CSRF",
    "ci/cd": "CI/CD", "cicd": "CI/CD", "rto": "RTO", "rpo": "RPO", "hsts": "HSTS", "csp": "CSP", "edr": "EDR",
    "dlp": "DLP", "azure": "Azure", "entra": "Entra", "okta": "Okta", "github": "GitHub", "terraform": "Terraform",
    "kubernetes": "Kubernetes", "docker": "Docker", "pam": "PAM", "dr": "DR", "ha": "HA", "id": "ID",
}
SHORTHAND = {r"\bw/o\b": "without", r"\bw/\b": "with", r"\bb/c\b": "because", r"\bpls\b": "please",
             r"\bu\b": "you", r"\bthru\b": "through", r"\bimpl\b": "implementation", r"\bprod\b": "production",
             r"\bnon-prod\b": "non-production", r"\benv\b": "environment", r"\bauth\b": "authentication",
             r"\bconfig\b": "configuration", r"\binfo\b": "information", r"\bmgmt\b": "management"}


def _casefix(s: str) -> str:
    for pat, rep in SHORTHAND.items():
        s = re.sub(pat, rep, s, flags=re.I)

    def fix(m: re.Match) -> str:
        w = m.group(0)
        return TERMS.get(w.lower(), w)
    return re.sub(r"[A-Za-z][A-Za-z0-9/]*", fix, s)


def _sentence_case(line: str) -> str:
    line = re.sub(r"\s+", " ", line).strip()
    if not line:
        return line
    line = re.sub(r"(^|[.!?]\s+)([a-z])", lambda m: m.group(1) + m.group(2).upper(), line)
    return line


def normalize_text(text: str, field: str) -> str:
    """Deterministic offline 'improve wording': tidy, standard terms, sentence case, structure."""
    lines = [ln for ln in (text or "").replace("\r", "").split("\n")]
    out = []
    for ln in lines:
        raw = ln.strip()
        if not raw:
            out.append("")
            continue
        bullet = re.match(r"^([-*•]|\d+[.)])\s+", raw)
        prefix = ""
        if bullet:
            prefix = "- " if not bullet.group(1)[0].isdigit() else bullet.group(0)
            raw = raw[bullet.end():]
        s = _sentence_case(_casefix(raw))
        if s and s[-1] not in ".!?:;" and not prefix and len(s.split()) > 3:
            s += "."
        out.append(prefix + s)
    result = re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()
    low = result.lower()
    if field == "risk" and result and not low.startswith(("there is a risk", "risk that", "the risk", "risk of")):
        result = "There is a risk that " + result[0].lower() + result[1:]
    if field == "recommendation" and result:
        result = re.sub(r"^(we|you|they|the team)?\s*(should|must|need to|needs to)\s+", "", result, flags=re.I)
        result = result[0].upper() + result[1:]
    if field == "title_question" and result and not result.endswith("?"):
        result = result.rstrip(".") + "?"
    return result


def _item_context(review: dict, item: dict | None, mitigations: list[dict]) -> dict:
    ctx = {"review": {"title": review.get("title"), "description": (review.get("description") or "")[:3000],
                      "profile": profile_summary(review),
                      "design_summary": (review.get("design") or {}).get("summary", "")}}
    if item:
        sub = item.get("subcategory") or {}
        ctx["item"] = {
            "type": item.get("kind"), "label": item.get("label"),
            "question": item.get("display_title"), "nist_csf_outcome": sub.get("text"),
            "answer": item.get("answer"), "risk": item.get("risk"), "recommendation": item.get("recommendation"),
            "impact": item.get("impact"), "likelihood": item.get("likelihood"),
            "linked_controls": [m["title"] for m in mitigations if m["id"] in item.get("mitigation_ids", [])],
        }
    return ctx


def draft_offline(review: dict, item: dict | None, field: str, mitigations: list[dict],
                  suggestions: dict | None) -> str:
    """Template-based draft when no AI provider is configured."""
    linked = [m for m in mitigations if item and m["id"] in item.get("mitigation_ids", [])]
    cls = effective_class(review)
    data = data_phrase(review.get("data_types"))
    if field == "answer":
        if linked:
            return ("This is addressed by the following controls:\n" +
                    "\n".join(f"- {m['title']}" + (f" - {m['description']}" if m['description'] else "")
                              for m in linked) + "\n\nEvidence: [link to design / configuration / ticket].")
        return "[Describe how the solution meets this requirement, the controls in place and supporting evidence.]"
    if field == "recommendation":
        if suggestions and suggestions.get("recommendation"):
            return suggestions["recommendation"]
        if linked:
            return f"Implement {linked[0]['title'].lower()} before go-live and provide evidence to the reviewer."
        return "[Recommended action, owner and target date.]"
    if field == "impact_description":
        return (f"If this risk is realised, {data} classified {CLASSIFICATIONS[cls]['label']} could be exposed or "
                f"altered, affecting customers and operations and potentially triggering regulatory notification "
                f"and reputational harm.")
    if field == "risk":
        title = (item or {}).get("display_title") or "a security weakness"
        return f"There is a risk that {title.rstrip('?').lower()} is exploited, resulting in unauthorised access to {data}."
    if field == "notes":
        return "Condition: [action required] by [date]. Owner: [name]."
    return "[Add details]"


async def write_text(review: dict, item: dict | None, field: str, text: str, mode: str,
                     mitigations: list[dict], llm: LLM | None) -> dict:
    mode = "improve" if mode == "improve" and (text or "").strip() else "draft"
    guide_key = field
    if field == "title":
        guide_key = f"title_{(item or {}).get('kind', 'question')}"
    if llm is not None:
        user = json.dumps({"mode": mode, "field": field, "field_guidance": FIELD_GUIDE.get(guide_key, ""),
                           "text": text, "context": _item_context(review, item, mitigations)}, indent=1)
        try:
            res = await llm.complete_json(WRITE_SYSTEM, user)
            out = str(res.get("text", "")).strip()
            if out:
                return {"text": out, "provider": llm.label, "source": "ai", "mode": mode, "cached": llm.last_cached}
        except ProviderError as e:
            fallback = normalize_text(text, guide_key) if mode == "improve" else draft_offline(
                review, item, field, mitigations, None)
            return {"text": fallback, "provider": "heuristic", "source": "heuristic", "mode": mode,
                    "warning": f"AI unavailable, used offline rules: {e}"}
    out = normalize_text(text, guide_key) if mode == "improve" else draft_offline(review, item, field, mitigations,
                                                                                    None)
    return {"text": out, "provider": "heuristic", "source": "heuristic", "mode": mode}


# --------------------------------------------------------------------------- per-item suggestions
def _item_text(item: dict) -> str:
    sub = item.get("subcategory") or {}
    return " ".join(str(x or "") for x in (item.get("display_title"), sub.get("text"), item.get("answer"),
                                            item.get("risk"), item.get("recommendation"), item.get("notes")))


def _score(item_text: str, item_ctrls: set[str], title: str, desc: str, nist: list[str],
           keywords: list[str]) -> tuple[float, list[str]]:
    reasons = []
    bases = {base_control(c) for c in nist}
    shared = sorted(bases & item_ctrls)
    score = 0.0
    if shared:
        score += min(len(shared), 3) * 0.9
        reasons.append("implements " + ", ".join(shared[:4]))
    low = f" {item_text.lower()} "
    kw = [k for k in keywords if re.search(rf"(?<![a-z0-9]){re.escape(k.lower())}", low)]
    if kw:
        score += min(len(kw), 3) * 0.7
        reasons.append("relevant to " + ", ".join(f"“{k}”" for k in kw[:3]))
    sim = similarity(item_text, f"{title} {desc}")
    if sim > 0.04:
        score += sim * 6
    return round(score, 3), reasons


def _library_risk(ref: str) -> dict | None:
    from ..library import risk_library
    return next((r for r in risk_library() if r["id"] == ref), None)


def deterministic_item_suggestions(review: dict, item: dict, mitigations: list[dict], cat: Catalog) -> dict:
    text = _item_text(item)
    ctrls = item_controls(item, cat)
    linked = set(item.get("mitigation_ids", []))
    lib = mitigation_library()
    lib_risk = _library_risk(item.get("library_ref") or "")
    preferred = set(lib_risk.get("mitigations", [])) if lib_risk else set()
    for m_ref in (item.get("code_mitigations") or []):
        preferred.add(m_ref)

    existing = []
    used_lib = {m["library_ref"] for m in mitigations if m.get("library_ref")}
    for m in mitigations:
        if m["id"] in linked:
            continue
        lm = lib.get(m.get("library_ref") or "", {})
        score, why = _score(text, ctrls, m["title"], m["description"], m["nist"] or lm.get("nist", []),
                            lm.get("keywords", []) or list(tokens(m["title"]))[:6])
        if m.get("library_ref") in preferred:
            score += 2.0
            why.insert(0, "recommended for this risk")
        if score >= 0.9:
            existing.append({"mitigation_id": m["id"], "title": m["title"], "state": m["state"],
                             "status": m["status"], "shared": len(m["item_ids"]), "score": score + 0.5,
                             "reason": "; ".join(why) or "similar wording", "source": "register"})
    existing.sort(key=lambda s: (-s["score"], s["mitigation_id"]))

    library = []
    for lid, m in lib.items():
        if lid in used_lib:
            continue  # already in the register - surfaced above as a reusable control
        score, why = _score(text, ctrls, m["title"], m["description"], m["nist"], m["keywords"])
        if lid in preferred:
            score += 2.0
            why.insert(0, "recommended for this risk")
        if score >= 0.9:
            library.append({"library_id": lid, "title": m["title"], "description": m["description"],
                            "nist": m["nist"], "score": score, "reason": "; ".join(why), "source": "library"})
    library.sort(key=lambda s: (-s["score"], s["library_id"]))

    cls = effective_class(review)
    rec = ""
    if lib_risk:
        rec = lib_risk.get("recommendation", "")
    elif library:
        top = library[0]
        rec = f"{top['title']}: {top['description']}"
    elif existing:
        rec = f"Apply the existing control “{existing[0]['title']}” to this item and provide evidence."
    likelihood = (lib_risk or {}).get("likelihood", "possible")
    impact = CLASS_IMPACT[cls] if not lib_risk or lib_risk.get("impact") == "by_class" else lib_risk["impact"]
    data = data_phrase(review.get("data_types"))
    impact_desc = (f"Could expose or alter {data} ({CLASSIFICATIONS[cls]['label']}), with customer, regulatory "
                   f"and reputational consequences.")
    return {"existing": existing[:4], "library": library[:5], "new": [], "recommendation": rec,
            "likelihood": likelihood, "impact": impact, "impact_description": impact_desc,
            "provider": "heuristic", "source": "heuristic"}


ITEM_SUGGEST_SYSTEM = """You are a principal security architect helping a reviewer close a line item in a security
design review. Choose mitigating controls that would close (or materially reduce) the item.
Prefer, in order: (1) controls already in the review's register - one control should be reused to close many
items; (2) controls from the provided library; (3) only if nothing fits, propose a NEW control.
Also suggest a recommendation and, for risks, likelihood and impact on these scales:
likelihood: rare|unlikely|possible|likely|almost_certain   impact: insignificant|minor|moderate|major|severe
Return ONLY JSON:
{"existing_ids": [register ids], "library_ids": ["M-..."],
 "new_controls": [{"title": "...", "description": "...", "nist": ["AC-6"]}],
 "recommendation": "...", "likelihood": "...", "impact": "...", "impact_description": "...",
 "rationale": "one or two sentences"}"""


async def item_suggestions(review: dict, item: dict, mitigations: list[dict], cat: Catalog,
                           llm: LLM | None) -> dict:
    base = deterministic_item_suggestions(review, item, mitigations, cat)
    if llm is None:
        return base
    lib = mitigation_library()
    reg = {m["id"]: m for m in mitigations if m["id"] not in item.get("mitigation_ids", [])}
    candidates = [s["library_id"] for s in base["library"]]
    # Give the model a broader, deterministic shortlist of library controls.
    extra = sorted(lib, key=lambda k: -_score(_item_text(item), item_controls(item, cat), lib[k]["title"],
                                               lib[k]["description"], lib[k]["nist"], lib[k]["keywords"])[0])
    shortlist = list(dict.fromkeys(candidates + extra))[:18]
    user = json.dumps({
        "context": _item_context(review, item, mitigations),
        "register": [{"id": m["id"], "title": m["title"], "state": m["state"], "closes_items": len(m["item_ids"])}
                     for m in reg.values()],
        "library": [{"id": k, "title": lib[k]["title"], "nist": lib[k]["nist"]} for k in shortlist],
        "nist_800_53_for_item": sorted(item_controls(item, cat))[:25],
    }, indent=1)
    try:
        res = await llm.complete_json(ITEM_SUGGEST_SYSTEM, user)
    except ProviderError as e:
        return {**base, "warning": f"AI unavailable, showing offline suggestions: {e}"}
    existing = []
    for mid in res.get("existing_ids") or []:
        try:
            m = reg.get(int(mid))
        except (TypeError, ValueError):
            m = None
        if m:
            existing.append({"mitigation_id": m["id"], "title": m["title"], "state": m["state"],
                             "status": m["status"], "shared": len(m["item_ids"]), "score": 99,
                             "reason": "AI: reuse existing control", "source": "ai"})
    library = []
    used_lib = {m.get("library_ref") for m in mitigations}
    for lid in res.get("library_ids") or []:
        if lid in lib and lid not in used_lib:
            m = lib[lid]
            library.append({"library_id": lid, "title": m["title"], "description": m["description"],
                            "nist": m["nist"], "score": 99, "reason": "AI recommended", "source": "ai"})
    new = []
    for n in (res.get("new_controls") or [])[:3]:
        if isinstance(n, dict) and n.get("title"):
            new.append({"title": str(n["title"])[:200], "description": str(n.get("description", ""))[:800],
                        "nist": [c for c in (n.get("nist") or []) if isinstance(c, str) and c in cat.controls][:6],
                        "source": "ai"})

    def merge(a: list[dict], b: list[dict], key: str) -> list[dict]:
        seen, out = set(), []
        for s in a + b:
            if s[key] not in seen:
                seen.add(s[key])
                out.append(s)
        return out
    lk = str(res.get("likelihood", "")).lower()
    ik = str(res.get("impact", "")).lower()
    return {
        "existing": merge(existing, base["existing"], "mitigation_id")[:5],
        "library": merge(library, base["library"], "library_id")[:6],
        "new": new,
        "recommendation": str(res.get("recommendation") or base["recommendation"])[:1500],
        "likelihood": lk if lk in LIKELIHOOD else base["likelihood"],
        "impact": ik if ik in IMPACT else base["impact"],
        "impact_description": str(res.get("impact_description") or base["impact_description"])[:1000],
        "rationale": str(res.get("rationale", ""))[:600],
        "provider": llm.label, "source": "ai", "cached": llm.last_cached,
    }


# --------------------------------------------------------------------------- risk discovery
RISK_SYSTEM = """You are a principal security architect performing threat modelling for a security design review.
Given the design (profile, description, design understanding from documents, code review summary), the risks
ALREADY recorded and the candidate risks already proposed, identify ADDITIONAL design-specific risks that are
NOT already covered. Be concrete to this design (name the components, data and flows). No duplicates or
rephrasings of existing risks. Maximum 8.
likelihood: rare|unlikely|possible|likely|almost_certain   impact: insignificant|minor|moderate|major|severe
Risk statements must follow: "There is a risk that <event> caused by <cause>, resulting in <consequence>."
Return ONLY JSON:
{"risks": [{"title": "...", "risk": "...", "likelihood": "...", "impact": "...", "recommendation": "...",
            "csf": ["PR.DS-01"], "mitigations": ["M-... library ids"], "rationale": "why this design has it"}]}"""


def _existing_risks(items: list[dict]) -> list[dict]:
    return [i for i in items if i.get("is_risk")]


def _is_duplicate(title: str, risk: str, existing: list[dict], threshold: float = 0.42) -> bool:
    for e in existing:
        et = f"{e.get('title') or e.get('display_title', '')} {e.get('risk', '')}"
        if similarity(f"{title} {risk}", et) >= threshold or similarity(title, e.get("title") or "") >= 0.6:
            return True
    return False


def _resolve_mitigations(lib_ids: list[str], mitigations: list[dict]) -> list[dict]:
    lib = mitigation_library()
    by_ref = {m.get("library_ref"): m for m in mitigations if m.get("library_ref")}
    out = []
    for lid in lib_ids:
        if lid in by_ref:
            m = by_ref[lid]
            out.append({"mitigation_id": m["id"], "title": m["title"], "reuse": True})
        elif lid in lib:
            out.append({"library_id": lid, "title": lib[lid]["title"], "reuse": False})
    return out


async def suggest_risks(review: dict, items: list[dict], mitigations: list[dict], cat: Catalog,
                        llm: LLM | None) -> dict:
    existing = _existing_risks(items)
    have_refs = {i.get("library_ref") for i in items if i.get("library_ref")}
    out: list[dict] = []
    for s in library_risks(review):
        if s["library_ref"] in have_refs or _is_duplicate(s["title"], s["risk"], existing):
            continue
        out.append(s)
    # Unpromoted code-review findings are risks too.
    for f in (review.get("code_review") or {}).get("findings", []):
        if f.get("item_id") or f.get("severity") not in ("critical", "high", "medium"):
            continue
        if f"code:{f['id']}" in have_refs:
            continue
        lk, ik = SEVERITY_TO_LI[f["severity"]]
        out.append({"key": f"code:{f['id']}", "library_ref": f"code:{f['id']}", "title": f["title"],
                    "risk": f"There is a risk that {f['description'][0].lower() + f['description'][1:]}"
                    if f.get("description") else f["title"],
                    "likelihood": lk, "impact": ik, "rating": risk_rating(lk, ik),
                    "recommendation": f.get("recommendation", ""), "csf": f.get("csf", []),
                    "mitigations": f.get("mitigations", []),
                    "rationale": f"Code review ({f.get('source')}) - " + ", ".join(
                        f"{e['file']}:{e.get('line', '')}" for e in (f.get("evidence") or [])[:2]),
                    "source": "code"})
    warning = None
    provider = "heuristic"
    if llm is not None:
        design = review.get("design") or {}
        code = review.get("code_review") or {}
        user = json.dumps({
            "title": review.get("title"), "description": (review.get("description") or "")[:4000],
            "profile": profile_summary(review),
            "design": {k: design.get(k) for k in ("summary", "components", "data_flows", "trust_boundaries",
                                                   "integrations", "notable_concerns") if design.get(k)},
            "code_review": {"summary": code.get("summary"),
                            "findings": [f["title"] for f in code.get("findings", [])[:25]]},
            "already_recorded_risks": [f"{i.get('display_title')}: {i.get('risk', '')}"[:300] for i in existing],
            "candidate_risks": [s["title"] for s in out],
            "mitigation_library": [{"id": k, "title": v["title"]} for k, v in mitigation_library().items()],
        }, indent=1)
        try:
            res = await llm.complete_json(RISK_SYSTEM, user)
            provider = llm.label
            pool = existing + [{"title": s["title"], "risk": s["risk"]} for s in out]
            for i, r in enumerate(res.get("risks") or []):
                if not isinstance(r, dict) or not r.get("title"):
                    continue
                title, risk = str(r["title"])[:200], str(r.get("risk", ""))[:1200]
                if _is_duplicate(title, risk, pool):
                    continue
                lk = str(r.get("likelihood", "possible")).lower()
                ik = str(r.get("impact", "moderate")).lower()
                lk = lk if lk in LIKELIHOOD else "possible"
                ik = ik if ik in IMPACT else "moderate"
                s = {"key": f"ai:{i}:{abs(hash(title)) % 10**8}", "library_ref": "", "title": title, "risk": risk,
                     "likelihood": lk, "impact": ik, "rating": risk_rating(lk, ik),
                     "recommendation": str(r.get("recommendation", ""))[:1200],
                     "csf": [c for c in (r.get("csf") or []) if c in cat.subcategories][:5],
                     "mitigations": [m for m in (r.get("mitigations") or []) if m in mitigation_library()][:4],
                     "rationale": str(r.get("rationale", ""))[:500], "source": "ai"}
                out.append(s)
                pool.append({"title": title, "risk": risk})
        except ProviderError as e:
            warning = f"AI unavailable, showing library and code-review risks only: {e}"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
    out.sort(key=lambda s: (order.get(s["rating"], 4), {"code": 0, "library": 1, "ai": 2}[s["source"]]))
    for s in out:
        s["mitigation_refs"] = _resolve_mitigations(s["mitigations"], mitigations)
    return {"suggestions": out, "provider": provider, "warning": warning,
            "existing_risks": len(existing)}
