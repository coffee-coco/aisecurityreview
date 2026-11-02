"""Design understanding from uploaded architecture documents, diagrams and the intake form.

The AI reads every document (text extracted locally, plus images/PDFs natively when the provider
supports vision) and works out *what* is being reviewed - e.g. "an AI agent with tool access",
"a public website" - its components, data flows, trust boundaries and data handled. Offline, the
same fields are derived deterministically from keyword detectors.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..catalog import Catalog
from ..profile import (
    CLASSIFICATIONS, DATA_TYPE_KEYWORDS, DATA_TYPES, EXPOSURES, SYSTEM_TYPE_KEYWORDS, SYSTEM_TYPES, class_level,
    data_phrase, detect_exposure, detect_keywords, norm_class, suggest_classification,
)
from .providers import LLM, Attachment, ProviderError
from .scoping import detect_services, detect_technologies

DESIGN_SYSTEM = """You are a principal security architect. Read the project's architecture documents, diagrams
and intake details and build an accurate understanding of WHAT is being reviewed for a security design review.
Identify the kind of system (e.g. AI agent / LLM app, public website, API, data platform, SaaS adoption), its
components, data flows, trust boundaries, the data handled and its sensitivity, and how exposed it is.
Only state what the material supports; put unknowns in open_questions.
Allowed values:
system_types: %s
data_types: %s
classification: public (C1) | internal (C2) | confidential (C3) | restricted (C4)
exposure: internal | partner | public
Return ONLY JSON:
{"summary": "3-5 sentences: what it is, who uses it, what data, where it runs",
 "system_types": [], "components": [{"name": "...", "type": "frontend|api|service|database|queue|storage|llm|agent|tool|identity|external|network|other", "description": "..."}],
 "data_flows": [{"from": "...", "to": "...", "data": "...", "protocol": "...", "crosses_boundary": true}],
 "trust_boundaries": ["..."], "data_types": [], "suggested_classification": "...",
 "classification_rationale": "...", "exposure": "...", "exposure_rationale": "...",
 "technologies": ["cloud / platform names"], "services": ["lower-case services e.g. s3, api gateway"],
 "integrations": ["third parties / external systems"], "uses_ai": true, "third_party": true,
 "notable_concerns": ["design-level security concerns"], "open_questions": ["what the reviewer should ask"]}"""


def _doc_corpus(review: dict, docs: list[dict], limit: int) -> str:
    intake = {k: review.get(k) for k in ("title", "description", "tech_stack", "business_unit", "change_type")}
    parts = ["## Intake\n" + json.dumps(intake, indent=1)]
    used = len(parts[0])
    for d in docs:
        text = d.get("text") or ""
        if not text:
            continue
        chunk = f"\n\n## Document: {d['filename']}\n{text}"
        if used + len(chunk) > limit:
            chunk = chunk[: max(0, limit - used)] + "\n[... truncated ...]"
        parts.append(chunk)
        used += len(chunk)
        if used >= limit:
            break
    return "".join(parts)


def heuristic_design(review: dict, docs: list[dict], cat: Catalog) -> dict:
    text = " ".join([review.get("title") or "", review.get("description") or "", review.get("tech_stack") or ""] +
                    [d.get("text") or "" for d in docs]).lower()
    systems = detect_keywords(text, SYSTEM_TYPE_KEYWORDS, min_hits=2)
    if not systems:
        systems = detect_keywords(text, SYSTEM_TYPE_KEYWORDS, min_hits=1)[:3]
    data = detect_keywords(text, DATA_TYPE_KEYWORDS, min_hits=1)
    cls = suggest_classification(data)
    exposure = detect_exposure(text)
    techs = [t for t in detect_technologies(text, cat) if t != "Secrets"]
    services = detect_services(text)
    flows = []
    for m in re.finditer(r"\[flow\]\s*([^\n]{3,120})", text):
        flows.append({"from": "", "to": "", "data": m.group(1).strip(), "protocol": "", "crosses_boundary": False})
    concerns, questions = [], []
    if "ai_agent" in systems:
        concerns.append("Agent/LLM component: prompt injection and tool permissions must be assessed.")
        questions += ["Which tools/APIs can the agent call, with what credentials and scopes?",
                      "Is there human approval before the agent performs side-effecting actions?",
                      "What data is sent to the model provider and is it retained or used for training?"]
    if exposure == "public":
        concerns.append("Internet-facing: requires WAF, rate limiting, strong authentication and monitoring.")
        questions.append("Which endpoints are reachable without authentication?")
    if class_level(cls) >= 3:
        concerns.append(f"Handles {CLASSIFICATIONS[cls]['label']} data - encryption, access control and logging "
                        f"are mandatory.")
        questions.append("Where is the sensitive data stored, and who (people and services) can access it?")
    if "saas" in systems or "integration" in systems:
        questions.append("What vendor assurance (SOC 2 / ISO 27001) and data residency commitments exist?")
    names = ", ".join(SYSTEM_TYPES[s] for s in systems) or "a system"
    dnames = data_phrase(data, "unspecified data")
    summary = (f"Based on the {len(docs)} document(s) and intake, this appears to be {names}, "
               f"{EXPOSURES[exposure]['label'].lower()}, handling {dnames} "
               f"(suggested {CLASSIFICATIONS[cls]['label']}).")
    if techs:
        summary += " Platforms: " + ", ".join(techs) + "."
    return {
        "summary": summary, "system_types": systems, "components": [], "data_flows": flows[:30],
        "trust_boundaries": [], "data_types": data, "suggested_classification": cls,
        "classification_rationale": "Derived from detected data types" if data else "No sensitive data detected",
        "exposure": exposure, "exposure_rationale": "Keyword detection on documents and intake",
        "technologies": techs, "services": services, "integrations": [],
        "uses_ai": bool({"ai_agent", "ai_ml"} & set(systems)), "third_party": "saas" in systems,
        "notable_concerns": concerns, "open_questions": questions,
    }


def _clean(res: dict, cat: Catalog, fallback: dict) -> dict:
    allowed_tech = {p.lower(): p for p in cat.providers}

    def strs(v, n=20, ln=300):
        return [str(x)[:ln] for x in (v or []) if isinstance(x, (str, int, float))][:n]

    comps = [{"name": str(c.get("name", ""))[:120], "type": str(c.get("type", "other"))[:30],
              "description": str(c.get("description", ""))[:400]}
             for c in (res.get("components") or []) if isinstance(c, dict) and c.get("name")][:40]
    flows = [{"from": str(f.get("from", ""))[:120], "to": str(f.get("to", ""))[:120],
              "data": str(f.get("data", ""))[:200], "protocol": str(f.get("protocol", ""))[:60],
              "crosses_boundary": bool(f.get("crosses_boundary"))}
             for f in (res.get("data_flows") or []) if isinstance(f, dict)][:40]
    cls = str(res.get("suggested_classification", "")).lower()
    exp = str(res.get("exposure", "")).lower()
    return {
        "summary": str(res.get("summary") or fallback["summary"])[:3000],
        "system_types": [s for s in (res.get("system_types") or []) if s in SYSTEM_TYPES] or fallback["system_types"],
        "components": comps, "data_flows": flows or fallback["data_flows"],
        "trust_boundaries": strs(res.get("trust_boundaries")),
        "data_types": [d for d in (res.get("data_types") or []) if d in DATA_TYPES] or fallback["data_types"],
        "suggested_classification": norm_class(cls) if cls else fallback["suggested_classification"],
        "classification_rationale": str(res.get("classification_rationale", ""))[:500],
        "exposure": exp if exp in EXPOSURES else fallback["exposure"],
        "exposure_rationale": str(res.get("exposure_rationale", ""))[:500],
        "technologies": sorted({allowed_tech[t.lower()] for t in res.get("technologies") or []
                                if isinstance(t, str) and t.lower() in allowed_tech}) or fallback["technologies"],
        "services": [str(s).lower()[:40] for s in (res.get("services") or []) if isinstance(s, str)][:30]
        or fallback["services"],
        "integrations": strs(res.get("integrations")),
        "uses_ai": bool(res.get("uses_ai")) if "uses_ai" in res else fallback["uses_ai"],
        "third_party": bool(res.get("third_party")) if "third_party" in res else fallback["third_party"],
        "notable_concerns": strs(res.get("notable_concerns"), 15, 400),
        "open_questions": strs(res.get("open_questions"), 15, 400),
    }


async def analyze_design(review: dict, docs: list[dict], cat: Catalog, llm: LLM | None) -> dict:
    """docs: [{id, filename, kind, mime, text, path}]"""
    base = heuristic_design(review, docs, cat)
    meta = {"documents": [d["filename"] for d in docs], "provider": "heuristic", "source": "heuristic"}
    if llm is None:
        skipped = [d["filename"] for d in docs if d["kind"] == "image"]
        warn = (f"{len(skipped)} image(s) need an AI provider with vision (e.g. Gemini) to be understood."
                if skipped else None)
        return {**base, **meta, "warning": warn}
    attachments: list[Attachment] = []
    skipped = []
    for d in docs:
        want = d["kind"] == "image" or (d.get("mime") == "application/pdf" and (d.get("meta") or {}).get("needs_vision"))
        if not want:
            continue
        kind = "image" if d["kind"] == "image" else "pdf"
        if llm.supports(kind) and Path(d["path"]).exists() and len(attachments) < 16:
            attachments.append(Attachment(d["mime"], Path(d["path"]).read_bytes(), d["filename"]))
        else:
            skipped.append(d["filename"])
    system = DESIGN_SYSTEM % (", ".join(SYSTEM_TYPES), ", ".join(DATA_TYPES))
    user = _doc_corpus(review, docs, int(llm.context_chars * 0.7))
    if attachments:
        user += "\n\n## Attached diagrams/images: " + ", ".join(a.name for a in attachments)
    try:
        res = await llm.complete_json(system, user, attachments)
    except ProviderError as e:
        return {**base, **meta, "warning": f"AI unavailable, used offline detection: {e}"}
    out = _clean(res, cat, base)
    warn = (f"Not sent to the model (unsupported type for {llm.provider}): {', '.join(skipped)}" if skipped else None)
    return {**out, **meta, "provider": llm.label, "source": "ai", "cached": llm.last_cached, "warning": warn}
