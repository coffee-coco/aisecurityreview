"""Review profile vocabulary + deterministic helpers shared by scoping, AI assist and reports.

The profile is what drives a review: how exposed the system is, how sensitive the data it
handles (and touches) is, what kinds of data and what kind of system it is.
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------- classification
# Stored values stay human words; C-levels are the display / org vocabulary.
CLASSIFICATIONS = {
    "public": {"level": 1, "code": "C1", "label": "C1 Public", "desc": "Approved for public release"},
    "internal": {"level": 2, "code": "C2", "label": "C2 Internal", "desc": "Internal business information"},
    "confidential": {"level": 3, "code": "C3", "label": "C3 Confidential",
                     "desc": "Customer, employee or commercially sensitive data"},
    "restricted": {"level": 4, "code": "C4", "label": "C4 Restricted",
                   "desc": "Highly sensitive - payment card, health, credentials, regulated"},
}
CODE_TO_CLASS = {v["code"].lower(): k for k, v in CLASSIFICATIONS.items()}


def norm_class(value: str) -> str:
    v = (value or "").strip().lower()
    return CODE_TO_CLASS.get(v, v if v in CLASSIFICATIONS else "internal")


def class_level(value: str) -> int:
    return CLASSIFICATIONS[norm_class(value)]["level"]


EXPOSURES = {
    "internal": {"label": "Internal only", "desc": "Staff / corporate network only"},
    "partner": {"label": "Partner / B2B", "desc": "Reachable by suppliers, partners or B2B integrations"},
    "public": {"label": "Public / internet", "desc": "Reachable by customers or anyone on the internet"},
}

DATA_TYPES = {
    "pii": "Personal information (PII)",
    "sensitive_pii": "Sensitive personal (ID numbers, biometrics)",
    "health": "Health / medical",
    "financial": "Financial / banking",
    "payment_card": "Payment card (PCI)",
    "credentials": "Credentials, keys & secrets",
    "customer": "Customer records",
    "employee": "Employee / HR",
    "ip": "Intellectual property / source code",
    "legal": "Legal / regulatory",
    "operational": "Operational / telemetry / logs",
    "public": "Public content",
}
PERSONAL_TYPES = {"pii", "sensitive_pii", "health", "financial", "payment_card", "customer", "employee"}


def data_phrase(types: list[str] | None, empty: str = "business data") -> str:
    """'personal information (PII), customer records and financial / banking' - keeps acronyms."""
    labels = [DATA_TYPES.get(t, t) for t in types or []]
    labels = [l[0].lower() + l[1:] if l[1:2].islower() else l for l in labels]
    if not labels:
        return empty
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]

SYSTEM_TYPES = {
    "web_app": "Website / web application",
    "api": "API / backend service",
    "mobile_app": "Mobile app",
    "ai_agent": "AI agent / LLM application",
    "ai_ml": "ML model / AI feature",
    "data_platform": "Data platform / analytics",
    "integration": "Integration / ETL / file transfer",
    "saas": "SaaS adoption",
    "infrastructure": "Infrastructure / platform change",
    "identity": "Identity & access change",
    "internal_tool": "Internal tool / automation",
    "iot_ot": "IoT / OT",
}

# Deterministic keyword detection used offline and as a safety net under AI output.
SYSTEM_TYPE_KEYWORDS = {
    "web_app": ["website", "web app", "web application", "portal", "frontend", "front-end", "browser", "react",
                "angular", "next.js", "cloudfront", "cdn", "landing page", "spa"],
    "api": ["api", "rest", "graphql", "grpc", "endpoint", "microservice", "backend", "webhook", "fastapi",
            "express", "spring boot"],
    "mobile_app": ["mobile app", "ios", "android", "react native", "flutter", "push notification", "app store"],
    "ai_agent": ["agent", "agentic", "llm", "gpt", "claude", "gemini", "prompt", "tool calling", "function calling",
                 "rag", "retrieval augmented", "copilot", "chatbot", "langchain", "llamaindex", "mcp", "autogen",
                 "crewai", "vector store", "embedding"],
    "ai_ml": ["machine learning", "ml model", "sagemaker", "vertex", "model training", "inference", "classifier",
              "computer vision", "bedrock", "azure openai"],
    "data_platform": ["data lake", "warehouse", "analytics", "etl", "elt", "snowflake", "databricks", "bigquery",
                      "redshift", "athena", "glue", "power bi", "tableau", "reporting"],
    "integration": ["integration", "sftp", "file transfer", "mulesoft", "boomi", "kafka", "event bus",
                    "message queue", "service bus", "sync", "middleware"],
    "saas": ["saas", "software as a service", "subscription", "workday", "salesforce", "servicenow", "vendor platform"],
    "infrastructure": ["upgrade", "cluster", "kubernetes", "eks", "aks", "gke", "network", "firewall", "vpc",
                       "landing zone", "terraform", "migration", "data centre", "datacenter"],
    "identity": ["sso", "saml", "oidc", "okta", "entra", "active directory", "iam", "mfa", "identity provider",
                 "privileged access", "pam"],
    "internal_tool": ["internal tool", "automation", "script", "bot", "rpa", "back office", "staff only"],
    "iot_ot": ["iot", "ot ", "scada", "plc", "sensor", "device firmware", "industrial"],
}

DATA_TYPE_KEYWORDS = {
    "pii": ["personal", "name", "address", "email", "phone", "date of birth", "dob", "pii", "customer details",
            "profile"],
    "sensitive_pii": ["passport", "driver licence", "drivers license", "tfn", "tax file", "ssn", "social security",
                      "biometric", "medicare number", "national id"],
    "health": ["health", "medical", "patient", "clinical", "diagnosis", "hipaa"],
    "financial": ["bank account", "bsb", "iban", "financial", "salary", "payroll", "invoice", "transaction",
                  "statement", "loan"],
    "payment_card": ["card number", "credit card", "debit card", "pan", "pci", "cardholder", "payment card",
                     "card payment"],
    "credentials": ["password", "credential", "secret", "api key", "token", "private key", "certificate"],
    "customer": ["customer", "policyholder", "member", "client record", "crm"],
    "employee": ["employee", "staff", "hr ", "human resources", "payroll", "workforce"],
    "ip": ["source code", "intellectual property", "proprietary", "trade secret", "algorithm", "model weights"],
    "legal": ["legal", "regulatory", "compliance", "contract", "litigation"],
    "operational": ["logs", "telemetry", "metrics", "monitoring", "audit trail"],
}

EXPOSURE_KEYWORDS = {
    "public": ["public", "internet", "customer-facing", "customers", "anonymous", "website", "mobile app",
               "public api", "cloudfront", "front door", "cdn"],
    "partner": ["partner", "b2b", "supplier", "vendor access", "third-party access", "extranet", "agency"],
}


def _has(text: str, word: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(word.strip())}(?![a-z0-9])", text) is not None


def detect_keywords(text: str, vocab: dict[str, list[str]], min_hits: int = 1) -> list[str]:
    text = f" {text.lower()} "
    out = []
    for key, words in vocab.items():
        hits = sum(1 for w in words if _has(text, w))
        if hits >= min_hits:
            out.append(key)
    return out


def detect_exposure(text: str) -> str:
    found = detect_keywords(text, EXPOSURE_KEYWORDS)
    return "public" if "public" in found else "partner" if "partner" in found else "internal"


def suggest_classification(data_types: list[str]) -> str:
    dt = set(data_types)
    if dt & {"payment_card", "health", "sensitive_pii", "credentials"}:
        return "restricted"
    if dt & {"pii", "financial", "customer", "employee", "ip", "legal"}:
        return "confidential"
    if dt - {"public"}:
        return "internal"
    return "public" if dt == {"public"} else "internal"


def effective_class(review: dict) -> str:
    """Highest classification the system handles or connects to."""
    cands = [norm_class(review.get("data_classification", "internal"))]
    cands += [norm_class(c) for c in review.get("interacts_with") or []]
    return max(cands, key=class_level)


# --------------------------------------------------------------------------- risk scoring
LIKELIHOOD = {"rare": 1, "unlikely": 2, "possible": 3, "likely": 4, "almost_certain": 5}
IMPACT = {"insignificant": 1, "minor": 2, "moderate": 3, "major": 4, "severe": 5}
LIKELIHOOD_LABELS = {"rare": "Rare", "unlikely": "Unlikely", "possible": "Possible", "likely": "Likely",
                     "almost_certain": "Almost certain"}
IMPACT_LABELS = {"insignificant": "Insignificant", "minor": "Minor", "moderate": "Moderate", "major": "Major",
                 "severe": "Severe"}
TREATMENTS = {"mitigate": "Mitigate", "accept": "Accept", "transfer": "Transfer", "avoid": "Avoid"}
REC_STATUSES = {"proposed": "Proposed", "agreed": "Agreed", "implemented": "Implemented", "declined": "Declined"}
MIT_STATUSES = {"proposed": "Proposed", "planned": "Planned", "in_progress": "In progress",
                "implemented": "Implemented", "verified": "Verified"}
SEVERITY_TO_LI = {  # code findings -> likelihood / impact
    "critical": ("likely", "severe"), "high": ("likely", "major"), "medium": ("possible", "moderate"),
    "low": ("unlikely", "minor"), "info": ("rare", "minor"),
}
CLASS_IMPACT = {"public": "minor", "internal": "moderate", "confidential": "major", "restricted": "severe"}


def risk_rating(likelihood: str, impact: str) -> str:
    l, i = LIKELIHOOD.get(likelihood or ""), IMPACT.get(impact or "")
    if not (l and i):
        return ""
    score = l * i
    return "critical" if score >= 20 else "high" if score >= 12 else "medium" if score >= 5 else "low"


def item_answered(item: dict, has_mitigation: bool) -> bool:
    kind = item.get("kind", "question")
    if kind == "risk":
        return bool(item.get("treatment")) or has_mitigation
    if kind == "recommendation":
        return item.get("rec_status") in ("agreed", "implemented", "declined")
    return item.get("status", "open") != "open" or bool((item.get("answer") or "").strip())


ANSWERED_SQL = """CASE x.kind
  WHEN 'risk' THEN (x.treatment != '' OR EXISTS (SELECT 1 FROM item_mitigations im WHERE im.item_id = x.id))
  WHEN 'recommendation' THEN (x.rec_status IN ('agreed','implemented','declined'))
  ELSE (x.status != 'open' OR trim(x.answer) != '') END"""


# --------------------------------------------------------------------------- profile tokens
def profile_tokens(review: dict) -> set[str]:
    """Flatten the review profile into tokens used by the risk library conditions."""
    cls = effective_class(review)
    t = {f"exposure:{review.get('exposure') or 'internal'}", f"class:{cls}",
         "new" if review.get("change_type") == "new" else "change"}
    lvl = class_level(cls)
    t |= {f"class>={k}" for k, v in CLASSIFICATIONS.items() if lvl >= v["level"]}
    t |= {f"data:{d}" for d in review.get("data_types") or []}
    t |= {f"system:{s}" for s in review.get("system_types") or []}
    t |= {f"tech:{x}" for x in review.get("technologies") or []}
    t |= {f"service:{x}" for x in review.get("services") or []}
    for flag in ("third_party", "uses_ai", "personal_data", "internet_facing"):
        if review.get(flag):
            t.add(f"flag:{flag}")
    if review.get("exposure") in ("public", "partner"):
        t.add("flag:internet_facing")
    if set(review.get("data_types") or []) & PERSONAL_TYPES:
        t.add("flag:personal_data")
    for f in (review.get("code_review") or {}).get("findings", []):
        if f.get("category"):
            t.add(f"code:{f['category']}")
    return t


def profile_text(review: dict) -> str:
    design = review.get("design") or {}
    parts = [review.get(k) or "" for k in ("title", "description", "tech_stack", "business_unit")]
    parts += [design.get("summary") or "", " ".join(design.get("notable_concerns") or [])]
    parts += [(review.get("code_review") or {}).get("summary") or ""]
    return " ".join(parts).lower()


def profile_summary(review: dict) -> dict:
    """Compact, human-readable profile passed to AI prompts."""
    return {
        "exposure": EXPOSURES.get(review.get("exposure") or "internal", {}).get("label"),
        "data_classification": CLASSIFICATIONS[norm_class(review.get("data_classification"))]["label"],
        "connects_to": [CLASSIFICATIONS[norm_class(c)]["label"] for c in review.get("interacts_with") or []],
        "effective_classification": CLASSIFICATIONS[effective_class(review)]["label"],
        "data_types": [DATA_TYPES.get(d, d) for d in review.get("data_types") or []],
        "system_types": [SYSTEM_TYPES.get(s, s) for s in review.get("system_types") or []],
        "third_party": bool(review.get("third_party")),
        "uses_ai": bool(review.get("uses_ai")),
        "technologies": review.get("technologies") or [],
        "services": review.get("services") or [],
    }


def vocab() -> dict:
    return {
        "classifications": [{"id": k, **v} for k, v in CLASSIFICATIONS.items()],
        "exposures": [{"id": k, **v} for k, v in EXPOSURES.items()],
        "data_types": [{"id": k, "label": v} for k, v in DATA_TYPES.items()],
        "system_types": [{"id": k, "label": v} for k, v in SYSTEM_TYPES.items()],
        "likelihood": [{"id": k, "label": v, "n": LIKELIHOOD[k]} for k, v in LIKELIHOOD_LABELS.items()],
        "impact": [{"id": k, "label": v, "n": IMPACT[k]} for k, v in IMPACT_LABELS.items()],
        "treatments": [{"id": k, "label": v} for k, v in TREATMENTS.items()],
        "rec_statuses": [{"id": k, "label": v} for k, v in REC_STATUSES.items()],
        "mit_statuses": [{"id": k, "label": v} for k, v in MIT_STATUSES.items()],
    }


# --------------------------------------------------------------------------- text similarity
STOP = set("a an the and or of to for in on with by is are be this that it as at from into via use using must "
           "should ensure all any not no can will".split())


def tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(w) > 2 and w not in STOP}


def similarity(a: str, b: str) -> float:
    ta, tb = tokens(a), tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)
