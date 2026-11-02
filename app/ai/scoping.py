"""Review scoping: decide which NIST CSF 2.0 requirements (and therefore which
800-53 controls and Checkov checks) apply to a new initiative or change, plus the
requirements of any additional framework (NIST AI RMF, OWASP...) the profile triggers."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from ..catalog import Catalog
from ..frameworks import CSF_ID, applicable_frameworks
from ..profile import CLASSIFICATIONS, effective_class, profile_summary, profile_tokens
from .providers import LLM, ProviderError

# --------------------------------------------------------------------------- vocab
TECH_KEYWORDS: dict[str, list[str]] = {
    "AWS": ["aws", "amazon web services", "s3", "ec2", "lambda", "rds", "dynamodb", "cloudfront", "eks", "ecs",
            "fargate", "api gateway", "sqs", "sns", "redshift", "bedrock", "sagemaker", "cognito", "aurora"],
    "Azure": ["azure", "entra", "aks", "cosmos", "app service", "function app", "key vault", "blob storage",
              "storage account", "azure sql", "defender for cloud", "azure openai"],
    "GCP": ["gcp", "google cloud", "gke", "bigquery", "cloud run", "cloud storage", "gcs", "pub/sub", "pubsub",
            "cloud sql", "vertex"],
    "Kubernetes": ["kubernetes", "k8s", "eks", "aks", "gke", "helm", "openshift", "pod", "cluster"],
    "Docker": ["docker", "container", "dockerfile", "image"],
    "GitHub": ["github"],
    "GitHub Actions": ["github actions", "github workflow"],
    "GitLab": ["gitlab"],
    "GitLab CI": ["gitlab ci", "gitlab pipeline"],
    "Bitbucket": ["bitbucket"],
    "Bitbucket Pipelines": ["bitbucket pipeline"],
    "Azure Pipelines": ["azure devops", "azure pipeline"],
    "CircleCI": ["circleci"],
    "Argo Workflows": ["argo"],
    "OpenAPI": ["openapi", "swagger", "rest api", " api"],
    "Oracle Cloud": ["oracle cloud", "oci"],
    "Alibaba Cloud": ["alibaba", "alicloud"],
    "DigitalOcean": ["digitalocean"],
    "Linode": ["linode"],
    "IBM Cloud": ["ibm cloud"],
    "OpenStack": ["openstack"],
    "Palo Alto": ["palo alto", "pan-os", "panos"],
    "Tencent Cloud": ["tencent"],
    "Yandex Cloud": ["yandex"],
    "Naver Cloud": ["naver"],
    "Ansible": ["ansible"],
    "Okta": ["okta"],
    "Terraform": ["terraform"],
}

SERVICE_VOCAB = [
    "s3", "ec2", "lambda", "rds", "aurora", "dynamodb", "cloudfront", "api gateway", "eks", "ecs", "ecr", "sqs",
    "sns", "kms", "iam", "vpc", "load balancer", "elb", "alb", "redshift", "opensearch", "elasticsearch", "cognito",
    "bedrock", "sagemaker", "secrets manager", "cloudtrail", "cloudwatch", "waf", "glue", "kinesis", "efs", "ebs",
    "elasticache", "neptune", "documentdb", "msk", "kafka", "step functions", "appsync", "transfer", "workspaces",
    "cosmos", "storage account", "key vault", "app service", "function app", "aks", "sql server", "postgres",
    "postgresql", "mysql", "mariadb", "redis", "service bus", "event hub", "front door", "application gateway",
    "container registry", "synapse", "data factory", "databricks", "cognitive", "openai", "search service",
    "bigquery", "cloud storage", "cloud run", "gke", "pubsub", "cloud sql", "cloud functions", "spanner", "dataproc",
    "vertex", "memorystore", "artifact registry", "firewall", "dns", "certificate", "vpn", "bastion",
]

FLAG_LABELS = {
    "internet_facing": "Internet-facing",
    "personal_data": "Personal / sensitive data",
    "third_party": "Third party / supplier involved",
    "uses_ai": "Uses AI / ML",
}


def _text(review: dict) -> str:
    design = review.get("design") or {}
    code = review.get("code_review") or {}
    parts = [str(review.get(k) or "") for k in ("title", "description", "tech_stack", "business_unit")]
    parts += [design.get("summary") or "", " ".join(design.get("technologies") or []),
              " ".join(design.get("services") or []), code.get("summary") or "",
              " ".join((code.get("inventory") or {}).get("frameworks") or [])]
    parts += [s.replace("_", " ") for s in review.get("system_types") or []]
    return " ".join(parts).lower()


def _flags(review: dict) -> set[str]:
    flags = {f"flag:{k}" for k in FLAG_LABELS if review.get(k)}
    flags.add("flag:new" if review.get("change_type") == "new" else "flag:change")
    if review.get("exposure") in ("public", "partner"):
        flags.add("flag:internet_facing")
    if set(review.get("system_types") or []) & {"ai_agent", "ai_ml"}:
        flags.add("flag:uses_ai")
    return flags


def _tokens(review: dict) -> set[str]:
    """Intake flags plus profile tokens (system:ai_agent, exposure:public, ...), lower-cased."""
    return _flags(review) | {t.lower() for t in profile_tokens(review)}


def _framework_of(s: dict) -> str:
    return s.get("framework_id", CSF_ID)


def detect_technologies(text: str, catalog: Catalog) -> list[str]:
    found = []
    padded = f" {text} "
    for tech, words in TECH_KEYWORDS.items():
        if tech not in catalog.providers:
            continue
        if any(re.search(rf"(?<![a-z0-9]){re.escape(w.strip())}(?![a-z0-9])", padded) for w in words):
            found.append(tech)
    if found or any(w in text for w in ("code", "app", "application", "repo", "software")):
        found.append("Secrets")  # hard-coded secret checks apply to any codebase
    return sorted(set(found))


def detect_services(text: str) -> list[str]:
    return [s for s in SERVICE_VOCAB if re.search(rf"(?<![a-z0-9]){re.escape(s)}(?![a-z0-9])", text)]


def heuristic_risk(review: dict, text: str) -> tuple[str, str]:
    score, why = 0, []
    weights = {"personal_data": 2, "third_party": 1, "uses_ai": 1}
    exposure = review.get("exposure") or ("public" if review.get("internet_facing") else "internal")
    if exposure == "public":
        score += 2
        why.append("Public / internet facing")
    elif exposure == "partner":
        score += 1
        why.append("Partner / B2B facing")
    for k, w in weights.items():
        if review.get(k):
            score += w
            why.append(FLAG_LABELS[k])
    cls = effective_class(review)
    cls_w = {"restricted": 3, "confidential": 2, "internal": 1}.get(cls, 0)
    if cls_w:
        score += cls_w
        label = CLASSIFICATIONS[cls]["label"]
        why.append(f"{label} data" if cls == (review.get("data_classification") or "internal")
                   else f"connects to {label} data")
    if "ai_agent" in (review.get("system_types") or []):
        score += 1
        why.append("autonomous AI agent")
    for word, label in (("payment", "payments"), ("card", "cardholder data"), ("health", "health data"),
                        ("production", "production system"), ("admin", "administrative access")):
        if word in text:
            score += 1
            why.append(label)
    rating = "critical" if score >= 7 else "high" if score >= 5 else "medium" if score >= 2 else "low"
    return rating, ", ".join(why) or "No elevated risk factors declared"


def heuristic_key_risks(review: dict, techs: list[str]) -> list[dict]:
    risks = []
    if review.get("internet_facing"):
        risks.append({"title": "External attack surface",
                      "description": "Internet exposure increases risk of exploitation, credential stuffing and DDoS.",
                      "csf": ["PR.IR-01", "DE.CM-01", "ID.RA-08"]})
    if review.get("personal_data"):
        risks.append({"title": "Personal data breach",
                      "description": "Unauthorised access to personal data creates regulatory notification and privacy obligations.",
                      "csf": ["GV.OC-03", "PR.DS-01", "RS.CO-02"]})
    if review.get("third_party"):
        risks.append({"title": "Supplier / third-party risk",
                      "description": "Security depends on the supplier's controls, contract terms and incident handling.",
                      "csf": ["GV.SC-05", "GV.SC-07", "DE.CM-06"]})
    if review.get("uses_ai"):
        risks.append({"title": "AI-specific risk",
                      "description": "Prompt injection, data leakage via prompts/training, and unreliable model output.",
                      "csf": ["PR.DS-10", "PR.AA-05", "GV.PO-02"]})
    if any(t in techs for t in ("AWS", "Azure", "GCP")):
        risks.append({"title": "Cloud misconfiguration",
                      "description": "Public storage, over-permissive IAM and missing encryption/logging are common cloud failure modes.",
                      "csf": ["PR.PS-01", "PR.AA-05", "PR.DS-01"]})
    return risks


def _nice(hit: str) -> str:
    if hit.startswith("flag:"):
        return FLAG_LABELS.get(hit[5:], hit[5:].replace("_", " "))
    if ":" in hit:
        kind, _, value = hit.partition(":")
        return f"{kind} {value.replace('_', ' ')}"
    return f"“{hit}”"


def heuristic_scope(review: dict, catalog: Catalog) -> dict:
    text = _text(review)
    tokens = _tokens(review)
    applies = applicable_frameworks(catalog, tokens, text)
    techs = detect_technologies(text, catalog)
    subs = []
    for sid, s in catalog.subcategories.items():
        fw = _framework_of(s)
        if fw not in applies:
            continue
        hits = []
        for t in s.get("triggers", []):
            t = str(t).lower()
            if ":" in t:  # profile token, e.g. flag:uses_ai, system:ai_agent, exposure:public
                if t in tokens:
                    hits.append(t)
            elif re.search(rf"(?<![a-z0-9]){re.escape(t)}", text):
                hits.append(t)
        if not (s.get("baseline") or hits):
            continue
        if s["scope"] == "org" and len(hits) < 2:
            continue
        prio = "high" if len(hits) >= 2 else "medium" if (hits or s.get("baseline")) else "low"
        baseline = ("Baseline requirement for every project review" if fw == CSF_ID
                    else f"Baseline {s.get('framework_short', fw)} requirement for this type of system")
        rationale = ("Matched " + ", ".join(_nice(h) for h in hits)) if hits else baseline
        if hits and s.get("baseline"):
            rationale += " (baseline)"
        subs.append({"id": sid, "priority": prio, "rationale": rationale})
    rating, why = heuristic_risk(review, text)
    return {
        "summary": (f"{'New initiative' if review.get('change_type') == 'new' else 'Change'} “{review.get('title')}”. "
                    f"Scoped offline using keyword and intake-flag rules - configure an AI provider in Settings "
                    f"for context-aware scoping."),
        "inherent_risk": rating,
        "risk_rationale": why,
        "key_risks": heuristic_key_risks(review, techs),
        "technologies": techs,
        "services": detect_services(text),
        "subcategories": subs,
        "clarifying_questions": [str(q) for q in ((review.get("design") or {}).get("open_questions") or [])][:8],
    }


# --------------------------------------------------------------------------- LLM
SYSTEM_PROMPT = """You are a principal security architect running the intake/scoping step of a
security design review for a new initiative or a change to an existing system.

You use NIST Cybersecurity Framework (CSF) 2.0 subcategories as the review requirements.
Each subcategory is mapped (by NIST) to SP 800-53 Rev 5 controls, and those controls are
mapped to Checkov infrastructure-as-code checks, so the platforms you select determine
which technical checks the project team must satisfy.

Select the subcategories that genuinely need to be answered by THIS project team. Prefer
"project" scope items; only include "org" scope items if the change materially affects
that organisation-wide outcome. Typically choose 15-40 subcategories. Be specific in your
rationale - reference the actual technologies, data and integrations described.

When additional requirement frameworks are listed (e.g. NIST AI RMF, OWASP Top 10 lists),
they apply to this profile: also select their requirements that this team must answer
(typically 5-20 in total across them), using their exact ids in "subcategories".

Return ONLY a JSON object with exactly these keys:
{
  "summary": "2-3 sentence architect's summary of what is changing and why it matters for security",
  "inherent_risk": "low|medium|high|critical",
  "risk_rationale": "one sentence",
  "key_risks": [{"title": "...", "description": "...", "csf": ["PR.DS-01", ...]}],
  "technologies": ["values chosen ONLY from the allowed technologies list"],
  "services": ["lower-case cloud/service keywords in the stack, e.g. s3, rds, api gateway, key vault"],
  "subcategories": [{"id": "PR.DS-01", "priority": "high|medium|low", "rationale": "why it applies here"}],
  "clarifying_questions": ["project-specific questions the reviewer should ask that the NIST questions do not cover"]
}"""


def _framework_sections(review: dict, catalog: Catalog) -> str:
    """Prompt sections for the additional frameworks that apply to this review profile."""
    applies = applicable_frameworks(catalog, _tokens(review), _text(review))
    out = []
    for fw in getattr(catalog, "frameworks", []):
        if fw["id"] == CSF_ID or fw["id"] not in applies:
            continue
        lines = []
        for s in catalog.subcategories.values():
            if _framework_of(s) != fw["id"]:
                continue
            label = s["text"] if s.get("title", s["id"]) == s["id"] else f"{s['title']}: {s['text']}"
            lines.append(f"{s['id']} [{s['scope']}] {label[:220]}")
        out.append(f"\n\n## {fw['name']} {fw['version']} (id [scope] requirement)\n" + "\n".join(lines))
    return "".join(out)


def build_user_prompt(review: dict, catalog: Catalog) -> str:
    lines = []
    for s in catalog.subcategories.values():
        if _framework_of(s) == CSF_ID:
            lines.append(f"{s['id']} [{s['scope']}] {s['text']}")
    intake = {
        "title": review.get("title"),
        "type": "New initiative" if review.get("change_type") == "new" else "Change to existing system",
        "description": review.get("description"),
        "tech_stack": review.get("tech_stack"),
        "business_unit": review.get("business_unit"),
        "profile": profile_summary(review),
        "handles_personal_or_sensitive_data": bool(review.get("personal_data")),
    }
    design = review.get("design") or {}
    if design.get("summary"):
        intake["design_from_documents"] = {k: design.get(k) for k in (
            "summary", "components", "data_flows", "trust_boundaries", "integrations", "notable_concerns")
            if design.get(k)}
    code = review.get("code_review") or {}
    if code.get("summary"):
        intake["code_review"] = {"summary": code["summary"],
                                 "top_findings": [f["title"] for f in (code.get("findings") or [])[:15]]}
    tms = [t for t in review.get("linked_threat_models") or [] if t.get("threats")]
    if tms:
        intake["threat_models"] = [{"title": t["title"], "summary": t["summary"],
                                    "threats": [f"[{x['category']}] {x['title']}" for x in t["threats"][:30]]}
                                   for t in tms]
    return (
        "## Review intake\n" + json.dumps(intake, indent=2) +
        "\n\n## Allowed technologies (Checkov platforms)\n" + ", ".join(sorted(catalog.providers)) +
        "\n\n## NIST CSF 2.0 subcategories (id [scope] outcome)\n" + "\n".join(lines) +
        _framework_sections(review, catalog)
    )


def _clean(result: dict, catalog: Catalog) -> dict:
    allowed_tech = {p.lower(): p for p in catalog.providers}
    subs, seen = [], set()
    for item in result.get("subcategories") or []:
        if isinstance(item, str):
            item = {"id": item}
        sid = str(item.get("id", "")).strip().upper()
        if sid in catalog.subcategories and sid not in seen:
            seen.add(sid)
            prio = str(item.get("priority", "medium")).lower()
            subs.append({"id": sid, "priority": prio if prio in ("high", "medium", "low") else "medium",
                         "rationale": str(item.get("rationale", ""))[:1000]})
    risk = str(result.get("inherent_risk", "")).lower()
    return {
        "summary": str(result.get("summary", ""))[:2000],
        "inherent_risk": risk if risk in ("low", "medium", "high", "critical") else "medium",
        "risk_rationale": str(result.get("risk_rationale", ""))[:500],
        "key_risks": [
            {"title": str(r.get("title", ""))[:200], "description": str(r.get("description", ""))[:800],
             "csf": [c for c in (r.get("csf") or []) if c in catalog.subcategories]}
            for r in (result.get("key_risks") or []) if isinstance(r, dict)
        ][:10],
        "technologies": sorted({allowed_tech[t.lower()] for t in result.get("technologies") or []
                                if isinstance(t, str) and t.lower() in allowed_tech}),
        "services": [str(s).lower()[:40] for s in (result.get("services") or []) if isinstance(s, str)][:30],
        "subcategories": subs,
        "clarifying_questions": [str(q)[:500] for q in (result.get("clarifying_questions") or [])][:10],
    }


async def scope_review(review: dict, catalog: Catalog, llm: LLM | None) -> dict:
    """Run scoping with the configured LLM, falling back to heuristics on failure."""
    meta = {"scoped_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if llm is not None:
        try:
            raw = await llm.complete_json(SYSTEM_PROMPT, build_user_prompt(review, catalog))
            result = _clean(raw, catalog)
            if not result["subcategories"]:
                raise ProviderError("model returned no valid CSF subcategories")
            if not result["technologies"]:
                result["technologies"] = detect_technologies(_text(review), catalog)
            return {**result, **meta, "provider": llm.label, "source": "ai"}
        except (ProviderError, ValueError, KeyError, TypeError) as e:
            result = heuristic_scope(review, catalog)
            return {**result, **meta, "provider": "heuristic", "source": "heuristic",
                    "warning": f"AI scoping failed, used offline rules instead: {e}"}
    return {**heuristic_scope(review, catalog), **meta, "provider": "heuristic", "source": "heuristic"}
