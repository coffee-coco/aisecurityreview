"""Whole-codebase security review.

Pipeline (each stage is deterministic for the same inputs):
1. inventory  - languages, frameworks, dependencies, IaC, HTTP routes
2. rules      - static rules across every file (systemic, aggregated findings)
3. checkov    - real Checkov run over IaC (resource-level misconfigurations)
4. holistic   - cross-cutting heuristics + an AI review that reads the code *together*
                (auth model, trust boundaries, data flows, agent tool use ...) with a
                map-reduce strategy when the codebase is bigger than the model context.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Awaitable, Callable

from ..catalog import Catalog, base_control
from ..library import mitigation_library
from ..ai.providers import LLM, ProviderError
from .evidence import verify_snippet
from .rules import RULES, SEV_ORDER, TEST_PATH, run_rules
from .workspace import build_inventory, iter_sources, read_text

Progress = Callable[[float, str], Awaitable[None]]
CODE_LANGS_FOR_AI = {"Python", "JavaScript", "TypeScript", "Java", "Kotlin", "Go", "Ruby", "PHP", "C#", "Rust",
                     "Scala", "Swift", "Dart", "Groovy", "Elixir", "Vue", "Svelte", "C", "C++", "Shell", "PowerShell",
                     "Terraform", "HCL", "Bicep", "YAML", "JSON", "TOML", "INI", "Config", "Properties", "Dockerfile",
                     "SQL", "GraphQL", "Protobuf", "HTML", "XML", "Env", "Gradle", "Make", "Batch", "Markdown"}


# --------------------------------------------------------------------------- checkov
def _checkov_bin() -> str | None:
    local = Path(sys.executable).parent / "checkov"
    if local.exists():
        return str(local)
    return shutil.which("checkov")


async def run_checkov(roots: list[tuple[str, Path]], cat: Catalog, timeout: int = 900) -> dict:
    exe = _checkov_bin()
    if not exe:
        return {"ran": False, "error": "Checkov is not installed (pip install checkov)."}
    failed: dict[str, dict] = {}
    passed: set[str] = set()
    frameworks: set[str] = set()
    errors = []
    multi = len(roots) > 1
    for label, root in roots:
        proc = await asyncio.create_subprocess_exec(
            exe, "-d", str(root), "-o", "json", "--compact", "--skip-download", "--soft-fail",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "BC_SKIP_MAPPING": "TRUE", "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false"})
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            errors.append(f"{label}: timed out after {timeout}s")
            continue
        text = out.decode("utf-8", "replace").strip()
        if not text:
            continue
        try:
            data = json.loads(text[text.find("[") if text.lstrip().startswith("[") else text.find("{"):])
        except json.JSONDecodeError:
            errors.append(f"{label}: could not parse Checkov output")
            continue
        for block in data if isinstance(data, list) else [data]:
            if not isinstance(block, dict) or "results" not in block:
                continue
            frameworks.add(block.get("check_type", ""))
            res = block["results"]
            for c in res.get("passed_checks", []):
                passed.add(c["check_id"])
            for c in res.get("failed_checks", []):
                f = failed.setdefault(c["check_id"], {"check_id": c["check_id"], "name": c.get("check_name", ""),
                                                      "guideline": c.get("guideline") or "", "resources": []})
                rng = c.get("file_line_range") or [0, 0]
                path = (c.get("file_path") or "").lstrip("/")
                if len(f["resources"]) < 25:
                    f["resources"].append({"file": f"{label}/{path}" if multi else path, "line": rng[0],
                                           "resource": c.get("resource", ""), "type": block.get("check_type", "")})
    passed -= set(failed)
    findings = []
    for cid, f in sorted(failed.items()):
        chk = cat.checks_by_id.get(cid, {})
        nist = chk.get("controls", [])[:6] if chk else []
        sev = "high" if any(k in f["name"].lower() for k in ("public", "encrypt", "0.0.0.0", "admin", "root",
                                                               "secret", "password", "wildcard", "*"))\
            else "medium"
        findings.append({
            "id": f"checkov:{cid}", "rule": cid, "title": f["name"] or cid, "severity": sev, "category": "iac",
            "description": f"Checkov {cid} failed for {len(f['resources'])} resource"
                           f"{'s' if len(f['resources']) != 1 else ''}: "
                           + ", ".join(r["resource"] for r in f["resources"][:4]),
            "evidence": [{"file": r["file"], "line": r["line"], "snippet": r["resource"]} for r in f["resources"]],
            "occurrences": len(f["resources"]), "recommendation": f["guideline"] or f"Remediate {cid}: {f['name']}.",
            "csf": [], "nist": nist, "mitigations": ["M-IAC-SCANNING", "M-CSPM"], "source": "checkov",
        })
    return {"ran": True, "frameworks": sorted(x for x in frameworks if x), "failed": len(failed),
            "passed": len(passed), "passed_ids": sorted(passed), "failed_ids": sorted(failed),
            "findings": findings, "error": "; ".join(errors)}


# --------------------------------------------------------------------------- holistic heuristics
AUTH_DEPS = ("jsonwebtoken", "passport", "next-auth", "@auth/", "pyjwt", "authlib", "fastapi-users", "flask-login",
             "flask-jwt", "django", "spring-boot-starter-security", "spring-security", "devise", "oauth", "msal",
             "okta", "auth0", "firebase-admin", "cognito", "keycloak", "jose", "express-session", "itsdangerous",
             "golang-jwt", "omniauth", "clerk", "supabase", "lucia", "iron-session", "python-jose")
RATE_DEPS = ("express-rate-limit", "rate-limiter-flexible", "slowapi", "flask-limiter", "django-ratelimit",
             "bucket4j", "resilience4j", "throttler", "@nestjs/throttler", "limiter", "ratelimit")
GUARD_DEPS = ("guardrails", "nemoguardrails", "llm-guard", "presidio", "rebuff", "lakera", "azure-ai-contentsafety",
              "llamafirewall", "promptguard", "garak")
WEB_FW = {"Express", "Fastify", "NestJS", "Next.js", "Koa", "hapi", "Django", "Flask", "FastAPI", "Starlette",
          "Tornado", "Spring Boot", "Rails", "Laravel", "Gin", "Echo", "Fiber", "ASP.NET Core"}


def _has_dep(deps: list[str], names: tuple[str, ...]) -> bool:
    return any(any(d == n or d.startswith(n) or n in d for n in names) for d in deps)


def holistic_heuristics(inv: dict, findings: list[dict], roots: list[tuple[str, Path]]) -> list[dict]:
    out = []
    deps = inv["dependencies"]
    paths = " ".join(f["path"].lower() for f in inv["file_list"])
    routes = inv["routes"]
    fw = set(inv["frameworks"])
    if routes and not _has_dep(deps, AUTH_DEPS) and not re.search(r"auth|login|session|jwt|oauth|token", paths):
        out.append({
            "id": "holistic:no-auth", "rule": "H-NO-AUTH", "title": "No authentication layer evident across the API",
            "severity": "high", "category": "auth",
            "description": f"{len(routes)} HTTP routes were found but no authentication library, middleware or "
                           f"auth module was identified anywhere in the codebase.",
            "evidence": [{"file": r["file"], "line": r["line"], "snippet": f"{r['method']} {r['route']}"}
                         for r in routes[:8]],
            "recommendation": "Confirm how callers are authenticated (gateway, SSO, mTLS). Enforce authentication "
                              "centrally (middleware / API gateway) with deny-by-default authorisation.",
            "csf": ["PR.AA-03", "PR.AA-05"], "nist": ["IA-2", "AC-3"], "mitigations": ["M-API-AUTH", "M-SSO"],
            "source": "holistic"})
    if routes and fw & WEB_FW and not _has_dep(deps, RATE_DEPS):
        out.append({
            "id": "holistic:no-rate-limit", "rule": "H-NO-RATE-LIMIT", "title": "No rate limiting in the application",
            "severity": "low", "category": "config",
            "description": "No rate-limiting library was found; brute force, scraping and denial-of-wallet "
                           "protection must come from an upstream gateway/WAF.",
            "evidence": [], "recommendation": "Apply per-client rate limits at the gateway/WAF or with middleware.",
            "csf": ["PR.IR-04"], "nist": ["SC-5"], "mitigations": ["M-RATE-LIMIT", "M-WAF"], "source": "holistic"})
    if "Express" in fw and "helmet" not in deps:
        out.append({
            "id": "holistic:no-helmet", "rule": "H-NO-SEC-HEADERS", "title": "Security headers not configured (Express)",
            "severity": "low", "category": "config",
            "description": "Express is used without helmet or equivalent, so CSP/HSTS/X-Frame-Options are not set "
                           "by the application.",
            "evidence": [], "recommendation": "Add helmet (or set headers at the CDN) with a strict CSP and HSTS.",
            "csf": ["PR.PS-01"], "nist": ["SC-8", "CM-6"], "mitigations": ["M-SECURITY-HEADERS"],
            "source": "holistic"})
    if inv["ai_frameworks"] and not _has_dep(deps, GUARD_DEPS):
        ai_files = [f["path"] for f in inv["file_list"] if re.search(r"agent|prompt|llm|chain|tool|rag", f["path"], re.I)]
        out.append({
            "id": "holistic:ai-no-guardrails", "rule": "H-AI-GUARDRAILS",
            "title": "LLM application without input/output guardrails",
            "severity": "medium", "category": "ai",
            "description": f"AI frameworks ({', '.join(inv['ai_frameworks'])}) are used but no guardrail / "
                           f"content-safety / PII-redaction component was found.",
            "evidence": [{"file": p, "line": 1, "snippet": ""} for p in ai_files[:6]],
            "recommendation": "Add prompt-injection detection, output filtering, PII redaction and tool-call "
                              "allow-listing; evaluate the model against an abuse test set before go-live.",
            "csf": ["PR.DS-10", "ID.RA-01"], "nist": ["SI-10", "SI-4"],
            "mitigations": ["M-AI-GUARDRAILS", "M-AI-EVAL"], "source": "holistic"})
    has_secret_finding = any(f["category"] == "secrets" for f in findings)
    env_files = [f["path"] for f in inv["file_list"] if re.search(r"(^|/)\.env(\.|$)", f["path"])
                 and not f["path"].endswith((".example", ".sample", ".template"))]
    if env_files and not has_secret_finding:
        out.append({
            "id": "holistic:env-files", "rule": "H-ENV-FILES", "title": "Environment files included in the codebase",
            "severity": "medium", "category": "secrets",
            "description": f"{len(env_files)} .env file(s) are present in the upload and may contain secrets.",
            "evidence": [{"file": p, "line": 1, "snippet": ""} for p in env_files[:8]],
            "recommendation": "Remove .env files from source control, add them to .gitignore and rotate any values.",
            "csf": ["PR.AA-01"], "nist": ["IA-5"], "mitigations": ["M-SECRETS-VAULT", "M-SECRET-SCANNING"],
            "source": "holistic"})
    return out


def infer_system_types(inv: dict) -> list[str]:
    fw = set(inv["frameworks"])
    langs = {l["name"] for l in inv["languages"]}
    out = []
    if fw & {"React", "Angular", "Vue", "Svelte", "Next.js"} or "HTML" in langs:
        out.append("web_app")
    if inv["routes"] or fw & WEB_FW:
        out.append("api")
    if inv["ai_frameworks"]:
        agentic = any(re.search(r"agent|tool|mcp|crew|autogen", f["path"], re.I) for f in inv["file_list"]) or \
            {"LangChain", "CrewAI", "AutoGen", "Model Context Protocol", "Semantic Kernel"} & fw
        out.append("ai_agent" if agentic else "ai_ml")
    if langs & {"Swift", "Dart", "Objective-C"} or any(d in inv["dependencies"] for d in ("react-native", "expo")):
        out.append("mobile_app")
    if inv["iac"] and not out:
        out.append("infrastructure")
    return out


# --------------------------------------------------------------------------- AI holistic review
CODE_SYSTEM = """You are a principal application security engineer doing a HOLISTIC security review of a whole
codebase for a security design review. Per-resource IaC misconfigurations are already covered by Checkov and
simple patterns by static rules (both listed) - do NOT repeat those. Focus on what only a whole-codebase view
reveals: the authentication and authorisation model and where it is (not) enforced, trust boundaries, data flows
of sensitive data end-to-end, multi-tenant isolation, business-logic flaws, secrets and key management design,
input handling across layers, outbound calls (SSRF), file handling, logging/monitoring gaps, dependency and
supply-chain posture, and for AI/agent systems: prompt-injection paths, tool permissions/excessive agency,
data leakage to models, output handling and human-in-the-loop.
Cite evidence as file paths and line numbers exactly as shown, with each snippet copied verbatim from the file
(without the line-number prefix) - snippets are checked against the code. Only report issues supported by the code.
severity: critical|high|medium|low   category: auth|access_control|secrets|injection|crypto|transport|config|
logging|ai|data_protection|file_handling|ssrf|supply_chain|business_logic|availability|error_handling
Return ONLY JSON:
{"summary": "3-6 sentence overall assessment of the security posture",
 "architecture": {"components": ["..."], "entry_points": ["..."], "data_stores": ["..."],
                  "external_services": ["..."], "auth_model": "...", "trust_boundaries": ["..."]},
 "system_types": ["web_app|api|mobile_app|ai_agent|ai_ml|data_platform|integration|infrastructure|internal_tool"],
 "data_types": ["pii|sensitive_pii|health|financial|payment_card|credentials|customer|employee|ip|operational"],
 "findings": [{"title": "...", "severity": "...", "category": "...", "description": "what and why it matters here",
               "evidence": [{"file": "path", "line": 12, "snippet": "short code excerpt"}],
               "recommendation": "specific fix", "csf": ["PR.AA-05"], "nist": ["AC-3"], "mitigations": ["M-..."]}],
 "strengths": ["good practices observed"],
 "open_questions": ["things the reviewer should ask the team"]}"""

MAP_SYSTEM = """You are an application security engineer reviewing ONE PART of a larger codebase as part of a
holistic review. Report security findings supported by this code, and concise notes that will help a later
whole-system synthesis (what this part does, how it authenticates/authorises, what data it handles, what it calls).
Do not repeat the static-rule/Checkov findings listed. Cite file paths and line numbers exactly as shown and copy
snippets verbatim from the file (without the line-number prefix).
Return ONLY JSON: {"notes": "...", "findings": [same finding schema as described: title, severity, category,
description, evidence[{file,line,snippet}], recommendation, csf, nist, mitigations]}"""


def _priority(path: str, lang: str, size: int, hit_files: set[str]) -> float:
    low = path.lower()
    s = 0.0
    if re.search(r"auth|login|session|jwt|oauth|permission|rbac|acl|policy|guard|middleware|security|crypto|token",
                 low):
        s += 6
    if re.search(r"agent|prompt|llm|tool|chain|rag|mcp|openai|anthropic|gemini|bedrock", low):
        s += 5
    if re.search(r"(^|/)(main|app|server|index|wsgi|asgi|program|startup|routes?|urls|controllers?|handlers?|"
                 r"api|views?|resolvers?|lambda|functions?)[./]", low):
        s += 4
    if re.search(r"config|settings|\.env|docker|compose|terraform|\.tf$|workflow|pipeline|helm|k8s|serverless", low):
        s += 3
    if re.search(r"upload|file|storage|s3|blob|db|database|model|repository|query|sql", low):
        s += 2
    if path in hit_files:
        s += 3
    if lang in ("Markdown", "JSON") and not re.search(r"package\.json|appsettings|config", low):
        s -= 3
    if TEST_PATH.search(path):
        s -= 6
    s -= min(size / 40_000, 3)
    return s


def _numbered(text: str, max_lines: int = 4000) -> str:
    lines = text.split("\n")[:max_lines]
    return "\n".join(f"{i:>5}| {ln[:400]}" for i, ln in enumerate(lines, 1))


def _evidence(e: dict, sources: dict[str, Path]) -> dict:
    """Evidence item; ``verified`` only when the quoted snippet is found in the uploaded file."""
    path = str(e["file"]).strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    try:
        line = int(e.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    snippet = str(e.get("snippet") or "")
    item = {"file": path[:300], "line": line, "snippet": snippet[:300], "verified": path in sources}
    if item["verified"] and snippet.strip():
        chk = verify_snippet(sources[path], snippet)
        item["verified"] = chk.verified
        if chk.verified:
            item["line"], item["end_line"] = chk.start_line, chk.end_line
    return item


def _clean_findings(raw: list, cat: Catalog, sources: dict[str, Path]) -> list[dict]:
    lib = mitigation_library()
    out = []
    for f in raw or []:
        if not isinstance(f, dict) or not f.get("title"):
            continue
        sev = str(f.get("severity", "medium")).lower()
        sev = sev if sev in SEV_ORDER else "medium"
        ev = [_evidence(e, sources) for e in (f.get("evidence") or [])[:10] if isinstance(e, dict) and e.get("file")]
        title = str(f["title"])[:200]
        fp = hashlib.sha1((title.lower() + "|" + (ev[0]["file"] if ev else "")).encode()).hexdigest()[:10]
        out.append({
            "id": f"ai:{fp}", "rule": "", "title": title, "severity": sev,
            "category": re.sub(r"[^a-z_]", "", str(f.get("category", "config")).lower()) or "config",
            "description": str(f.get("description", ""))[:2000], "evidence": ev, "occurrences": len(ev),
            "recommendation": str(f.get("recommendation", ""))[:1500],
            "csf": [c for c in (f.get("csf") or []) if isinstance(c, str) and c in cat.subcategories][:5],
            "nist": [c for c in (f.get("nist") or []) if isinstance(c, str) and
                     (c in cat.controls or base_control(c) in cat.controls)][:6],
            "mitigations": [m for m in (f.get("mitigations") or []) if m in lib][:4], "source": "ai",
            "verified": all(e["verified"] for e in ev),
        })
    return out


def _dedupe(findings: list[dict]) -> list[dict]:
    from ..profile import similarity
    out: list[dict] = []
    for f in findings:
        dup = next((o for o in out if similarity(o["title"], f["title"]) >= 0.6), None)
        if dup:
            known = {(e["file"], e["line"]) for e in dup["evidence"]}
            dup["evidence"] += [e for e in f["evidence"] if (e["file"], e["line"]) not in known][:6]
            if "verified" in dup:
                dup["verified"] = all(e.get("verified", True) for e in dup["evidence"])
            if SEV_ORDER[f["severity"]] < SEV_ORDER[dup["severity"]]:
                dup["severity"] = f["severity"]
            continue
        out.append(f)
    return out


async def ai_holistic(llm: LLM, inv: dict, roots: list[tuple[str, Path]], prior: list[dict], profile: dict,
                      cat: Catalog, progress: Progress) -> dict:
    hit_files = {e["file"] for f in prior for e in f["evidence"]}
    files = [f for f in inv["file_list"] if f["lang"] in CODE_LANGS_FOR_AI]
    files.sort(key=lambda f: (-_priority(f["path"], f["lang"], f["bytes"], hit_files), f["path"]))
    abs_paths = dict(iter_sources(roots))
    header = json.dumps({
        "review_profile": profile,
        "inventory": {k: inv[k] for k in ("files", "lines", "languages", "frameworks", "ai_frameworks", "iac",
                                          "manifests")},
        "dependencies": inv["dependencies"][:250],
        "http_routes": [f"{r['method']} {r['route']} ({r['file']}:{r['line']})" for r in inv["routes"][:150]],
        "already_found_by_static_rules_and_checkov": [f"[{f['severity']}] {f['title']}" for f in prior[:80]],
        "file_tree": [f"{f['path']} ({f['lines']} lines)" for f in inv["file_list"][:3000]],
    }, indent=0)
    budget = int(llm.context_chars * 0.75) - len(header) - 6000
    blobs: list[tuple[str, str]] = []
    for f in files:
        text = read_text(abs_paths[f["path"]]) if f["path"] in abs_paths else None
        if text is None or not text.strip():
            continue
        blobs.append((f["path"], f"\n===== FILE: {f['path']} =====\n{_numbered(text)}\n"))
    total = sum(len(b) for _, b in blobs)
    coverage = {"files_total": len(files), "files_reviewed": 0, "chars_reviewed": 0, "mode": "single"}

    if total <= budget:
        await progress(0.55, f"AI reviewing {len(blobs)} files together…")
        res = await llm.complete_json(CODE_SYSTEM, header + "\n\n## SOURCE CODE\n" + "".join(b for _, b in blobs))
        coverage.update(files_reviewed=len(blobs), chars_reviewed=total)
        return {**res, "findings": _clean_findings(res.get("findings"), cat, abs_paths), "coverage": coverage}

    # Map-reduce: batch files in priority order, review each batch, then synthesise holistically.
    coverage["mode"] = "map-reduce"
    batch_budget = max(min(budget, 400_000), 30_000)
    batches: list[list[tuple[str, str]]] = [[]]
    size = 0
    for path, b in blobs:
        if size + len(b) > batch_budget and batches[-1]:
            batches.append([])
            size = 0
        if len(b) > batch_budget:
            b = b[:batch_budget]
        batches[-1].append((path, b))
        size += len(b)
    max_batches = 12
    reviewed = batches[:max_batches]
    notes, findings = [], []
    for i, batch in enumerate(reviewed):
        await progress(0.45 + 0.35 * i / len(reviewed), f"AI reviewing part {i + 1}/{len(reviewed)} "
                                                         f"({len(batch)} files)…")
        try:
            r = await llm.complete_json(MAP_SYSTEM, header + f"\n\n## SOURCE CODE (part {i + 1} of "
                                                             f"{len(reviewed)})\n" + "".join(b for _, b in batch))
        except ProviderError as e:
            notes.append(f"Part {i + 1}: AI error {e}")
            continue
        notes.append(f"Part {i + 1} ({', '.join(p for p, _ in batch[:12])}{'…' if len(batch) > 12 else ''}): "
                     f"{str(r.get('notes', ''))[:3000]}")
        findings += _clean_findings(r.get("findings"), cat, abs_paths)
        coverage["files_reviewed"] += len(batch)
        coverage["chars_reviewed"] += sum(len(b) for _, b in batch)
    await progress(0.85, "AI synthesising whole-system view…")
    reduce_user = header + "\n\n## NOTES FROM REVIEWING EACH PART\n" + "\n".join(notes) + \
        "\n\n## FINDINGS FROM PARTS (merge, dedupe, add cross-cutting issues)\n" + \
        json.dumps([{k: f[k] for k in ("title", "severity", "category", "description", "evidence", "recommendation",
                                       "csf", "nist", "mitigations")} for f in findings][:150])
    res = await llm.complete_json(CODE_SYSTEM, reduce_user)
    merged = _clean_findings(res.get("findings"), cat, abs_paths) + findings
    return {**res, "findings": _dedupe(merged), "coverage": coverage}


# --------------------------------------------------------------------------- orchestrate
def offline_summary(inv: dict, findings: list[dict], system_types: list[str]) -> str:
    from ..profile import SYSTEM_TYPES
    langs = ", ".join(f"{l['name']} {l['pct']}%" for l in inv["languages"][:4]) or "no recognised languages"
    parts = [f"{inv['files']} files / {inv['lines']:,} lines ({langs})."]
    if inv["frameworks"]:
        parts.append("Frameworks: " + ", ".join(inv["frameworks"][:10]) + ".")
    if system_types:
        parts.append("Looks like: " + ", ".join(SYSTEM_TYPES.get(s, s) for s in system_types) + ".")
    if inv["routes"]:
        parts.append(f"{len(inv['routes'])} HTTP route definitions found.")
    if inv["iac"]:
        parts.append("Infrastructure as code: " + ", ".join(f"{i['type']} ({i['files']})" for i in inv["iac"]) + ".")
    by = {}
    for f in findings:
        by[f["severity"]] = by.get(f["severity"], 0) + 1
    if findings:
        parts.append("Findings: " + ", ".join(f"{by[s]} {s}" for s in ("critical", "high", "medium", "low") if s in by)
                     + ".")
    else:
        parts.append("No issues detected by static rules or Checkov.")
    return " ".join(parts)


async def review_codebase(roots: list[tuple[str, Path]], cat: Catalog, llm: LLM | None, profile: dict,
                          progress: Progress, use_ai: bool = True, use_checkov: bool = True) -> dict:
    await progress(0.05, "Building inventory…")
    inv = await asyncio.to_thread(build_inventory, roots)
    await progress(0.15, f"Running {len(RULES)} static rules over {inv['files']} files…")
    rule_findings, rule_stats = await asyncio.to_thread(run_rules, roots)
    checkov = {"ran": False}
    if use_checkov and inv["iac"]:
        await progress(0.3, "Running Checkov on infrastructure as code…")
        checkov = await run_checkov(roots, cat)
    elif use_checkov:
        checkov = {"ran": False, "error": "No infrastructure-as-code files found."}
    prior = rule_findings + checkov.get("findings", [])
    holistic = holistic_heuristics(inv, prior, roots)
    system_types = infer_system_types(inv)
    result = {
        "inventory": {**inv, "file_list": inv["file_list"][:5000]},
        "rule_stats": rule_stats,
        "checkov": {k: v for k, v in checkov.items() if k != "findings"},
        "architecture": {}, "strengths": [], "open_questions": [], "data_types": [],
        "system_types": system_types, "provider": "heuristic", "warnings": [],
        "coverage": {"files_total": inv["files"], "files_reviewed": 0, "mode": "rules"},
    }
    ai_findings: list[dict] = []
    if llm is not None and use_ai and inv["files"]:
        try:
            res = await ai_holistic(llm, inv, roots, prior + holistic, profile, cat, progress)
            ai_findings = res["findings"]
            result.update(
                summary=str(res.get("summary", ""))[:3000],
                architecture=res.get("architecture") if isinstance(res.get("architecture"), dict) else {},
                strengths=[str(s)[:300] for s in (res.get("strengths") or [])][:12],
                open_questions=[str(s)[:400] for s in (res.get("open_questions") or [])][:12],
                coverage=res["coverage"], provider=llm.label)
            from ..profile import DATA_TYPES, SYSTEM_TYPES
            st = [s for s in (res.get("system_types") or []) if s in SYSTEM_TYPES]
            result["system_types"] = list(dict.fromkeys(st + system_types))
            result["data_types"] = [d for d in (res.get("data_types") or []) if d in DATA_TYPES]
        except ProviderError as e:
            result["warnings"].append(f"AI review unavailable, showing rules + Checkov only: {e}")
    elif use_ai and llm is None:
        result["warnings"].append("No AI provider configured - showing static rules, Checkov and holistic heuristics. "
                                  "Configure Gemini in Settings for the full AI whole-codebase review.")
    findings = _dedupe(ai_findings + holistic) + rule_findings + checkov.get("findings", [])
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                 {"ai": 0, "holistic": 1, "rule": 2, "checkov": 3}.get(f["source"], 4), f["title"]))
    result["findings"] = findings
    if not result.get("summary"):
        result["summary"] = offline_summary(inv, findings, result["system_types"])
    await progress(0.97, "Saving results…")
    return result
