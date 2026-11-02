"""Markdown rendering of threat-model artifacts: the standalone download and the review report section."""
from __future__ import annotations

APP_TYPE_LABEL = {"web": "Web / API application", "genai": "Generative AI application",
                  "agentic": "Agentic AI application"}


def _esc(s) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", "<br>")


def _data(arts: dict, kind: str) -> dict:
    return (arts.get(kind) or {}).get("data") or {}


def threat_table(arts: dict) -> list[str]:
    dread = {a["threat_id"]: a for a in _data(arts, "dread").get("assessments") or []}
    out = ["| ID | Category | Threat | Component | Likelihood | DREAD | Mappings |", "|---|---|---|---|---|---|---|"]
    for t in _data(arts, "threat_model").get("threats") or []:
        maps = [t.get("owasp_top10"), t.get("owasp_llm"), t.get("owasp_asi"), *(t.get("mitre_attack") or []),
                *(t.get("mitre_atlas") or []), *(t.get("csf") or [])]
        a = dread.get(t["id"])
        score = f"{a['score']} ({a['rating']})" if a else "-"
        text = f"**{t['title']}** - {t.get('scenario', '')}" + (f"\nImpact: {t['impact']}" if t.get("impact") else "") \
            + (f"\nCode: {', '.join(t['evidence'])}" if t.get("evidence") else "")
        out.append(f"| {t['id']} | {t['category']} | {_esc(text)} | {_esc(t.get('component'))} | "
                   f"{t.get('likelihood_hint', '')} | {score} | {_esc(', '.join(m for m in maps if m))} |")
    return out


def dread_table(arts: dict) -> list[str]:
    titles = {t["id"]: t["title"] for t in _data(arts, "threat_model").get("threats") or []}
    out = ["| Threat | Damage | Reproducibility | Exploitability | Affected users | Discoverability | Score | Rating |",
           "|---|---|---|---|---|---|---|---|"]
    for a in _data(arts, "dread").get("assessments") or []:
        out.append(f"| {a['threat_id']} {_esc(titles.get(a['threat_id'], ''))} | {a['damage']} | "
                   f"{a['reproducibility']} | {a['exploitability']} | {a['affected_users']} | "
                   f"{a['discoverability']} | {a['score']} | {a['rating'].title()} |")
    return out


def report_section(arts: dict, title: str = "") -> list[str]:
    """Threat table + DREAD ratings for the review report; empty when there is no threat model."""
    tm = _data(arts, "threat_model")
    if not tm.get("threats"):
        return []
    out = [f"## Threat model{f' {title}' if title else ''}", ""]
    if tm.get("summary"):
        out += [tm["summary"], ""]
    out += threat_table(arts) + [""]
    if _data(arts, "dread").get("assessments"):
        out += ["### DREAD ratings", ""] + dread_table(arts) + [""]
    return out


def render_export(review: dict, arts: dict) -> str:
    tm = _data(arts, "threat_model")
    out = [f"# Threat model {review['ref']}: {review['title']}", ""]
    if tm:
        meta = arts["threat_model"]
        out += [f"_Application type: {APP_TYPE_LABEL.get(tm.get('app_type'), tm.get('app_type', ''))} · "
                f"{meta['source']}{' (' + meta['model'] + ')' if meta.get('model') else ''} · "
                f"updated {meta['updated_at']}_", ""]
        if tm.get("summary"):
            out += ["## Summary", "", tm["summary"], ""]
        if tm.get("assumptions"):
            out += ["## Assumptions", ""] + [f"- {a}" for a in tm["assumptions"]] + [""]
        out += ["## Threats", ""] + threat_table(arts) + [""]
    dfd = _data(arts, "dfd")
    if dfd.get("mermaid"):
        out += ["## Data flow diagram", "", "```mermaid", dfd["mermaid"], "```", ""]
    tree = _data(arts, "attack_tree")
    if tree.get("mermaid"):
        out += ["## Attack tree", ""] + ([f"**Goal:** {tree['goal']}", ""] if tree.get("goal") else [])
        out += ["```mermaid", tree["mermaid"], "```", ""]
    mits = _data(arts, "mitigations").get("mitigations") or []
    if mits:
        out += ["## Mitigations", "", "| ID | Mitigation | Threats | SP 800-53 | Library | Priority |",
                "|---|---|---|---|---|---|"]
        for m in mits:
            text = f"**{m['title']}** - {m['description']}"
            out.append(f"| {m['id']} | {_esc(text)} | {', '.join(m['threat_ids'])} | {', '.join(m['nist'])} | "
                       f"{m.get('library_ref') or '-'} | {m['priority'].title()} |")
        out.append("")
    if _data(arts, "dread").get("assessments"):
        out += ["## DREAD assessment", ""] + dread_table(arts) + [""]
    cases = _data(arts, "test_cases").get("test_cases") or []
    if cases:
        out += ["## Security test cases", ""]
        for c in cases:
            out += [f"### {c['id']} - {c['title']} ({c['threat_id']})", "", "```gherkin", c["gherkin"], "```", ""]
    if tm.get("improvement_suggestions"):
        out += ["## Information that would improve this threat model", ""]
        out += [f"- {s}" for s in tm["improvement_suggestions"]] + [""]
    return "\n".join(out) + "\n"
