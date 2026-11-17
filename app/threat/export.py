"""Markdown rendering of threat-model artifacts: the standalone download and the review report section.

Only threats with a verified attack path are reported by default; unverified (hypothetical) and mitigated ones are
counted, and listed separately only when asked for.
"""
from __future__ import annotations

from .verify import STATUS_LABEL, is_verified, path_summary, status_of

APP_TYPE_LABEL = {"web": "Web / API application", "genai": "Generative AI application",
                  "agentic": "Agentic AI application"}


def _esc(s) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", "<br>")


def _data(arts: dict, kind: str) -> dict:
    return (arts.get(kind) or {}).get("data") or {}


def _split(arts: dict) -> tuple[list[dict], list[dict]]:
    threats = _data(arts, "threat_model").get("threats") or []
    return [t for t in threats if is_verified(t)], [t for t in threats if not is_verified(t)]


def _omitted_note(rest: list[dict], listed: bool) -> list[str]:
    if not rest:
        return []
    return [f"_{len(rest)} threat(s) without a verified attack path (unverified or mitigated) are "
            f"{'listed separately below' if listed else 'not included'}; they have no code-verified entry point → "
            f"sink path, so they are not rated._", ""]


def threat_table(arts: dict, threats: list[dict] | None = None) -> list[str]:
    dread = {a["threat_id"]: a for a in _data(arts, "dread").get("assessments") or []}
    out = ["| ID | Category | Threat | Component | Likelihood | DREAD | Mappings |", "|---|---|---|---|---|---|---|"]
    for t in _split(arts)[0] if threats is None else threats:
        maps = [t.get("owasp_top10"), t.get("owasp_llm"), t.get("owasp_asi"), *(t.get("mitre_attack") or []),
                *(t.get("mitre_atlas") or []), *(t.get("csf") or [])]
        a = dread.get(t["id"])
        score = f"{a['score']} ({a['rating']})" if a else "-"
        text = f"**{t['title']}** - {t.get('scenario', '')}" + (f"\nImpact: {t['impact']}" if t.get("impact") else "") \
            + (f"\nCode: {', '.join(t['evidence'])}" if t.get("evidence") else "") \
            + (f"\nAttack path: {path_summary(t, 8)}" if t.get("attack_path") else "")
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


def unverified_table(threats: list[dict]) -> list[str]:
    out = ["| ID | Status | Threat | Why it is not verified |", "|---|---|---|---|"]
    for t in threats:
        why = "; ".join((t.get("verification") or {}).get("reasons") or []) or "Not verified."
        out.append(f"| {t['id']} | {STATUS_LABEL[status_of(t)]} | **{_esc(t['title'])}** - {_esc(t.get('scenario'))} | "
                   f"{_esc(why)} |")
    return out


def report_section(arts: dict, title: str = "") -> list[str]:
    """Verified threats + DREAD ratings for the review report; empty when there is no threat model."""
    tm = _data(arts, "threat_model")
    if not tm.get("threats"):
        return []
    verified, rest = _split(arts)
    out = [f"## Threat model{f' {title}' if title else ''}", ""]
    if tm.get("summary"):
        out += [tm["summary"], ""]
    out += (threat_table(arts, verified) if verified else ["_No threat has a verified attack path._"]) + [""]
    out += _omitted_note(rest, False)
    if _data(arts, "dread").get("assessments"):
        out += ["### DREAD ratings", ""] + dread_table(arts) + [""]
    return out


def tree_proof_lines(tree: dict) -> list[str]:
    """The attacks proven end to end (goal → leaf, every node backed by a verified attack path in the code)."""
    if "goal_status" not in tree:
        return []
    paths = tree.get("verified_paths") or []
    v = tree.get("verification") or {}
    out = [f"_Leaves: {v.get('verified', 0)} proven in code, {v.get('unverified', 0)} hypothetical, "
           f"{v.get('mitigated', 0)} blocked by a control. Goal {'reachable through a proven attack' if tree['goal_status'] == 'verified' else 'not proven reachable'}. "
           "In the diagram proven attacks are red with bold edges, hypothetical ones grey and dashed, blocked ones "
           "green._", ""]
    if paths:
        out += ["**Proven attack paths**", ""]
        for p in paths:
            proof = "; ".join(f"{x['threat_id']}: entry `{x['entry']}` → sink `{x['sink']}`" for x in p.get("proof") or [])
            out.append(f"- {' → '.join(p['nodes'])}" + (f" ({proof})" if proof else ""))
        out.append("")
    return out


def render_export(review: dict, arts: dict, include_unverified: bool = False) -> str:
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
        verified, rest = _split(arts)
        out += ["## Threats (verified attack paths)", ""]
        out += (threat_table(arts, verified) if verified else ["_No threat has a verified attack path._"]) + [""]
        out += _omitted_note(rest, include_unverified)
        if include_unverified and rest:
            out += ["## Unverified (hypothetical) and mitigated threats", ""] + unverified_table(rest) + [""]
    dfd = _data(arts, "dfd")
    if dfd.get("mermaid"):
        out += ["## Data flow diagram", "", "```mermaid", dfd["mermaid"], "```", ""]
    tree = _data(arts, "attack_tree")
    if tree.get("mermaid"):
        out += ["## Attack tree", ""] + ([f"**Goal:** {tree['goal']}", ""] if tree.get("goal") else [])
        out += tree_proof_lines(tree)
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
