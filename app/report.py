"""Markdown export of a completed (or in-flight) security review."""
from __future__ import annotations

import sqlite3

from . import db
from .catalog import Catalog
from .frameworks import CSF_ID, framework_meta, framework_of
from .threat.export import report_section
from .threat.store import get_artifacts

REQ_LABEL = {"open": "⬜ Open", "met": "✅ Met", "partial": "🟨 Partial", "not_met": "❌ Not met", "na": "➖ N/A"}
STATUS_LABEL = {"new": "New", "in_progress": "In progress", "awaiting_info": "Awaiting info",
                "approved": "Approved", "rejected": "Rejected"}


def _esc(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", "<br>")


def render_markdown(r: dict, cat: Catalog) -> str:
    ai = r.get("ai_meta") or {}
    reqs = r["requirements"]
    done = sum(1 for x in reqs if x["status"] != "open")
    gaps = [x for x in reqs if x["status"] in ("not_met", "partial")]
    used = dict.fromkeys(framework_of(cat, x["subcategory_id"]) for x in reqs)
    extra = ", ".join(f"{m['name']} {m['version']}" for m in (framework_meta(cat, f) for f in used if f != CSF_ID) if m)
    out = [
        f"# Security Review {r['ref']}: {r['title']}",
        "",
        "| | |", "|---|---|",
        f"| **Type** | {'New initiative' if r['change_type'] == 'new' else 'Change to existing system'} |",
        f"| **Status** | {STATUS_LABEL.get(r['status'], r['status'])} |",
        f"| **Risk rating** | {(r['risk_rating'] or 'unrated').title()} |",
        f"| **Requester** | {_esc(r['requester'])} |",
        f"| **Business owner** | {_esc(r['business_owner'])} |",
        f"| **Reviewer** | {_esc(r['reviewer'])} |",
        f"| **Business unit** | {_esc(r['business_unit'])} |",
        f"| **Data classification** | {r['data_classification'].title()} |",
        f"| **Platforms** | {', '.join(r['technologies']) or '-'} |",
        f"| **Due** | {r['due_date'] or '-'} |",
        f"| **Progress** | {done}/{len(reqs)} requirements assessed, {len(gaps)} gaps |",
        "",
        f"_Framework: NIST CSF {cat.meta['csf_version']} → SP 800-53 Rev {cat.meta['sp80053_version']} → "
        f"Checkov {cat.meta['checkov_version']}_" + (f"  \n_Additional frameworks: {extra}_" if extra else ""),
        "",
        "## Description", "", r["description"] or "_No description provided._", "",
    ]
    if ai.get("summary"):
        out += ["## Scoping summary", "", ai["summary"], ""]
        if ai.get("risk_rationale"):
            out += [f"**Inherent risk:** {ai.get('inherent_risk', '').title()} - {ai['risk_rationale']}", ""]
    if ai.get("key_risks"):
        out += ["## Key risks", ""]
        for k in ai["key_risks"]:
            out.append(f"- **{k['title']}** - {k['description']} _({', '.join(k.get('csf', []))})_")
        out.append("")
    if r.get("decision_notes"):
        out += ["## Decision & conditions", "", r["decision_notes"], ""]
    if gaps:
        out += ["## Gaps requiring remediation", "", "| Requirement | Status | Notes |", "|---|---|---|"]
        for g in gaps:
            out.append(f"| **{g['subcategory_id']}** {_esc(g['subcategory']['text'])} | {REQ_LABEL[g['status']]} | "
                       f"{_esc(g['notes'] or g['answer'])} |")
        out.append("")

    if not reqs:
        out += [f"## Requirements (NIST CSF {cat.meta['csf_version']})", ""]
    current_fw = current_fn = None
    for x in reqs:
        s = x["subcategory"]
        src = cat.subcategories.get(x["subcategory_id"], {})
        fid = framework_of(cat, x["subcategory_id"])
        if fid != current_fw:
            current_fw = fid
            fw = framework_meta(cat, fid) or {"name": "NIST CSF", "version": cat.meta["csf_version"]}
            out += [f"## Requirements ({fw['name']} {fw['version']})", ""]
        if s["function_id"] != current_fn:
            current_fn = s["function_id"]
            out += [f"### {s['function_title']} ({s['function_id']})", ""]
        title = src.get("title", s["id"])
        refs = f"**800-53:** {', '.join(c['id'] for c in s['controls']) or '-'}"
        if src.get("cwe"):
            refs += f" · **CWE:** {', '.join(src['cwe'])}"
        out += [
            f"#### {s['id']} - {s['text'] if title == s['id'] else title}",
            *([s["text"], ""] if title != s["id"] else []),
            f"**Status:** {REQ_LABEL.get(x['status'], x['status'])} · **Priority:** {x['priority'].title()} · {refs}",
            "",
            f"> **Q:** {s['question']}",
            "",
        ]
        if x["rationale"]:
            out += [f"_Why in scope:_ {x['rationale']}", ""]
        if x["answer"]:
            out += ["**Response:**", "", x["answer"], ""]
        if x["notes"]:
            out += ["**Reviewer notes:**", "", x["notes"], ""]

    states = r.get("check_states") or {}
    flagged = [s for s in states.values() if s["status"] in ("fail", "exception", "pass")]
    if flagged:
        out += ["## Checkov technical controls", "", "| Check | Name | Status | Note |", "|---|---|---|---|"]
        order = {"fail": 0, "exception": 1, "pass": 2}
        for s in sorted(flagged, key=lambda s: (order[s["status"]], s["check_id"])):
            chk = cat.checks_by_id.get(s["check_id"], {})
            out.append(f"| `{s['check_id']}` | {_esc(chk.get('name', ''))} | {s['status'].upper()} | {_esc(s['note'])} |")
        out.append("")
    if ai.get("clarifying_questions"):
        out += ["## Additional questions raised", ""] + [f"- {q}" for q in ai["clarifying_questions"]] + [""]
    try:
        with db.tx() as conn:
            for tm in r.get("linked_threat_models") or []:
                out += report_section(get_artifacts(conn, tm["id"]), f"{tm['ref']}: {tm['title']}")
    except sqlite3.OperationalError:  # threat-model table not created yet
        pass
    out += ["## Activity", ""] + [f"- `{a['ts']}` **{a['action']}** {a['detail']}" for a in r.get("activity", [])]
    return "\n".join(out) + "\n"
