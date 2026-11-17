"""Mermaid rendering for attack trees and data flow diagrams.

Diagrams are always generated here from validated JSON; Mermaid written by a model is never used.
Labels are escaped with Mermaid entity codes and node ids are prefixed so reserved words (``end``,
``graph``...) and punctuation can never break the diagram.
"""
from __future__ import annotations

import re

ESCAPES = (("#", "#35;"), ('"', "#quot;"), ("<", "#lt;"), (">", "#gt;"), ("|", "#124;"), ("`", "'"))


def safe_id(value, fallback: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", str(value or "")).strip("_")[:40]
    return s or fallback


def label(text, limit: int = 120) -> str:
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(s) > limit:
        s = s[:limit - 1].rstrip() + "…"
    for raw, code in ESCAPES:
        s = s.replace(raw, code)
    return s


def _nid(node_id: str) -> str:
    return f"n_{node_id}"


TREE_CLASSES = {  # attack semantics: a proven attack is the danger, a blocked one is the good news
    "verified": "fill:#3b0d12,stroke:#f87171,stroke-width:3px,color:#fecaca",
    "unverified": "fill:#111627,stroke:#71717a,stroke-dasharray:5 4,color:#a1a1aa",
    "mitigated": "fill:#052e1a,stroke:#34d399,color:#bbf7d0",
}


def attack_tree_mermaid(data: dict, verified_only: bool = False) -> str:
    """Attack tree as a Mermaid flowchart. When nodes carry a verification ``status`` (``verify.annotate_tree``),
    proven attacks are drawn red with bold edges, hypothetical ones grey and dashed, blocked ones green, and proven
    leaves show the entry → sink of the code path. ``verified_only`` draws just the routes proven from the goal down
    to the code."""
    nodes = [n for n in data.get("nodes") or [] if not verified_only or n.get("proven_route")]
    if not nodes:
        return ""
    known = {n["id"] for n in nodes}
    lines = ["flowchart TD"]
    leaves = []
    for n in nodes:
        text = n["label"] + (f" [{', '.join(n['threat_ids'])}]" if n.get("threat_ids") else "")
        proof = (n.get("proof") or [None])[0]
        mid, t = _nid(n["id"]), n["type"]
        body = label(text) + (f"<br/>✓ {label(proof['entry'], 60)} → {label(proof['sink'], 60)}" if proof else "")
        if t == "goal":
            lines.append(f'    {mid}(["{body}"])')
        elif t == "and":
            lines.append(f'    {mid}{{{{"AND: {body}"}}}}')
        elif t == "or":
            lines.append(f'    {mid}["OR: {body}"]')
        else:
            lines.append(f'    {mid}("{body}")')
            leaves.append(mid)
    edges, styled = [], {"verified": [], "unverified": []}
    by_id = {n["id"]: n for n in nodes}
    for n in nodes:
        for c in n.get("children") or []:
            if c in known:
                if by_id[c].get("proven_route") and n.get("proven_route"):  # part of an attack proven end to end
                    styled["verified"].append(len(edges))
                elif by_id[c].get("status") == "unverified":
                    styled["unverified"].append(len(edges))
                edges.append(f"    {_nid(n['id'])} --> {_nid(c)}")
    lines += edges
    statuses = {s: [_nid(n["id"]) for n in nodes if n.get("status") == s] for s in TREE_CLASSES}
    if any(statuses.values()):
        for s, ids in statuses.items():
            if ids:
                lines += [f"    classDef {s} {TREE_CLASSES[s]};", f"    class {','.join(ids)} {s};"]
        if styled["verified"]:
            lines.append(f"    linkStyle {','.join(map(str, styled['verified']))} stroke:#f87171,stroke-width:3px;")
        if styled["unverified"]:
            lines.append(f"    linkStyle {','.join(map(str, styled['unverified']))} stroke:#71717a,stroke-dasharray:4 4;")
        return "\n".join(lines)
    goals = [_nid(n["id"]) for n in nodes if n["type"] == "goal"]
    if goals:
        lines += ["    classDef goal fill:#fde2e2,stroke:#b42318,stroke-width:2px;",
                  f"    class {','.join(goals)} goal;"]
    if leaves:
        lines += ["    classDef leaf fill:#f4f4f5,stroke:#71717a;", f"    class {','.join(leaves)} leaf;"]
    return "\n".join(lines)


def _dfd_node(n: dict) -> str:
    mid, text = _nid(n["id"]), label(n["label"])
    if n["type"] == "external_entity":
        return f'{mid}["{text}"]'
    if n["type"] == "data_store":
        return f'{mid}[("{text}")]'
    return f'{mid}(("{text}"))'


def dfd_mermaid(data: dict) -> str:
    nodes = {n["id"]: n for n in data.get("nodes") or []}
    lines = ["flowchart LR"]
    placed: set[str] = set()
    boundary_ids = []
    for b in data.get("trust_boundaries") or []:
        members = [nid for nid in b.get("node_ids") or [] if nid in nodes and nid not in placed]
        if not members:
            continue
        tb = f"tb_{b['id']}"
        boundary_ids.append(tb)
        lines.append(f'    subgraph {tb}["{label(b["name"])}"]')
        for nid in members:
            lines.append("        " + _dfd_node(nodes[nid]))
            placed.add(nid)
        lines.append("    end")
    for nid, n in nodes.items():
        if nid not in placed:
            lines.append("    " + _dfd_node(n))
    for e in data.get("edges") or []:
        if e["from"] not in nodes or e["to"] not in nodes:
            continue
        text = e.get("label") or ""
        if e.get("protocol"):
            text = f"{text} ({e['protocol']})" if text else e["protocol"]
        arrow = f'-->|"{label(text, 80)}"|' if text else "-->"
        lines.append(f"    {_nid(e['from'])} {arrow} {_nid(e['to'])}")
    if boundary_ids:
        lines.append("    classDef trustBoundary stroke-dasharray: 5 5,fill:transparent;")
        lines.append(f"    class {','.join(boundary_ids)} trustBoundary;")
    return "\n".join(lines)
