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


def attack_tree_mermaid(data: dict) -> str:
    nodes = data.get("nodes") or []
    known = {n["id"] for n in nodes}
    lines = ["flowchart TD"]
    leaves = []
    for n in nodes:
        text = n["label"] + (f" [{', '.join(n['threat_ids'])}]" if n.get("threat_ids") else "")
        mid, t = _nid(n["id"]), n["type"]
        if t == "goal":
            lines.append(f'    {mid}(["{label(text)}"])')
        elif t == "and":
            lines.append(f'    {mid}{{{{"AND: {label(text)}"}}}}')
        elif t == "or":
            lines.append(f'    {mid}["OR: {label(text)}"]')
        else:
            lines.append(f'    {mid}("{label(text)}")')
            leaves.append(mid)
    for n in nodes:
        for c in n.get("children") or []:
            if c in known:
                lines.append(f"    {_nid(n['id'])} --> {_nid(c)}")
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
