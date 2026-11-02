"""Validation and normalisation of every threat-model artifact (AI output and manual edits alike).

Ids are made unique and sequential, enums are coerced, cross-references (threat ids, node ids) are checked
and anything invalid is dropped. Diagrams are regenerated from the cleaned data; scores are computed here.
"""
from __future__ import annotations

import re

from ..catalog import Catalog, base_control, get_catalog
from ..library import mitigation_library
from ..profile import similarity
from .mermaid import attack_tree_mermaid, dfd_mermaid, safe_id
from .references import allowed_ids, clean_code, clean_codes, select_cards

CATEGORIES = ("Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
              "Elevation of Privilege")
CATEGORY_ALIASES = {
    "s": "Spoofing", "spoof": "Spoofing", "t": "Tampering", "r": "Repudiation", "i": "Information Disclosure",
    "info disclosure": "Information Disclosure", "disclosure": "Information Disclosure", "d": "Denial of Service",
    "dos": "Denial of Service", "ddos": "Denial of Service", "e": "Elevation of Privilege",
    "eop": "Elevation of Privilege", "privilege escalation": "Elevation of Privilege",
    "elevation of privileges": "Elevation of Privilege",
}
LIKELIHOOD_HINTS = ("low", "medium", "high")
PRIORITIES = ("high", "medium", "low")
NODE_TYPES = ("goal", "and", "or", "leaf")
DFD_TYPES = {
    "external_entity": "external_entity", "external": "external_entity", "entity": "external_entity",
    "actor": "external_entity", "user": "external_entity", "interactor": "external_entity",
    "data_store": "data_store", "datastore": "data_store", "store": "data_store", "database": "data_store",
    "db": "data_store", "storage": "data_store", "queue": "data_store", "cache": "data_store",
}
DREAD_KEYS = ("damage", "reproducibility", "exploitability", "affected_users", "discoverability")
DREAD_ALIASES = {"damage": ("damage_potential", "Damage Potential", "Damage"),
                 "reproducibility": ("Reproducibility",), "exploitability": ("Exploitability",),
                 "affected_users": ("Affected Users", "affected"), "discoverability": ("Discoverability",)}


# --------------------------------------------------------------------------- helpers
def _s(v, n: int = 500) -> str:
    return str(v).strip()[:n] if isinstance(v, (str, int, float)) and not isinstance(v, bool) else ""


def _strs(v, n: int = 20, ln: int = 400) -> list[str]:
    if not isinstance(v, list):
        return []
    return [s for s in (_s(x, ln) for x in v) if s][:n]


def _list(v) -> list:
    return v if isinstance(v, list) else []


def _link(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else None


def _category(v) -> str | None:
    s = " ".join(re.sub(r"[^a-z ]", " ", str(v or "").lower()).split())
    for c in CATEGORIES:
        if c.lower() in s:
            return c
    return CATEGORY_ALIASES.get(s)


def _assign_ids(entries: list[dict], prefix: str) -> None:
    """Keep valid, unique '<prefix><n>' ids; give the rest the next free number."""
    pat = re.compile(rf"^{prefix}(\d+)$")
    used: set[str] = set()
    pending = []
    for e in entries:
        rid = str(e.get("id") or "").strip().upper()
        if pat.match(rid) and rid not in used:
            e["id"] = rid
            used.add(rid)
        else:
            pending.append(e)
    n = max([int(pat.match(u).group(1)) for u in used] or [0])
    for e in pending:
        n += 1
        e["id"] = f"{prefix}{n}"


def _ref_ids(values, valid: set[str]) -> list[str]:
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    for v in values if isinstance(values, list) else []:
        x = str(v).strip().upper()
        if x in valid and x not in out:
            out.append(x)
    return out


def _carry_links(entries: list[dict], prior: list[dict], key: str, by_id: bool, keep_links: bool) -> None:
    """Keep promotion links (item_id / mitigation_id) when an entry is still the same threat / control.

    Refine (by_id): ids are stable, match on id. Manual edit (keep_links): explicit links win, otherwise match
    on id only if the title still resembles the original. Fresh generation: match on title similarity.
    """
    used = {e[key] for e in entries if e.get(key)}
    free = {p["id"]: p for p in prior if p.get(key) and p.get("id") and p[key] not in used}

    def sim(p: dict, e: dict) -> float:
        return similarity(p.get("title", ""), e["title"])

    for e in entries:
        if e.get(key) or not free:
            continue
        p = free.get(e["id"]) if (by_id or keep_links) else None
        if p is not None and keep_links and sim(p, e) < 0.5:
            p = None
        if p is None and not by_id:
            p = max(free.values(), key=lambda x: sim(x, e))
            p = p if sim(p, e) >= 0.6 else None
        if p is not None:
            e[key] = p[key]
            del free[p["id"]]


# --------------------------------------------------------------------------- threat model
def _evidence_refs(v, known: set[str] | None) -> list[str]:
    """Code references ("path/file.py:42"). With ``known`` (the linked files) only existing files are kept, so a
    model cannot cite code that is not there; ``None`` keeps reviewer-edited values unchanged."""
    out = []
    for ref in _strs(v, 8, 200):
        path = re.sub(r":\d+(-\d+)?$", "", ref.strip())
        if known is None or path in known:
            out.append(ref)
    return out


def normalize_threat_model(raw: dict, *, app_type: str, cards: list[str], csf_ids: set[str],
                           prior: dict | None = None, by_id: bool = False, keep_links: bool = False,
                           known_files: set[str] | None = None) -> dict:
    allowed = allowed_ids(cards)
    threats, seen = [], set()
    for t in _list(raw.get("threats")):
        if not isinstance(t, dict):
            continue
        cat = _category(t.get("category") or t.get("threat_type"))
        scenario = _s(t.get("scenario"), 2000)
        title = _s(t.get("title"), 200) or scenario[:120]
        if not cat or not title or (cat, title.lower()) in seen:
            continue
        seen.add((cat, title.lower()))
        lk = str(t.get("likelihood_hint") or "medium").lower()
        threats.append({
            "id": _s(t.get("id"), 20), "category": cat, "title": title, "component": _s(t.get("component"), 200),
            "scenario": scenario or title, "impact": _s(t.get("impact"), 1500),
            "likelihood_hint": lk if lk in LIKELIHOOD_HINTS else "medium",
            **{f: clean_code(f, t.get(f), allowed) for f in ("owasp_top10", "owasp_llm", "owasp_asi")},
            **{f: clean_codes(f, t.get(f), allowed) for f in ("mitre_attack", "mitre_atlas")},
            "csf": _ref_ids(t.get("csf"), csf_ids)[:5],
            "evidence": _evidence_refs(t.get("evidence"), known_files),
            "item_id": _link(t.get("item_id")) if keep_links else None,
        })
    _assign_ids(threats, "T")
    _carry_links(threats, (prior or {}).get("threats") or [], "item_id", by_id, keep_links)
    out = {
        "summary": _s(raw.get("summary"), 3000), "app_type": app_type,
        "assumptions": _strs(raw.get("assumptions"), 20, 500),
        "improvement_suggestions": _strs(raw.get("improvement_suggestions"), 20, 500),
        "threats": threats[:80],
    }
    if keep_links and (prior or {}).get("inputs"):  # reviewer edit: keep the record of what the run was based on
        out["inputs"] = prior["inputs"]
    return out


# --------------------------------------------------------------------------- attack tree
def _flatten_tree(nodes) -> list[dict]:
    """Accept flat nodes with child ids and/or nested child objects; return records with raw child refs."""
    out: list[dict] = []

    def walk(n, depth: int) -> str | None:
        if not isinstance(n, dict) or depth > 12 or len(out) >= 150:
            return None
        rec = {"raw": str(n.get("id") or f"_auto{len(out) + 1}"), "node": n, "children": []}
        out.append(rec)
        for c in _list(n.get("children")):
            cid = walk(c, depth + 1) if isinstance(c, dict) else _s(c, 60)
            if cid:
                rec["children"].append(cid)
        return rec["raw"]

    for n in nodes if isinstance(nodes, list) else []:
        walk(n, 0)
    return out


def normalize_attack_tree(raw: dict, threat_ids: set[str]) -> dict:
    flat = _flatten_tree(raw.get("nodes"))
    idmap: dict[str, str] = {}
    records = []
    for rec in flat:
        if rec["raw"] in idmap:
            continue
        nid = safe_id(rec["raw"], f"n{len(idmap) + 1}")
        while nid in idmap.values():
            nid = f"{nid}_{len(idmap) + 1}"
        idmap[rec["raw"]] = nid
        records.append(rec)
    nodes = []
    for rec in records:
        n = rec["node"]
        lbl = _s(n.get("label") or n.get("name"), 200)
        if not lbl:
            continue
        nid = idmap[rec["raw"]]
        children = list(dict.fromkeys(idmap[c] for c in rec["children"] if c in idmap and idmap[c] != nid))
        nodes.append({"id": nid, "label": lbl, "type": str(n.get("type") or "").lower(), "children": children,
                      "threat_ids": _ref_ids(n.get("threat_ids"), threat_ids)})
    by_id = {n["id"]: n for n in nodes}
    for n in nodes:
        n["children"] = [c for c in n["children"] if c in by_id]
    state: dict[str, int] = {}

    def dfs(nid: str) -> None:  # drop back-edges so the tree is acyclic
        state[nid] = 1
        keep = []
        for c in by_id[nid]["children"]:
            if state.get(c) == 1:
                continue
            if c not in state:
                dfs(c)
            keep.append(c)
        by_id[nid]["children"] = keep
        state[nid] = 2

    children_of = {c for n in nodes for c in n["children"]}
    for n in sorted(nodes, key=lambda x: x["id"] in children_of):
        if n["id"] not in state:
            dfs(n["id"])
    children_of = {c for n in nodes for c in n["children"]}
    goals = [n for n in nodes if n["type"] == "goal" and n["id"] not in children_of]
    for n in nodes:
        if n["type"] == "goal" and n is not (goals[0] if goals else None):
            n["type"] = ""
    if not goals:
        roots = [n for n in nodes if n["id"] not in children_of]
        if roots:
            roots[0]["type"] = "goal"
    for n in nodes:
        if n["type"] != "goal":
            n["type"] = ("and" if n["type"] == "and" else "or") if n["children"] else "leaf"
    goal = _s(raw.get("goal"), 300) or next((n["label"] for n in nodes if n["type"] == "goal"), "")
    data = {"goal": goal, "nodes": nodes}
    data["mermaid"] = attack_tree_mermaid(data)
    return data


# --------------------------------------------------------------------------- data flow diagram
def normalize_dfd(raw: dict) -> dict:
    nodes, ref = [], {}
    for n in _list(raw.get("nodes")):
        if not isinstance(n, dict) or len(nodes) >= 120:
            continue
        lbl = _s(n.get("label") or n.get("name") or n.get("id"), 120)
        if not lbl:
            continue
        nid = safe_id(n.get("id") or lbl, f"n{len(nodes) + 1}")
        while any(x["id"] == nid for x in nodes):
            nid = f"{nid}_{len(nodes) + 1}"
        raw_id = str(n.get("id") or "")
        if raw_id:
            ref.setdefault(raw_id, nid)
        ref.setdefault(nid, nid)
        ref.setdefault(lbl.lower(), nid)
        typ = DFD_TYPES.get(str(n.get("type") or "").lower().replace(" ", "_"), "process")
        nodes.append({"id": nid, "label": lbl, "type": typ})

    def resolve(v) -> str | None:
        key = str(v or "")
        return ref.get(key) or ref.get(key.lower()) or ref.get(safe_id(key, ""))

    edges, seen = [], set()
    for e in _list(raw.get("edges")):
        if not isinstance(e, dict):
            continue
        src, dst = resolve(e.get("from") or e.get("source")), resolve(e.get("to") or e.get("target"))
        lbl = _s(e.get("label"), 160)
        if not src or not dst or src == dst or (src, dst, lbl.lower()) in seen:
            continue
        seen.add((src, dst, lbl.lower()))
        edges.append({"from": src, "to": dst, "label": lbl, "protocol": _s(e.get("protocol"), 40)})
    boundaries, placed = [], set()
    for i, b in enumerate(_list(raw.get("trust_boundaries")), 1):
        if not isinstance(b, dict):
            continue
        name = _s(b.get("name") or b.get("label"), 120) or f"Trust boundary {i}"
        members = []
        for x in _list(b.get("node_ids") or b.get("nodes")):
            nid = resolve(x)
            if nid and nid not in placed:
                members.append(nid)
                placed.add(nid)
        bid = safe_id(b.get("id") or name, f"tb{i}")
        while any(x["id"] == bid for x in boundaries):
            bid = f"{bid}_{i}"
        boundaries.append({"id": bid, "name": name, "node_ids": members})
    data = {"nodes": nodes, "edges": edges[:300], "trust_boundaries": boundaries[:30]}
    data["mermaid"] = dfd_mermaid(data)
    return data


# --------------------------------------------------------------------------- mitigations
def _kw_hit(word: str, text: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(word.lower())}(?![a-z0-9])", text) is not None


def _nist(values, cat: Catalog) -> list[str]:
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    for v in _list(values):
        c = re.sub(r"\s+", "", str(v).upper())
        if (c in cat.controls or base_control(c) in cat.controls) and c not in out:
            out.append(c)
    return out[:8]


def match_library(title: str, description: str, nist: list[str], lib: dict, register: list[dict]) -> str | None:
    """Deterministic library match for a generated control, preferring one already in the review's register."""
    for m in register:
        if m.get("library_ref") in lib and similarity(m.get("title", ""), title) >= 0.5:
            return m["library_ref"]
    text = f"{title} {description}".lower()
    bases = {base_control(c) for c in nist}
    best, best_score = None, 0.0
    for lid, m in lib.items():
        score = (2 * len(bases & {base_control(c) for c in m["nist"]})
                 + sum(1 for k in m["keywords"] if _kw_hit(str(k), text)) + 4 * similarity(title, m["title"]))
        if score > best_score:
            best, best_score = lid, score
    return best if best_score >= 3 else None


def normalize_mitigations(raw: dict, *, threat_ids: set[str], cat: Catalog, lib: dict, register: list[dict],
                          prior: dict | None = None, by_id: bool = False, keep_links: bool = False) -> dict:
    out = []
    for m in _list(raw.get("mitigations")):
        if not isinstance(m, dict):
            continue
        tids = _ref_ids(m.get("threat_ids"), threat_ids)
        title = _s(m.get("title"), 300)
        if not tids or not title:
            continue
        desc = _s(m.get("description"), 2000)
        nist = _nist(m.get("nist"), cat)
        ref = _s(m.get("library_ref"), 60)
        if ref not in lib:
            ref = ref.upper() if ref.upper() in lib else match_library(title, desc, nist, lib, register)
        if ref and not nist:
            nist = list(lib[ref]["nist"])[:8]
        prio = str(m.get("priority") or "medium").lower()
        out.append({"id": _s(m.get("id"), 20), "threat_ids": tids, "title": title, "description": desc,
                    "nist": nist, "library_ref": ref, "priority": prio if prio in PRIORITIES else "medium",
                    "mitigation_id": _link(m.get("mitigation_id")) if keep_links else None})
    _assign_ids(out, "M")
    _carry_links(out, (prior or {}).get("mitigations") or [], "mitigation_id", by_id, keep_links)
    return {"mitigations": out[:100]}


# --------------------------------------------------------------------------- DREAD
def _score(v) -> int | None:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return int(round(min(max(x, 0.0), 10.0)))


def dread_rating(score: float) -> str:
    return "critical" if score >= 8 else "high" if score >= 6 else "medium" if score >= 4 else "low"


def _tnum(tid: str) -> int:
    return int(tid[1:]) if tid[1:].isdigit() else 0


def normalize_dread(raw: dict, threat_ids: set[str]) -> dict:
    out, seen = [], set()
    for a in _list(raw.get("assessments")):
        if not isinstance(a, dict):
            continue
        tid = str(a.get("threat_id") or "").strip().upper()
        if tid not in threat_ids or tid in seen:
            continue
        scores = {}
        for k in DREAD_KEYS:
            v = a.get(k)
            for alias in DREAD_ALIASES[k]:
                v = a.get(alias) if v is None else v
            scores[k] = _score(v)
        if any(v is None for v in scores.values()):
            continue
        seen.add(tid)
        score = round(sum(scores.values()) / len(DREAD_KEYS), 1)
        out.append({"threat_id": tid, **scores, "score": score, "rating": dread_rating(score),
                    "rationale": _s(a.get("rationale"), 1000)})
    out.sort(key=lambda a: _tnum(a["threat_id"]))
    return {"assessments": out}


# --------------------------------------------------------------------------- test cases
def normalize_test_cases(raw: dict, threat_ids: set[str]) -> dict:
    out = []
    for c in _list(raw.get("test_cases")):
        if not isinstance(c, dict):
            continue
        tid = str(c.get("threat_id") or "").strip().upper()
        g = c.get("gherkin") if isinstance(c.get("gherkin"), str) else ""
        g = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", g.strip())
        if tid not in threat_ids or "scenario" not in g.lower():
            continue
        m = re.search(r"Scenario(?: Outline)?:\s*(.+)", g)
        title = _s(c.get("title"), 200) or (m.group(1).strip()[:200] if m else tid)
        if not re.match(r"(@\S+\s+)*Feature:", g):
            g = f"Feature: {title}\n\n" + "\n".join(f"  {ln}" if ln.strip() else ln for ln in g.splitlines())
        out.append({"id": _s(c.get("id"), 20), "threat_id": tid, "title": title, "gherkin": g[:6000]})
    _assign_ids(out, "TC")
    return {"test_cases": out[:150]}


# --------------------------------------------------------------------------- manual edits
def normalize_artifact(kind: str, data: dict, *, app_type: str, prior: dict, register: list[dict]) -> dict:
    """Validate a reviewer-edited artifact. Promotion links sent back by the editor are kept."""
    tm = (prior.get("threat_model") or {}).get("data") or {}
    threat_ids = {t["id"] for t in tm.get("threats") or []}
    if kind == "threat_model":
        return normalize_threat_model(data, app_type=app_type, cards=select_cards(app_type),
                                      csf_ids=set(get_catalog().subcategories), prior=tm, keep_links=True)
    if kind == "attack_tree":
        return normalize_attack_tree(data, threat_ids)
    if kind == "dfd":
        return normalize_dfd(data)
    if kind == "mitigations":
        return normalize_mitigations(data, threat_ids=threat_ids, cat=get_catalog(), lib=mitigation_library(),
                                     register=register, prior=(prior.get("mitigations") or {}).get("data"),
                                     keep_links=True)
    if kind == "dread":
        return normalize_dread(data, threat_ids)
    return normalize_test_cases(data, threat_ids)
