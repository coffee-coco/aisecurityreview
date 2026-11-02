"""Line items (questions / risks / recommendations) and the mitigating-control register."""
from __future__ import annotations

import json
import sqlite3

from . import db
from .catalog import Catalog, base_control
from .library import mitigation_library
from .profile import item_answered, risk_rating

ITEM_KINDS = ("question", "risk", "recommendation")
ITEM_TEXT_FIELDS = ("title", "answer", "notes", "rationale", "risk", "impact_description", "recommendation")
ITEM_FIELDS = ITEM_TEXT_FIELDS + ("status", "priority", "is_risk", "is_recommendation", "likelihood", "impact",
                                  "treatment", "rec_status", "kind")
MIT_FIELDS = ("title", "description", "state", "status", "owner", "due_date", "nist")
KIND_PREFIX = {"question": "Q", "risk": "R", "recommendation": "REC"}


def _links(conn: sqlite3.Connection, review_id: int) -> list[tuple[int, int]]:
    return [(r[0], r[1]) for r in conn.execute(
        "SELECT im.item_id, im.mitigation_id FROM item_mitigations im JOIN items x ON x.id = im.item_id "
        "WHERE x.review_id = ?", (review_id,))]


def serialize_item(row: dict, cat: Catalog, mit_ids: list[int], label: str) -> dict:
    d = dict(row)
    for b in db.ITEM_BOOLS:
        d[b] = bool(d.get(b))
    if d["kind"] == "risk":
        d["is_risk"] = True
    if d["kind"] == "recommendation":
        d["is_recommendation"] = True
    d["label"] = label
    d["mitigation_ids"] = mit_ids
    d["answered"] = item_answered(d, bool(mit_ids))
    d["risk_rating"] = risk_rating(d["likelihood"], d["impact"]) if d["is_risk"] else ""
    sid = d.get("subcategory_id")
    d["subcategory"] = cat.subcategory_brief(sid) if sid and sid in cat.subcategories else None
    d["display_title"] = d["title"] or (d["subcategory"]["question"] if d["subcategory"] else "")
    return d


def load_items(conn: sqlite3.Connection, review_id: int, cat: Catalog) -> list[dict]:
    rows = [dict(r) for r in conn.execute("SELECT * FROM items WHERE review_id = ? ORDER BY id", (review_id,))]
    links: dict[int, list[int]] = {}
    for item_id, mid in _links(conn, review_id):
        links.setdefault(item_id, []).append(mid)
    counters = {k: 0 for k in ITEM_KINDS}
    out = []
    for r in rows:
        if r["subcategory_id"] and r["subcategory_id"] not in cat.subcategories:
            continue
        if r["subcategory_id"]:
            label = r["subcategory_id"]
        else:
            counters[r["kind"]] += 1
            label = f"{KIND_PREFIX[r['kind']]}-{counters[r['kind']]}"
        out.append(serialize_item(r, cat, sorted(links.get(r["id"], [])), label))
    # Custom rows first (in creation order), then NIST CSF questions in framework order.
    out.sort(key=lambda x: (1, cat.order.get(x["subcategory_id"], 9999), 0) if x["subcategory_id"]
             else (0, 0, x["id"]))
    return out


def serialize_mitigation(row: dict, item_ids: list[int]) -> dict:
    d = dict(row)
    try:
        d["nist"] = json.loads(d.get("nist") or "[]")
    except json.JSONDecodeError:
        d["nist"] = []
    d["item_ids"] = item_ids
    return d


def load_mitigations(conn: sqlite3.Connection, review_id: int) -> list[dict]:
    links: dict[int, list[int]] = {}
    for item_id, mid in _links(conn, review_id):
        links.setdefault(mid, []).append(item_id)
    rows = conn.execute("SELECT * FROM mitigations WHERE review_id = ? ORDER BY id", (review_id,))
    return [serialize_mitigation(dict(r), sorted(links.get(r["id"], []))) for r in rows]


def item_controls(item: dict, cat: Catalog) -> set[str]:
    """Base SP 800-53 controls an item relates to (CSF mapping, library risk or code finding)."""
    ctrls: set[str] = set()
    sid = item.get("subcategory_id")
    if sid and sid in cat.subcategories:
        ctrls |= set(cat.subcategories[sid]["controls"])
    ref = item.get("library_ref") or ""
    if ref.startswith("R-"):
        from .library import risk_library
        lib = mitigation_library()
        for r in risk_library():
            if r["id"] == ref:
                for mid in r.get("mitigations", []):
                    ctrls |= {base_control(c) for c in lib.get(mid, {}).get("nist", [])}
                for csf in r.get("csf", []):
                    if csf in cat.subcategories:
                        ctrls |= set(cat.subcategories[csf]["controls"][:4])
    return ctrls


def create_item(conn: sqlite3.Connection, review_id: int, data: dict) -> int:
    ts = db.now()
    data = {k: v for k, v in data.items() if k in ITEM_FIELDS + ("subcategory_id", "library_ref", "source")}
    kind = data.get("kind", "question")
    if kind == "risk":
        data["is_risk"] = 1
    if kind == "recommendation":
        data["is_recommendation"] = 1
    data = {k: int(v) if isinstance(v, bool) else v for k, v in data.items()}
    cols = list(data) + ["review_id", "created_at", "updated_at"]
    vals = list(data.values()) + [review_id, ts, ts]
    cur = conn.execute(f"INSERT INTO items ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", vals)
    db.touch(conn, review_id)
    return cur.lastrowid


def create_mitigation(conn: sqlite3.Connection, review_id: int, data: dict) -> int:
    ts = db.now()
    row = {
        "title": (data.get("title") or "").strip()[:300] or "Untitled control",
        "description": data.get("description") or "",
        "state": data.get("state") if data.get("state") in ("existing", "new") else "new",
        "status": data.get("status") or ("implemented" if data.get("state") == "existing" else "proposed"),
        "owner": data.get("owner") or "",
        "due_date": data.get("due_date") or "",
        "nist": json.dumps(list(data.get("nist") or [])),
        "library_ref": data.get("library_ref") or "",
        "source": data.get("source") or "manual",
    }
    cols = list(row) + ["review_id", "created_at", "updated_at"]
    cur = conn.execute(f"INSERT INTO mitigations ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                       list(row.values()) + [review_id, ts, ts])
    db.touch(conn, review_id)
    return cur.lastrowid


def mitigation_from_library(conn: sqlite3.Connection, review_id: int, lib_id: str, source: str = "library") -> int:
    """Reuse the register entry for a library control if it exists, otherwise create it."""
    row = conn.execute("SELECT id FROM mitigations WHERE review_id = ? AND library_ref = ?",
                       (review_id, lib_id)).fetchone()
    if row:
        return row["id"]
    m = mitigation_library()[lib_id]
    return create_mitigation(conn, review_id, {"title": m["title"], "description": m["description"],
                                               "nist": m["nist"], "library_ref": lib_id, "source": source})


def link(conn: sqlite3.Connection, item_id: int, mitigation_id: int) -> None:
    conn.execute("INSERT OR IGNORE INTO item_mitigations (item_id, mitigation_id) VALUES (?, ?)",
                 (item_id, mitigation_id))
