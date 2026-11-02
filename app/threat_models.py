"""Threat models: standalone records (``reviews.kind = 'threat_model'``) that own linked code, a code review,
documents and the six threat-model artifacts. Security reviews link to them (many-to-many) and promote their
threats, mitigations and code findings into the review's own risk and control registers."""
from __future__ import annotations

import json
import sqlite3

from . import db
from .profile import similarity
from .threat import store

SCHEMA = """
CREATE TABLE IF NOT EXISTS review_threat_models (
    review_id       INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    threat_model_id INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    links           TEXT NOT NULL DEFAULT '{}',   -- promotions into this review: threats / mitigations / findings
    linked_at       TEXT NOT NULL,
    PRIMARY KEY (review_id, threat_model_id)
);
"""

COPY_COLUMNS = ("title", "description", "change_type", "tech_stack", "business_unit", "data_classification",
                "internet_facing", "personal_data", "third_party", "uses_ai", "technologies", "services", "exposure",
                "data_types", "interacts_with", "system_types", "design", "code_review")


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def _json(v, empty):
    try:
        return json.loads(v) if isinstance(v, str) and v else empty
    except json.JSONDecodeError:
        return empty


def get_links(conn: sqlite3.Connection, review_id: int, tm_id: int) -> dict | None:
    row = conn.execute("SELECT links FROM review_threat_models WHERE review_id = ? AND threat_model_id = ?",
                       (review_id, tm_id)).fetchone()
    if row is None:
        return None
    links = _json(row["links"], {})
    for k in ("threats", "mitigations", "findings"):
        links.setdefault(k, {})
    return links


def save_links(conn: sqlite3.Connection, review_id: int, tm_id: int, links: dict) -> None:
    conn.execute("UPDATE review_threat_models SET links = ? WHERE review_id = ? AND threat_model_id = ?",
                 (json.dumps(links), review_id, tm_id))


def linked_ids(conn: sqlite3.Connection, review_id: int) -> list[int]:
    return [r[0] for r in conn.execute("SELECT threat_model_id FROM review_threat_models WHERE review_id = ? "
                                       "ORDER BY linked_at, threat_model_id", (review_id,))]


def linking_reviews(conn: sqlite3.Connection, tm_id: int) -> list[int]:
    return [r[0] for r in conn.execute("SELECT review_id FROM review_threat_models WHERE threat_model_id = ?",
                                       (tm_id,))]


def overlay(entries: list[dict], links: dict, key: str, valid: set[int]) -> None:
    """Set ``key`` (item_id / mitigation_id) on each entry from this review's promotion links. Matches on id while
    the title still resembles the promoted one, then on title similarity, so regenerated ids do not mislink."""
    for e in entries:
        e[key] = None
    used: set[int] = set()
    for e in entries:
        ln = links.get(str(e.get("id")))
        if ln and ln.get(key) in valid and similarity(ln.get("title", ""), e.get("title", "")) >= 0.5:
            e[key] = ln[key]
            used.add(ln[key])
    free = [ln for ln in links.values() if ln.get(key) in valid and ln[key] not in used]
    for e in entries:
        if e[key] or not free:
            continue
        best = max(free, key=lambda ln: similarity(ln.get("title", ""), e.get("title", "")))
        if similarity(best.get("title", ""), e.get("title", "")) >= 0.6:
            e[key] = best[key]
            free.remove(best)


def apply_checkov(conn: sqlite3.Connection, review_id: int, code_review: dict, checks_by_id: dict) -> None:
    """Real Checkov results update the review's per-check status, unless a reviewer already set it."""
    ck = (code_review or {}).get("checkov") or {}
    ts = db.now()
    for status, ids in (("pass", ck.get("passed_ids", [])), ("fail", ck.get("failed_ids", []))):
        for cid in ids:
            if cid not in checks_by_id:
                continue
            conn.execute(
                """INSERT INTO review_checks (review_id, check_id, status, note, updated_at)
                   VALUES (?, ?, ?, 'Checkov scan of the linked threat model code', ?)
                   ON CONFLICT(review_id, check_id) DO UPDATE SET status = excluded.status,
                     note = excluded.note, updated_at = excluded.updated_at
                   WHERE review_checks.status = 'applicable'""", (review_id, cid, status, ts))


def merged_code_review(tms: list[dict]) -> dict:
    """One code-review view over every linked threat model, for the review's scoping and risk suggestions."""
    reviewed = [t["code_review"] for t in tms if (t.get("code_review") or {}).get("ran_at")]
    if not reviewed:
        return {}
    out = dict(reviewed[0])
    if len(reviewed) > 1:
        out["summary"] = "\n\n".join(c.get("summary") or "" for c in reviewed).strip()
        out["findings"] = [f for c in reviewed for f in c.get("findings") or []]
        out["system_types"] = list(dict.fromkeys(s for c in reviewed for s in c.get("system_types") or []))
        out["data_types"] = list(dict.fromkeys(s for c in reviewed for s in c.get("data_types") or []))
    return out


def migrate(conn: sqlite3.Connection) -> None:
    """Once: move each review's own code, code review and threat artifacts into a new linked threat model."""
    if conn.execute("SELECT 1 FROM settings WHERE key = 'migrated_threat_models_v1'").fetchone():
        return
    rows = conn.execute(
        """SELECT * FROM reviews r WHERE r.kind = 'review' AND (
             EXISTS (SELECT 1 FROM threat_artifacts a WHERE a.review_id = r.id)
             OR EXISTS (SELECT 1 FROM documents d WHERE d.review_id = r.id AND d.kind = 'code')
             OR (r.code_review NOT IN ('', '{}')))""").fetchall()
    for r in rows:
        ts = db.now()
        cols = [c for c in COPY_COLUMNS if c in r.keys()]
        tm_id = conn.execute(
            f"INSERT INTO reviews ({', '.join(cols)}, kind, created_at, updated_at) "
            f"VALUES ({', '.join('?' * len(cols))}, 'threat_model', ?, ?)", [r[c] for c in cols] + [ts, ts]).lastrowid
        conn.execute("UPDATE documents SET review_id = ? WHERE review_id = ? AND kind = 'code'", (tm_id, r["id"]))
        conn.execute("UPDATE threat_artifacts SET review_id = ? WHERE review_id = ?", (tm_id, r["id"]))
        links: dict = {"threats": {}, "mitigations": {}, "findings": {}}
        arts = store.get_artifacts(conn, tm_id)
        for kind, key, ref in (("threat_model", "threats", "item_id"), ("mitigations", "mitigations", "mitigation_id")):
            data = (arts.get(kind) or {}).get("data") or {}
            for e in data.get(key) or []:
                if e.get(ref):
                    links[key][str(e["id"])] = {ref: e[ref], "title": e.get("title", "")}
                e[ref] = None
            if arts.get(kind):
                store.update_data(conn, tm_id, kind, data)
        code = _json(r["code_review"], {})
        for f in code.get("findings") or []:
            if f.get("item_id"):
                links["findings"][str(f["id"])] = f.pop("item_id")
        conn.execute("UPDATE reviews SET code_review = ? WHERE id = ?", (json.dumps(code), tm_id))
        conn.execute("UPDATE reviews SET code_review = '{}' WHERE id = ?", (r["id"],))
        conn.execute("INSERT INTO review_threat_models (review_id, threat_model_id, links, linked_at) "
                     "VALUES (?, ?, ?, ?)", (r["id"], tm_id, json.dumps(links), ts))
        db.log_activity(conn, tm_id, "created", f"Threat model moved out of review SR-{r['id']:04d}")
        db.log_activity(conn, r["id"], "threat", f"Code and threat model moved to linked threat model TM-{tm_id:04d}")
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('migrated_threat_models_v1', '1')")
