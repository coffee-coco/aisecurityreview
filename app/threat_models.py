"""Threat models: standalone records (``reviews.kind = 'threat_model'``) that own linked code, a code review,
documents and the six threat-model artifacts. Security reviews link to them (many-to-many) and promote their
threats, mitigations and code findings into the review's own risk and control registers."""
from __future__ import annotations

import json

from . import db
from .profile import similarity


def _json(v, empty):
    try:
        return json.loads(v) if isinstance(v, str) and v else empty
    except json.JSONDecodeError:
        return empty


def get_links(conn: db.Connection, review_id: int, tm_id: int) -> dict | None:
    row = conn.execute("SELECT links FROM review_threat_models WHERE review_id = %s AND threat_model_id = %s",
                       (review_id, tm_id)).fetchone()
    if row is None:
        return None
    links = _json(row["links"], {})
    for k in ("threats", "mitigations", "findings"):
        links.setdefault(k, {})
    return links


def save_links(conn: db.Connection, review_id: int, tm_id: int, links: dict) -> None:
    conn.execute("UPDATE review_threat_models SET links = %s WHERE review_id = %s AND threat_model_id = %s",
                 (json.dumps(links), review_id, tm_id))


def linked_ids(conn: db.Connection, review_id: int) -> list[int]:
    return [r[0] for r in conn.execute("SELECT threat_model_id FROM review_threat_models WHERE review_id = %s "
                                       "ORDER BY linked_at, threat_model_id", (review_id,))]


def linking_reviews(conn: db.Connection, tm_id: int) -> list[int]:
    return [r[0] for r in conn.execute("SELECT review_id FROM review_threat_models WHERE threat_model_id = %s",
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


def apply_checkov(conn: db.Connection, review_id: int, code_review: dict, checks_by_id: dict) -> None:
    """Real Checkov results update the review's per-check status, unless a reviewer already set it."""
    ck = (code_review or {}).get("checkov") or {}
    ts = db.now()
    for status, ids in (("pass", ck.get("passed_ids", [])), ("fail", ck.get("failed_ids", []))):
        for cid in ids:
            if cid not in checks_by_id:
                continue
            conn.execute(
                """INSERT INTO review_checks (review_id, check_id, status, note, updated_at)
                   VALUES (%s, %s, %s, 'Checkov scan of the linked threat model code', %s)
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
