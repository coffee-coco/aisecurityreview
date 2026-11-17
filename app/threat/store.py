"""Persistence for threat-model artifacts: one JSON document per (review, kind)."""
from __future__ import annotations

import json

from .. import db
from . import KINDS


def _row(row: dict) -> dict:
    try:
        data = json.loads(row["data"] or "{}")
    except json.JSONDecodeError:
        data = {}
    return {"data": data, "source": row["source"], "model": row["model"], "updated_at": row["updated_at"]}


def get_artifact(conn: db.Connection, review_id: int, kind: str) -> dict | None:
    row = conn.execute("SELECT * FROM threat_artifacts WHERE review_id = %s AND kind = %s", (review_id, kind)).fetchone()
    return _row(row) if row else None


def get_artifacts(conn: db.Connection, review_id: int) -> dict[str, dict | None]:
    out: dict[str, dict | None] = {k: None for k in KINDS}
    for row in conn.execute("SELECT * FROM threat_artifacts WHERE review_id = %s", (review_id,)):
        if row["kind"] in out:
            out[row["kind"]] = _row(row)
    return out


def put_artifact(conn: db.Connection, review_id: int, kind: str, data: dict, source: str, model: str) -> dict:
    ts = db.now()
    conn.execute(
        """INSERT INTO threat_artifacts (review_id, kind, data, source, model, updated_at)
           VALUES (%s, %s, %s, %s, %s, %s)
           ON CONFLICT(review_id, kind) DO UPDATE SET data = excluded.data, source = excluded.source,
             model = excluded.model, updated_at = excluded.updated_at""",
        (review_id, kind, json.dumps(data), source, model, ts))
    db.touch(conn, review_id)
    return {"data": data, "source": source, "model": model, "updated_at": ts}


def update_data(conn: db.Connection, review_id: int, kind: str, data: dict) -> None:
    """Rewrite the data of an existing artifact without changing its provenance (e.g. promotion links)."""
    conn.execute("UPDATE threat_artifacts SET data = %s WHERE review_id = %s AND kind = %s",
                 (json.dumps(data), review_id, kind))


def delete_artifact(conn: db.Connection, review_id: int, kind: str) -> None:
    conn.execute("DELETE FROM threat_artifacts WHERE review_id = %s AND kind = %s", (review_id, kind))
    db.touch(conn, review_id)
