"""Persistence for threat-model artifacts: one JSON document per (review, kind)."""
from __future__ import annotations

import json
import sqlite3

from .. import db
from . import KINDS

SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_artifacts (
    review_id  INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,                 -- threat_model | attack_tree | dfd | mitigations | dread | test_cases
    data       TEXT NOT NULL DEFAULT '{}',
    source     TEXT NOT NULL DEFAULT 'ai',    -- ai | manual
    model      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (review_id, kind)
);
"""


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def _row(row: sqlite3.Row) -> dict:
    try:
        data = json.loads(row["data"] or "{}")
    except json.JSONDecodeError:
        data = {}
    return {"data": data, "source": row["source"], "model": row["model"], "updated_at": row["updated_at"]}


def get_artifact(conn: sqlite3.Connection, review_id: int, kind: str) -> dict | None:
    row = conn.execute("SELECT * FROM threat_artifacts WHERE review_id = ? AND kind = ?", (review_id, kind)).fetchone()
    return _row(row) if row else None


def get_artifacts(conn: sqlite3.Connection, review_id: int) -> dict[str, dict | None]:
    out: dict[str, dict | None] = {k: None for k in KINDS}
    for row in conn.execute("SELECT * FROM threat_artifacts WHERE review_id = ?", (review_id,)):
        if row["kind"] in out:
            out[row["kind"]] = _row(row)
    return out


def put_artifact(conn: sqlite3.Connection, review_id: int, kind: str, data: dict, source: str, model: str) -> dict:
    ts = db.now()
    conn.execute(
        """INSERT INTO threat_artifacts (review_id, kind, data, source, model, updated_at) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(review_id, kind) DO UPDATE SET data = excluded.data, source = excluded.source,
             model = excluded.model, updated_at = excluded.updated_at""",
        (review_id, kind, json.dumps(data), source, model, ts))
    db.touch(conn, review_id)
    return {"data": data, "source": source, "model": model, "updated_at": ts}


def update_data(conn: sqlite3.Connection, review_id: int, kind: str, data: dict) -> None:
    """Rewrite the data of an existing artifact without changing its provenance (e.g. promotion links)."""
    conn.execute("UPDATE threat_artifacts SET data = ? WHERE review_id = ? AND kind = ?",
                 (json.dumps(data), review_id, kind))


def delete_artifact(conn: sqlite3.Connection, review_id: int, kind: str) -> None:
    conn.execute("DELETE FROM threat_artifacts WHERE review_id = ? AND kind = ?", (review_id, kind))
    db.touch(conn, review_id)
