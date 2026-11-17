"""Persistence for AI-generated fixes: one row per (review, finding) - a patch, a proof-of-vulnerability
Python test and a markdown explanation. Mirrors threat/store.py's simple per-key storage."""
from __future__ import annotations

import json

from .. import db


def _row(row: dict) -> dict:
    d = dict(row)
    try:
        d["files"] = json.loads(d["files"] or "[]")
    except json.JSONDecodeError:
        d["files"] = []
    return d


def get_fix(conn: db.Connection, review_id: int, finding_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM code_fixes WHERE review_id = %s AND finding_id = %s",
                       (review_id, finding_id)).fetchone()
    return _row(row) if row else None


def get_fixes(conn: db.Connection, review_id: int) -> dict[str, dict]:
    return {r["finding_id"]: _row(r) for r in
            conn.execute("SELECT * FROM code_fixes WHERE review_id = %s", (review_id,))}


def put_fix(conn: db.Connection, review_id: int, finding_id: str, *, status: str = "ready", patch: str = "",
           files: list[str] | None = None, test_filename: str = "", test_code: str = "", explanation: str = "",
           provider: str = "", error: str = "") -> dict:
    ts = db.now()
    conn.execute(
        """INSERT INTO code_fixes (review_id, finding_id, status, patch, files, test_filename, test_code,
                                   explanation, provider, error, created_at, updated_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT(review_id, finding_id) DO UPDATE SET status = excluded.status, patch = excluded.patch,
             files = excluded.files, test_filename = excluded.test_filename, test_code = excluded.test_code,
             explanation = excluded.explanation, provider = excluded.provider, error = excluded.error,
             updated_at = excluded.updated_at""",
        (review_id, finding_id, status, patch, json.dumps(files or []), test_filename, test_code, explanation,
         provider, error, ts, ts))
    return get_fix(conn, review_id, finding_id)


def delete_fix(conn: db.Connection, review_id: int, finding_id: str) -> None:
    conn.execute("DELETE FROM code_fixes WHERE review_id = %s AND finding_id = %s", (review_id, finding_id))
