"""Reviewer-managed requirement <-> Checkov check links.

Rows either include or exclude a check for a requirement, globally (review_id NULL) or for one
review. They are merged on top of the curated automatic links in that order:
auto -> global include/exclude -> review include/exclude (see Catalog.subcategory_checks).
"""
from __future__ import annotations

import sqlite3

from . import db

SCHEMA = """
CREATE TABLE IF NOT EXISTS check_links (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id TEXT NOT NULL,
    check_id       TEXT NOT NULL,
    action         TEXT NOT NULL CHECK (action IN ('include', 'exclude')),
    review_id      INTEGER REFERENCES reviews(id) ON DELETE CASCADE,   -- NULL = all reviews
    note           TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE (requirement_id, check_id, review_id)
);
-- SQLite treats NULLs as distinct in UNIQUE constraints, so global rows need their own index.
CREATE UNIQUE INDEX IF NOT EXISTS ux_check_links_global ON check_links(requirement_id, check_id) WHERE review_id IS NULL;
CREATE INDEX IF NOT EXISTS ix_check_links_req ON check_links(requirement_id);
CREATE INDEX IF NOT EXISTS ix_check_links_review ON check_links(review_id);
"""


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def overrides(conn: sqlite3.Connection, requirement_id: str, review_id: int | None = None) -> list[dict]:
    """Global rows plus (when review_id is given) that review's rows, global first."""
    sql = "SELECT * FROM check_links WHERE requirement_id = ? AND (review_id IS NULL"
    args: list = [requirement_id]
    if review_id is not None:
        sql += " OR review_id = ?"
        args.append(review_id)
    sql += ") ORDER BY review_id IS NOT NULL, id"
    return [dict(r) for r in conn.execute(sql, args)]


def all_links(conn: sqlite3.Connection, review_id: int | None = None, include_reviews: bool = False) -> list[dict]:
    if include_reviews:
        rows = conn.execute("SELECT * FROM check_links ORDER BY requirement_id, review_id IS NOT NULL, check_id")
    elif review_id is not None:
        rows = conn.execute("SELECT * FROM check_links WHERE review_id = ? ORDER BY requirement_id, check_id",
                            (review_id,))
    else:
        rows = conn.execute("SELECT * FROM check_links WHERE review_id IS NULL ORDER BY requirement_id, check_id")
    return [dict(r) for r in rows]


def set_link(conn: sqlite3.Connection, requirement_id: str, check_id: str, action: str, note: str = "",
             review_id: int | None = None) -> dict:
    ts = db.now()
    if review_id is None:
        conn.execute(
            """INSERT INTO check_links (requirement_id, check_id, action, review_id, note, created_at, updated_at)
               VALUES (?, ?, ?, NULL, ?, ?, ?)
               ON CONFLICT(requirement_id, check_id) WHERE review_id IS NULL DO UPDATE SET
                 action = excluded.action, note = excluded.note, updated_at = excluded.updated_at""",
            (requirement_id, check_id, action, note, ts, ts))
        row = conn.execute("SELECT * FROM check_links WHERE requirement_id = ? AND check_id = ? AND review_id IS NULL",
                           (requirement_id, check_id)).fetchone()
    else:
        conn.execute(
            """INSERT INTO check_links (requirement_id, check_id, action, review_id, note, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(requirement_id, check_id, review_id) DO UPDATE SET
                 action = excluded.action, note = excluded.note, updated_at = excluded.updated_at""",
            (requirement_id, check_id, action, review_id, note, ts, ts))
        row = conn.execute("SELECT * FROM check_links WHERE requirement_id = ? AND check_id = ? AND review_id = ?",
                           (requirement_id, check_id, review_id)).fetchone()
    return dict(row)


def delete_link(conn: sqlite3.Connection, requirement_id: str, check_id: str, review_id: int | None = None) -> bool:
    if review_id is None:
        cur = conn.execute("DELETE FROM check_links WHERE requirement_id = ? AND check_id = ? AND review_id IS NULL",
                           (requirement_id, check_id))
    else:
        cur = conn.execute("DELETE FROM check_links WHERE requirement_id = ? AND check_id = ? AND review_id = ?",
                           (requirement_id, check_id, review_id))
    return cur.rowcount > 0


def global_by_requirement(conn: sqlite3.Connection) -> dict[str, dict[str, set[str]]]:
    """{requirement_id: {'include': {check ids}, 'exclude': {check ids}}} for global rows."""
    out: dict[str, dict[str, set[str]]] = {}
    for r in conn.execute("SELECT requirement_id, check_id, action FROM check_links WHERE review_id IS NULL"):
        out.setdefault(r["requirement_id"], {"include": set(), "exclude": set()})[r["action"]].add(r["check_id"])
    return out
