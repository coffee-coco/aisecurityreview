"""Reviewer-managed requirement <-> Checkov check links.

Rows either include or exclude a check for a requirement, globally (review_id NULL) or for one
review. They are merged on top of the curated automatic links in that order:
auto -> global include/exclude -> review include/exclude (see Catalog.subcategory_checks).
"""
from __future__ import annotations

from . import db


def overrides(conn: db.Connection, requirement_id: str, review_id: int | None = None) -> list[dict]:
    """Workspace-wide rows plus (when review_id is given) that review's rows, workspace-wide first."""
    sql = "SELECT * FROM check_links WHERE workspace_id = %s AND requirement_id = %s AND (review_id IS NULL"
    args: list = [db.workspace_id(), requirement_id]
    if review_id is not None:
        sql += " OR review_id = %s"
        args.append(review_id)
    sql += ") ORDER BY review_id IS NOT NULL, id"
    return [dict(r) for r in conn.execute(sql, args)]


def all_links(conn: db.Connection, review_id: int | None = None, include_reviews: bool = False) -> list[dict]:
    ws = db.workspace_id()
    if include_reviews:
        rows = conn.execute("SELECT * FROM check_links WHERE workspace_id = %s "
                            "ORDER BY requirement_id, review_id IS NOT NULL, check_id", (ws,))
    elif review_id is not None:
        rows = conn.execute("SELECT * FROM check_links WHERE workspace_id = %s AND review_id = %s "
                            "ORDER BY requirement_id, check_id", (ws, review_id))
    else:
        rows = conn.execute("SELECT * FROM check_links WHERE workspace_id = %s AND review_id IS NULL "
                            "ORDER BY requirement_id, check_id", (ws,))
    return [dict(r) for r in rows]


def set_link(conn: db.Connection, requirement_id: str, check_id: str, action: str, note: str = "",
             review_id: int | None = None) -> dict:
    ts, ws = db.now(), db.workspace_id()
    if review_id is None:
        row = conn.execute(
            """INSERT INTO check_links (workspace_id, requirement_id, check_id, action, review_id, note, created_at,
                                        updated_at)
               VALUES (%s, %s, %s, %s, NULL, %s, %s, %s)
               ON CONFLICT (workspace_id, requirement_id, check_id) WHERE review_id IS NULL DO UPDATE SET
                 action = excluded.action, note = excluded.note, updated_at = excluded.updated_at
               RETURNING *""",
            (ws, requirement_id, check_id, action, note, ts, ts)).fetchone()
    else:
        row = conn.execute(
            """INSERT INTO check_links (workspace_id, requirement_id, check_id, action, review_id, note, created_at,
                                        updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (requirement_id, check_id, review_id) DO UPDATE SET
                 action = excluded.action, note = excluded.note, updated_at = excluded.updated_at
               RETURNING *""",
            (ws, requirement_id, check_id, action, review_id, note, ts, ts)).fetchone()
    return dict(row)


def delete_link(conn: db.Connection, requirement_id: str, check_id: str, review_id: int | None = None) -> bool:
    ws = db.workspace_id()
    if review_id is None:
        cur = conn.execute("DELETE FROM check_links WHERE workspace_id = %s AND requirement_id = %s AND check_id = %s "
                           "AND review_id IS NULL", (ws, requirement_id, check_id))
    else:
        cur = conn.execute("DELETE FROM check_links WHERE workspace_id = %s AND requirement_id = %s AND check_id = %s "
                           "AND review_id = %s", (ws, requirement_id, check_id, review_id))
    return cur.rowcount > 0


def global_by_requirement(conn: db.Connection) -> dict[str, dict[str, set[str]]]:
    """{requirement_id: {'include': {check ids}, 'exclude': {check ids}}} for workspace-wide rows."""
    out: dict[str, dict[str, set[str]]] = {}
    for r in conn.execute("SELECT requirement_id, check_id, action FROM check_links "
                          "WHERE workspace_id = %s AND review_id IS NULL", (db.workspace_id(),)):
        out.setdefault(r["requirement_id"], {"include": set(), "exclude": set()})[r["action"]].add(r["check_id"])
    return out
