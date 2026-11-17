"""Postgres persistence (psycopg 3 connection pool). The schema is managed by Alembic (``migrations/``).

Every request / background job runs inside a workspace: ``set_workspace`` stores the id in a context variable and
the data helpers scope their queries with ``workspace_id()``.
"""
from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg
from psycopg_pool import ConnectionPool

from .config import AI_DEFAULTS, DATABASE_URL, DB_POOL_MAX, DB_POOL_MIN, SECRET_SETTINGS

STATUSES = ["new", "in_progress", "awaiting_info", "approved", "rejected"]
REQ_STATUSES = ["open", "met", "partial", "not_met", "na"]
CHECK_STATUSES = ["applicable", "pass", "fail", "na", "exception"]

JSON_COLUMNS = ("technologies", "services", "ai_meta", "data_types", "interacts_with", "system_types",
                "design", "code_review")
JSON_OBJECTS = ("ai_meta", "design", "code_review")
BOOL_COLUMNS = ("internet_facing", "personal_data", "third_party", "uses_ai")
ITEM_BOOLS = ("is_risk", "is_recommendation")

Connection = psycopg.Connection


class Row(dict):
    """A result row addressable by column name or position (``row["id"]`` / ``row[0]``)."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


def _row_factory(cursor):
    names = [c.name for c in cursor.description] if cursor.description else []
    return lambda values: Row(zip(names, values))


_pool: ConnectionPool | None = None
_pool_pid: int | None = None
_pool_lock = threading.Lock()


def pool() -> ConnectionPool:
    """Process-wide pool, recreated after fork (Celery prefork children, uvicorn workers)."""
    global _pool, _pool_pid
    if _pool is None or _pool_pid != os.getpid():
        with _pool_lock:
            if _pool is None or _pool_pid != os.getpid():
                _pool = ConnectionPool(DATABASE_URL, min_size=DB_POOL_MIN, max_size=DB_POOL_MAX, open=True,
                                       kwargs={"row_factory": _row_factory, "autocommit": False})
                _pool_pid = os.getpid()
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None and _pool_pid == os.getpid():
        _pool.close()
    _pool = None


@contextmanager
def tx() -> Iterator[Connection]:
    """One transaction: committed on success, rolled back on error."""
    with pool().connection() as conn:
        yield conn


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------- workspace context
_workspace: ContextVar[int | None] = ContextVar("workspace_id", default=None)


def set_workspace(workspace_id: int | None) -> Token:
    return _workspace.set(workspace_id)


def reset_workspace(token: Token) -> None:
    _workspace.reset(token)


def workspace_id() -> int:
    ws = _workspace.get()
    if ws is None:
        raise RuntimeError("No workspace in context")
    return ws


_user: ContextVar[int | None] = ContextVar("user_id", default=None)


def set_user(user_id: int | None) -> Token:
    return _user.set(user_id)


def user_id() -> int | None:
    """The signed-in user (or API key owner) of the current request, if any."""
    return _user.get()


# ---------------------------------------------------------------------- reviews
def review_row(row: dict | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for col in JSON_COLUMNS:
        if col not in d:
            continue
        empty = {} if col in JSON_OBJECTS else []
        try:
            d[col] = json.loads(d.get(col) or json.dumps(empty))
        except json.JSONDecodeError:
            d[col] = empty
    for col in BOOL_COLUMNS:
        d[col] = bool(d.get(col))
    d["ref"] = f"{'TM' if d.get('kind') == 'threat_model' else 'SR'}-{d['id']:04d}"
    return d


def log_activity(conn: Connection, review_id: int, action: str, detail: str = "") -> None:
    conn.execute("INSERT INTO activity (review_id, ts, action, detail) VALUES (%s, %s, %s, %s)",
                 (review_id, now(), action, detail))


def touch(conn: Connection, review_id: int) -> None:
    conn.execute("UPDATE reviews SET updated_at = %s WHERE id = %s", (now(), review_id))


# ---------------------------------------------------------------------- workspace settings
def get_settings(ws: int | None = None) -> dict[str, str]:
    """AI provider and GitLab settings of the current workspace (secrets decrypted)."""
    from .security import decrypt

    ws = ws if ws is not None else workspace_id()
    values = dict(AI_DEFAULTS)
    with tx() as conn:
        for row in conn.execute("SELECT key, value FROM workspace_settings WHERE workspace_id = %s", (ws,)):
            values[row["key"]] = decrypt(row["value"]) if row["key"] in SECRET_SETTINGS else row["value"]
    return values


def save_settings(updates: dict[str, Any], ws: int | None = None) -> None:
    from .security import encrypt

    ws = ws if ws is not None else workspace_id()
    with tx() as conn:
        for k, v in updates.items():
            value = encrypt(str(v)) if k in SECRET_SETTINGS and v else str(v)
            conn.execute("INSERT INTO workspace_settings (workspace_id, key, value) VALUES (%s, %s, %s) "
                         "ON CONFLICT (workspace_id, key) DO UPDATE SET value = excluded.value", (ws, k, value))
