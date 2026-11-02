"""Tiny in-process background jobs (document analysis, code review) with progress in SQLite.

The browser polls GET /api/jobs/{id}. Jobs survive page reloads (state is in the DB) but not a
server restart - running jobs are marked as errored on startup.
"""
from __future__ import annotations

import asyncio
import json
import logging
import traceback
from typing import Any, Awaitable, Callable

from . import db

log = logging.getLogger("sentinel.jobs")
_tasks: set[asyncio.Task] = set()

JobFn = Callable[[Callable[[float, str], Awaitable[None]]], Awaitable[Any]]


def _update(job_id: int, **fields) -> None:
    if "result" in fields:
        fields["result"] = json.dumps(fields["result"])
    sets = ", ".join(f"{k} = ?" for k in fields) + ", updated_at = ?"
    with db.tx() as conn:
        conn.execute(f"UPDATE jobs SET {sets} WHERE id = ?", [*fields.values(), db.now(), job_id])


def start_job(review_id: int, kind: str, fn: JobFn) -> int:
    ts = db.now()
    with db.tx() as conn:
        job_id = conn.execute("INSERT INTO jobs (review_id, kind, status, message, created_at, updated_at) "
                              "VALUES (?, ?, 'queued', 'Queued…', ?, ?)", (review_id, kind, ts, ts)).lastrowid

    async def progress(p: float, msg: str) -> None:
        await asyncio.to_thread(_update, job_id, progress=round(min(max(p, 0), 1), 3), message=msg[:300])

    async def runner() -> None:
        _update(job_id, status="running", message="Starting…", progress=0.01)
        try:
            result = await fn(progress)
            _update(job_id, status="done", progress=1.0, message="Done", result=result or {})
        except Exception as e:  # noqa: BLE001 - surface any failure to the UI
            log.error("job %s failed: %s", job_id, traceback.format_exc())
            _update(job_id, status="error", message="Failed", error=f"{type(e).__name__}: {e}"[:1000])

    task = asyncio.create_task(runner())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return job_id


def get_job(job_id: int) -> dict | None:
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["result"] = json.loads(d["result"] or "{}")
    except json.JSONDecodeError:
        d["result"] = {}
    return d


def active_jobs(review_id: int) -> list[dict]:
    with db.tx() as conn:
        rows = conn.execute("SELECT id, kind, status, progress, message FROM jobs WHERE review_id = ? "
                            "AND status IN ('queued', 'running') ORDER BY id", (review_id,)).fetchall()
    return [dict(r) for r in rows]


def reset_stale() -> None:
    with db.tx() as conn:
        conn.execute("UPDATE jobs SET status = 'error', error = 'Server restarted while the job was running' "
                     "WHERE status IN ('queued', 'running')")
