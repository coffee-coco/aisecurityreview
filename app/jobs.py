"""Background jobs (document analysis, code review, fix generation, threat modelling, batch AI review) run on Celery
workers.

The API records a job row and enqueues ``sentinel.run_job``; a worker runs the registered async handler and writes
progress to Postgres, which the browser polls via GET /api/jobs/{id}. Handlers are module-level async functions
registered with ``@handler(name)`` and receive ``progress`` plus JSON-serialisable keyword parameters.

Jobs are cancelled through the database (status ``cancelled``): a running job's watcher cancels the handler within a
couple of seconds - in-flight AI calls included - and a queued or redelivered job is skipped, so cancelled work never
resumes. Every AI call is counted against the job (``ai_calls`` / ``ai_tokens``) and capped by JOB_MAX_AI_CALLS.
"""
from __future__ import annotations

import asyncio
import json
import logging
import traceback
from contextvars import ContextVar
from typing import Any, Awaitable, Callable

from fastapi import HTTPException

from . import db
from .config import CELERY_QUEUE, JOB_MAX_AI_CALLS

log = logging.getLogger("sentinel.jobs")

Progress = Callable[[float, str], Awaitable[None]]
JobFn = Callable[..., Awaitable[Any]]
HANDLERS: dict[str, JobFn] = {}
ACTIVE = ("queued", "running")
FINAL = ("done", "error", "cancelled")
WATCH_SECONDS = 2.0
_current_job: ContextVar[int | None] = ContextVar("job_id", default=None)


class JobBudgetExceeded(RuntimeError):
    pass


def handler(name: str) -> Callable[[JobFn], JobFn]:
    def register(fn: JobFn) -> JobFn:
        HANDLERS[name] = fn
        return fn
    return register


def _update(job_id: int, only_active: bool = True, **fields) -> None:
    """Write job fields; by default only while the job is still queued/running, so a cancel is never overwritten."""
    if "result" in fields:
        fields["result"] = json.dumps(fields["result"])
    sets = ", ".join(f"{k} = %s" for k in fields) + ", updated_at = %s"
    guard = " AND status IN ('queued', 'running')" if only_active else ""
    with db.tx() as conn:
        conn.execute(f"UPDATE jobs SET {sets} WHERE id = %s{guard}", [*fields.values(), db.now(), job_id])


def _status(job_id: int) -> str | None:
    with db.tx() as conn:
        row = conn.execute("SELECT status FROM jobs WHERE id = %s", (job_id,)).fetchone()
    return row["status"] if row else None


def start_job(review_id: int, kind: str, handler_name: str, /, **params) -> int:
    """Record a queued job for the current workspace and hand it to a worker."""
    if handler_name not in HANDLERS:
        raise ValueError(f"Unknown job handler '{handler_name}'")
    ts = db.now()
    with db.tx() as conn:
        job_id = conn.execute(
            "INSERT INTO jobs (workspace_id, review_id, kind, status, message, created_by, created_at, updated_at) "
            "VALUES (%s, %s, %s, 'queued', 'Queued…', %s, %s, %s) RETURNING id",
            (db.workspace_id(), review_id, kind, db.user_id(), ts, ts)).fetchone()["id"]
    from .worker import celery_app
    try:
        celery_app.send_task("sentinel.run_job", args=[job_id, handler_name, params], queue=CELERY_QUEUE)
    except Exception as e:  # noqa: BLE001 - broker unavailable
        log.error("could not enqueue job %s: %r", job_id, e)
        _update(job_id, status="error", message="Failed", error="The job queue is unavailable")
        raise HTTPException(503, "The job queue is unavailable - try again shortly") from e
    return job_id


def run(job_id: int, handler_name: str, params: dict) -> None:
    """Worker side: execute one job inside its workspace (skipped when it was cancelled or already finished)."""
    with db.tx() as conn:
        row = conn.execute("SELECT workspace_id, status FROM jobs WHERE id = %s", (job_id,)).fetchone()
    if not row or row["status"] in FINAL:
        if row:
            log.info("job %s is %s - skipping", job_id, row["status"])
        return
    token = db.set_workspace(row["workspace_id"])
    try:
        asyncio.run(_execute(job_id, HANDLERS[handler_name], params))
    finally:
        db.reset_workspace(token)


async def _watch(job_id: int, task: asyncio.Task, flag: dict) -> None:
    while not task.done():
        await asyncio.sleep(WATCH_SECONDS)
        if await asyncio.to_thread(_status, job_id) == "cancelled":
            flag["cancelled"] = True
            task.cancel()
            return


async def _execute(job_id: int, fn: JobFn, params: dict) -> None:
    async def progress(p: float, msg: str) -> None:
        await asyncio.to_thread(_update, job_id, progress=round(min(max(p, 0), 1), 3), message=msg[:300])

    job_token = _current_job.set(job_id)
    await asyncio.to_thread(_update, job_id, status="running", message="Starting…", progress=0.01,
                            started_at=db.now())
    flag = {"cancelled": False}
    task = asyncio.create_task(fn(progress, **params))
    watcher = asyncio.create_task(_watch(job_id, task, flag))
    try:
        result = await task
        await asyncio.to_thread(_update, job_id, status="done", progress=1.0, message="Done", result=result or {})
    except asyncio.CancelledError:
        if not flag["cancelled"] and await asyncio.to_thread(_status, job_id) != "cancelled":
            raise
        log.warning("job %s cancelled", job_id)
    except BaseException as e:  # noqa: BLE001 - surface any failure (incl. time limits) to the UI
        log.error("job %s failed: %s", job_id, traceback.format_exc())
        await asyncio.to_thread(_update, job_id, status="error", message="Failed",
                                error=f"{type(e).__name__}: {e}"[:1000])
        if not isinstance(e, Exception):
            raise
    finally:
        watcher.cancel()
        _current_job.reset(job_token)


# ---------------------------------------------------------------------- AI accounting (called by ai/providers)
def check_ai_budget() -> None:
    """Refuse another AI call when the current job is cancelled or has used its budget."""
    job_id = _current_job.get()
    if job_id is None:
        return
    with db.tx() as conn:
        row = conn.execute("SELECT status, ai_calls FROM jobs WHERE id = %s", (job_id,)).fetchone()
    if row and row["status"] == "cancelled":
        raise asyncio.CancelledError()
    if row and JOB_MAX_AI_CALLS and row["ai_calls"] >= JOB_MAX_AI_CALLS:
        raise JobBudgetExceeded(f"This job reached its limit of {JOB_MAX_AI_CALLS} AI calls (JOB_MAX_AI_CALLS)")


def record_ai_call(tokens: int) -> None:
    job_id = _current_job.get()
    if job_id is None:
        return
    with db.tx() as conn:
        conn.execute("UPDATE jobs SET ai_calls = ai_calls + 1, ai_tokens = ai_tokens + %s WHERE id = %s",
                     (max(int(tokens or 0), 0), job_id))


# ---------------------------------------------------------------------- monitor
def _decode(row: dict) -> dict:
    d = dict(row)
    try:
        d["result"] = json.loads(d.get("result") or "{}")
    except json.JSONDecodeError:
        d["result"] = {}
    return d


def get_job(job_id: int) -> dict | None:
    with db.tx() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = %s AND workspace_id = %s",
                           (job_id, db.workspace_id())).fetchone()
    return _decode(row) if row else None


def active_jobs(review_id: int) -> list[dict]:
    with db.tx() as conn:
        rows = conn.execute("SELECT id, kind, status, progress, message FROM jobs WHERE review_id = %s "
                            "AND status IN ('queued', 'running') ORDER BY id", (review_id,)).fetchall()
    return [dict(r) for r in rows]


def list_jobs(active_only: bool = False, limit: int = 100) -> list[dict]:
    """Jobs of the current workspace, newest first, with their review and who started them (no result payloads)."""
    sql = ("SELECT j.id, j.review_id, j.kind, j.status, j.progress, j.message, j.error, j.ai_calls, j.ai_tokens, "
           "j.created_at, j.started_at, j.updated_at, r.title AS review_title, r.kind AS review_kind, "
           "u.email AS created_by_email FROM jobs j JOIN reviews r ON r.id = j.review_id "
           "LEFT JOIN users u ON u.id = j.created_by WHERE j.workspace_id = %s")
    if active_only:
        sql += " AND j.status IN ('queued', 'running')"
    with db.tx() as conn:
        rows = conn.execute(sql + " ORDER BY j.id DESC LIMIT %s", (db.workspace_id(), limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["review_ref"] = f"{'TM' if d.pop('review_kind') == 'threat_model' else 'SR'}-{d['review_id']:04d}"
        out.append(d)
    return out


def cancel_jobs(job_id: int | None = None) -> list[int]:
    """Cancel one job, or every queued/running job, of the current workspace. Returns the cancelled ids."""
    sql = ("UPDATE jobs SET status = 'cancelled', message = 'Cancelled', updated_at = %s, "
           "error = CASE WHEN %s::bigint IS NULL THEN 'Purged by ' ELSE 'Cancelled by ' END || coalesce(%s, 'a user') "
           "WHERE workspace_id = %s AND status IN ('queued', 'running')")
    with db.tx() as conn:
        who = conn.execute("SELECT email FROM users WHERE id = %s", (db.user_id(),)).fetchone() if db.user_id() else None
        args: list = [db.now(), job_id, who["email"] if who else None, db.workspace_id()]
        if job_id is not None:
            sql += " AND id = %s"
            args.append(job_id)
        ids = [r["id"] for r in conn.execute(sql + " RETURNING id", args)]
    if ids:
        log.warning("cancelled job(s) %s", ids)
    return ids
