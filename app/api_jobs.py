"""Job queue monitor: list the workspace's background jobs, cancel one, or purge every queued/running job."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from . import jobs
from .auth import require_role
from .config import JOB_MAX_AI_CALLS, JOB_TIME_LIMIT

router = APIRouter(prefix="/api")


@router.get("/jobs")
def list_jobs(active: bool = False, limit: int = 100):
    rows = jobs.list_jobs(active_only=active, limit=min(max(limit, 1), 500))
    counts: dict[str, int] = {}
    for j in rows:
        counts[j["status"]] = counts.get(j["status"], 0) + 1
    return {"jobs": rows, "counts": counts, "limits": {"max_ai_calls": JOB_MAX_AI_CALLS, "time_limit": JOB_TIME_LIMIT}}


@router.post("/jobs/purge", dependencies=[Depends(require_role("admin"))])
def purge_jobs():
    """Cancel every queued and running job in this workspace."""
    return {"cancelled": jobs.cancel_jobs()}


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int):
    job = jobs.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] not in jobs.ACTIVE:
        raise HTTPException(409, f"Job is already {job['status']}")
    jobs.cancel_jobs(job_id)
    return jobs.get_job(job_id)
