"""Celery application for background jobs.

    celery -A app.worker worker --loglevel=INFO --concurrency=2
"""
from __future__ import annotations

from celery import Celery
from celery.signals import worker_process_shutdown

from . import db, jobs
from .config import CELERY_BROKER_URL, CELERY_QUEUE, JOB_TIME_LIMIT

celery_app = Celery("sentinel", broker=CELERY_BROKER_URL)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,                 # progress and results live in the jobs table
    task_default_queue=CELERY_QUEUE,
    task_acks_late=True,                     # a job lost with its worker (crash, scale-in) is redelivered
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,            # one job per process: queue depth reflects real load
    task_soft_time_limit=JOB_TIME_LIMIT,
    task_time_limit=JOB_TIME_LIMIT + 60,
    broker_transport_options={"visibility_timeout": JOB_TIME_LIMIT + 600},
    broker_connection_retry_on_startup=True,
    worker_cancel_long_running_tasks_on_connection_loss=False,
)


@celery_app.task(name="sentinel.run_job")
def run_job(job_id: int, handler_name: str, params: dict) -> None:
    jobs.run(job_id, handler_name, params)


@worker_process_shutdown.connect
def _close_pool(**_) -> None:
    db.close_pool()


# Job handlers register themselves on import.
from . import api_devil, api_files, api_fixes, api_threats  # noqa: E402,F401
