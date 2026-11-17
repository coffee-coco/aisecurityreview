"""Scale the Celery worker service of the compose project with load.

Load = jobs waiting in the Redis queue + jobs reserved/running on workers (kombu's ``unacked`` hash; workers use
acks_late with prefetch 1). Desired workers = ceil(load / WORKER_CONCURRENCY), clamped to [MIN_WORKERS, MAX_WORKERS].
Scale-out is immediate; scale-in waits until demand has stayed lower for SCALE_DOWN_DELAY seconds. Scaled-in
workers get a warm shutdown, so running jobs finish (or are redelivered if the grace period runs out).
"""
from __future__ import annotations

import logging
import math
import os
import subprocess
import time

import redis

BROKER = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
QUEUE = os.getenv("CELERY_QUEUE", "sentinel")
PROJECT = os.getenv("COMPOSE_PROJECT", "sentinel")
SERVICE = os.getenv("COMPOSE_SERVICE", "worker")
PROJECT_DIR = os.getenv("PROJECT_DIR", "/project")
COMPOSE_FILE = os.getenv("COMPOSE_FILE", os.path.join(PROJECT_DIR, "docker-compose.yml"))
PER_WORKER = max(1, int(os.getenv("WORKER_CONCURRENCY", "2")))
MIN_WORKERS = max(0, int(os.getenv("MIN_WORKERS", "1")))
MAX_WORKERS = max(MIN_WORKERS, int(os.getenv("MAX_WORKERS", "6")))
POLL = float(os.getenv("POLL_SECONDS", "10"))
SCALE_DOWN_DELAY = float(os.getenv("SCALE_DOWN_DELAY", "120"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s autoscaler: %(message)s")
log = logging.getLogger("autoscaler")


def load(r: redis.Redis) -> tuple[int, int]:
    return int(r.llen(QUEUE)), int(r.hlen("unacked"))


def running_workers() -> int:
    out = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}",
         "--filter", f"label=com.docker.compose.service={SERVICE}", "--filter", "status=running"],
        capture_output=True, text=True, check=True, timeout=30).stdout
    return len(out.split())


def desired_workers(waiting: int, inflight: int) -> int:
    return min(MAX_WORKERS, max(MIN_WORKERS, math.ceil((waiting + inflight) / PER_WORKER)))


def scale(n: int) -> subprocess.Popen:
    return subprocess.Popen(
        ["docker", "compose", "-p", PROJECT, "--project-directory", PROJECT_DIR, "-f", COMPOSE_FILE,
         "up", "-d", "--no-deps", "--no-build", "--no-recreate", "--scale", f"{SERVICE}={n}", SERVICE])


def main() -> None:
    r = redis.Redis.from_url(BROKER)
    log.info("watching queue %r: %d job(s) per worker, %d-%d workers", QUEUE, PER_WORKER, MIN_WORKERS, MAX_WORKERS)
    pending: subprocess.Popen | None = None
    low_since: float | None = None
    while True:
        try:
            if pending and pending.poll() is None:
                time.sleep(POLL)
                continue
            if pending and pending.returncode:
                log.warning("docker compose exited with %s", pending.returncode)
            pending = None
            waiting, inflight = load(r)
            current = running_workers()
            want = desired_workers(waiting, inflight)
            if want > current:
                log.info("scale out %d -> %d (waiting=%d, in flight=%d)", current, want, waiting, inflight)
                pending, low_since = scale(want), None
            elif want < current:
                low_since = low_since or time.monotonic()
                if time.monotonic() - low_since >= SCALE_DOWN_DELAY:
                    log.info("scale in %d -> %d (waiting=%d, in flight=%d)", current, want, waiting, inflight)
                    pending, low_since = scale(want), None
            else:
                low_since = None
        except Exception as e:  # noqa: BLE001 - keep watching through transient Redis / Docker errors
            log.warning("autoscaler error: %r", e)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
