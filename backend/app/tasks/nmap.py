"""Celery wrapper for on-demand nmap scans.

The runner in :mod:`app.services.nmap.runner` does all the real work;
this module exists purely so the API can dispatch a scan onto a
worker and return 202 immediately. A *started* scan is never retried —
re-running on a worker crash would replay potentially noisy port
traffic without consent. The **only** retry is for a not-yet-visible
row (``NmapScanRowMissing``): that fires before any scan traffic and
absorbs the dispatch-before-commit race (#510).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog

from app.celery_app import celery_app
from app.core.task_lock import single_flight
from app.services.nmap.runner import NmapScanRowMissing, run_scan

logger = structlog.get_logger(__name__)


@celery_app.task(name="app.tasks.nmap.run_scan", bind=True, max_retries=8)
@single_flight(lambda scan_id_str: scan_id_str)
def run_scan_task(self: Any, scan_id_str: str) -> dict[str, str]:
    """Drive one nmap scan from start to finish.

    The runner persists everything it needs into the row as it goes,
    so this wrapper has no return payload of its own — we just echo
    the scan id back so celery_result_backend has something to display.
    """
    scan_id = uuid.UUID(scan_id_str)
    logger.info("nmap_run_scan_task_started", scan_id=scan_id_str)
    try:
        asyncio.run(run_scan(scan_id))
    except NmapScanRowMissing as exc:
        # The dispatcher flushed the row but hadn't committed when we picked up
        # the task. Retry with capped exponential backoff — a lease-event
        # dispatch commits at the end of a potentially large batch, so the row
        # can legitimately be invisible for >10s (Copilot review of #510). 8
        # retries at 1,2,4,8,16,30,30,30s cover ~2min before we conclude the
        # caller's transaction rolled back (nothing, and no stuck row, to run).
        countdown = min(2**self.request.retries, 30)
        try:
            raise self.retry(exc=exc, countdown=countdown) from exc
        except self.MaxRetriesExceededError:
            logger.warning("nmap_run_scan_never_appeared", scan_id=scan_id_str)
            return {"scan_id": scan_id_str, "status": "missing"}
    return {"scan_id": scan_id_str}
