"""Celery wrappers for packet capture (issue #59).

Two tasks:

* ``run_capture_task`` — drives one server-vantage capture via the
  runner. Explicitly NOT retried (``max_retries=0``): the operator
  triggers a capture, and silently replaying it on a worker crash would
  re-tap traffic without consent (mirrors nmap).
* ``prune_captures`` — nightly retention sweep. pcaps are large +
  sensitive (plaintext creds/PII), so terminal rows older than
  ``PlatformSettings.pcap_retention_days`` are hard-deleted AND their
  ``.pcap`` files unlinked. Also reaps rows stuck in a non-terminal
  state past their deadline (worker crash / lost dispatch) so the
  operator never stares at a frozen row.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.core.task_lock import single_flight
from app.db import task_session
from app.models.pcap import PacketCapture
from app.models.settings import PlatformSettings
from app.services.pcap.runner import HARD_MAX_DURATION_S, run_pcap

logger = structlog.get_logger(__name__)

# Default retention if PlatformSettings has no value. pcaps are triage,
# not analytics — short window, same argument as the 24 h query-log window.
DEFAULT_RETENTION_DAYS = 7
# A non-terminal row older than (its deadline + this margin) with no
# progress is presumed dead (worker crash / lost dispatch) and reaped.
_STUCK_MARGIN_S = 120


@celery_app.task(name="app.tasks.pcap.run_capture", bind=True, max_retries=0)
@single_flight(lambda capture_id_str: capture_id_str)
def run_capture_task(self: Any, capture_id_str: str) -> dict[str, str]:  # noqa: ARG001
    """Drive one server-vantage packet capture from start to finish."""
    capture_id = uuid.UUID(capture_id_str)
    logger.info("pcap_run_task_started", capture_id=capture_id_str)
    asyncio.run(run_pcap(capture_id))
    return {"capture_id": capture_id_str}


async def _prune_with_session(db: AsyncSession) -> dict[str, int]:
    settings_row = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    retention_days = DEFAULT_RETENTION_DAYS
    if settings_row is not None:
        retention_days = int(
            getattr(settings_row, "pcap_retention_days", DEFAULT_RETENTION_DAYS)
            or DEFAULT_RETENTION_DAYS
        )

    now = datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)
    removed = 0
    files_unlinked = 0
    reaped = 0

    # 1) Retention: hard-delete terminal rows past the cutoff + unlink files.
    terminal = ("completed", "failed", "cancelled")
    old_rows = list(
        (
            await db.execute(
                select(PacketCapture).where(
                    PacketCapture.status.in_(terminal),
                    PacketCapture.created_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    for row in old_rows:
        if row.pcap_path:
            with contextlib.suppress(OSError):
                Path(row.pcap_path).unlink()
                files_unlinked += 1
        await db.delete(row)
        removed += 1

    # 2) Reap rows stuck in queued/running past their deadline.
    stuck_rows = list(
        (
            await db.execute(
                select(PacketCapture).where(PacketCapture.status.in_(("queued", "running")))
            )
        )
        .scalars()
        .all()
    )
    for row in stuck_rows:
        deadline_s = (row.max_duration_s or HARD_MAX_DURATION_S) + _STUCK_MARGIN_S
        anchor = row.started_at or row.created_at
        if anchor is None:
            continue
        if anchor.tzinfo is None:
            anchor = anchor.replace(tzinfo=UTC)
        if (now - anchor).total_seconds() > deadline_s:
            row.status = "failed"
            row.error_message = row.error_message or "capture reaped — no progress past deadline"
            if row.finished_at is None:
                row.finished_at = now
            reaped += 1

    await db.commit()
    return {
        "removed": removed,
        "files_unlinked": files_unlinked,
        "reaped": reaped,
        "retention_days": retention_days,
    }


async def _prune() -> dict[str, int]:
    async with task_session() as db:
        return await _prune_with_session(db)


@celery_app.task(
    name="app.tasks.pcap.prune_captures",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def prune_captures(self: Any) -> dict[str, int]:  # noqa: ARG001
    result = asyncio.run(_prune())
    logger.info("pcap_captures_pruned", **result)
    return result
