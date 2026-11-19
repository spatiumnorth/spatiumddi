"""DNSBL / RBL reputation sweep Celery task (#528).

Beat fires ``sweep_dnsbl`` daily; the task itself gates on the master
``PlatformSettings.dnsbl_monitoring_enabled`` toggle AND the
``security.dnsbl`` feature module, so cadence / enable changes in the UI
take effect without restarting beat, and a disabled module / master switch
short-circuits with zero DNS queries.

Idempotent — a full sweep re-derives the candidate set and upserts the
per-(ip, list) latch rows each run. ``autoretry_for`` catches transient DB
/ socket failures (the DNS-resolver errors are swallowed inside the engine
and recorded as ``check_error``, never raised).
"""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime

import structlog
from sqlalchemy.exc import SQLAlchemyError

from app.celery_app import celery_app
from app.db import task_session
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="app.tasks.dnsbl_sweep.sweep_dnsbl",
    bind=True,
    autoretry_for=(SQLAlchemyError, ConnectionError, socket.gaierror, OSError),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=3,
)
@module_gated("security.dnsbl")
def sweep_dnsbl(self) -> dict[str, object]:
    """Daily DNSBL reputation sweep across every public-facing candidate IP."""
    return asyncio.run(_sweep_async())


async def _sweep_async() -> dict[str, object]:
    from app.models.settings import PlatformSettings  # noqa: PLC0415
    from app.services.dnsbl.sweep import run_sweep  # noqa: PLC0415
    from app.services.feature_modules import is_module_enabled  # noqa: PLC0415

    async with task_session() as db:
        if not await is_module_enabled(db, "security.dnsbl"):
            return {"status": "module_disabled"}
        settings = await db.get(PlatformSettings, 1)
        if settings is None or not settings.dnsbl_monitoring_enabled:
            return {"status": "disabled"}
        resolvers = settings.dnsbl_query_resolvers or None

        counters = await run_sweep(db, resolvers=resolvers)

        # Stamp the last-run timestamp (best-effort; run_sweep commits its
        # own progress, so re-fetch a fresh settings row to update).
        fresh = await db.get(PlatformSettings, 1)
        if fresh is not None:
            fresh.dnsbl_sweep_last_run_at = datetime.now(UTC)
            await db.commit()

    logger.info("dnsbl_sweep_complete", **counters)
    return {"status": "ok", **counters}
