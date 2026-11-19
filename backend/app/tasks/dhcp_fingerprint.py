"""Celery task — fingerbank lookup + IPAddress stamping for one MAC.

Triggered from the agent ingestion endpoint per fresh fingerprint.
Idempotent — running it twice for the same MAC is a no-op on the
second call (cache window) plus a redundant UPDATE on every matching
IPAddress row (no-op semantically). Safe to retry.

Why it's a task instead of inline: fingerbank's API takes 100-500ms
per call and we don't want to block the agent's bulk POST behind a
synchronous round-trip.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog

from app.celery_app import celery_app
from app.db import task_session
from app.services.feature_modules import is_module_enabled
from app.services.profiling.passive import run_lookup_and_stamp

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="app.tasks.dhcp_fingerprint.lookup_fingerprint",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
)
def lookup_fingerprint_task(
    self: Any, mac_address: str, server_id: str | None = None
) -> dict[str, str]:
    """Drive one fingerbank lookup + IP-stamp pass.

    ``server_id`` is the reporting DHCP server; it scopes the IP stamp to
    the spaces that server serves (#2577). Optional so a message queued
    by an older api still runs.

    The fingerbank service swallows network errors internally, so a
    failure here typically means a DB issue (connection drop, schema
    mismatch). Retry up to 3 times with a 60s backoff, then give up
    — the next agent push for the same MAC will re-enqueue.
    """
    logger.info("dhcp_fingerprint_task_started", mac=mac_address)
    try:
        asyncio.run(_run(mac_address, server_id))
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "dhcp_fingerprint_task_error",
            mac=mac_address,
            error=str(exc),
            attempt=self.request.retries,
        )
        raise self.retry(exc=exc) from exc
    return {"mac": mac_address}


async def _run(mac_address: str, server_id: str | None = None) -> None:
    async with task_session() as db:
        # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
        # do no work (and open no driver connections) when it is.
        if not await is_module_enabled(db, "core.dhcp"):
            return
        await run_lookup_and_stamp(
            db,
            mac_address=mac_address,
            server_id=uuid.UUID(server_id) if server_id else None,
        )
