"""Daily prune of ``dhcp_lease_history`` rows past the retention window.

Gated on ``PlatformSettings.dhcp_lease_history_retention_days``:

  * ``> 0`` — drop every row where ``expired_at < now - retention``.
  * ``== 0`` — disable pruning entirely (keep history forever). Useful
    for long-term forensics or compliance retention without bringing
    Loki / a SIEM into the hot path.

Idempotent (CLAUDE.md non-negotiable #9): a second run over the same
state simply finds zero rows past the cutoff. Beat ticks once per day
because the table grows slowly even on a busy DHCP estate — five
minutes of history vs five hours doesn't move the operational needle.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, select

from app.celery_app import celery_app
from app.config import settings as app_config
from app.db import task_session
from app.models.dhcp import DHCPLeaseHistory
from app.models.settings import PlatformSettings
from app.services.feature_modules import is_module_enabled
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)


async def _prune() -> int:
    async with task_session(command_timeout=app_config.task_db_long_command_timeout) as db:
        # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
        # do no work (and open no driver connections) when it is.
        if not await is_module_enabled(db, "core.dhcp"):
            return 0
        settings = (await db.execute(select(PlatformSettings))).scalar_one_or_none()
        retention_days = (
            getattr(settings, "dhcp_lease_history_retention_days", 90) if settings else 90
        )
        if retention_days <= 0:
            logger.info("dhcp_lease_history_prune_disabled", retention_days=retention_days)
            return 0
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        result = await db.execute(
            delete(DHCPLeaseHistory).where(DHCPLeaseHistory.expired_at < cutoff)
        )
        await db.commit()
        # ``rowcount`` may be -1 on some drivers; guard for that.
        return max(int(result.rowcount or 0), 0)


@celery_app.task(name="app.tasks.dhcp_lease_history_prune.prune_lease_history")
@module_gated("core.dhcp")
def prune_lease_history() -> dict[str, int]:
    removed = asyncio.run(_prune())
    logger.info("dhcp_lease_history_prune_complete", rows_removed=removed)
    return {"rows_removed": removed}


__all__ = ["prune_lease_history"]
