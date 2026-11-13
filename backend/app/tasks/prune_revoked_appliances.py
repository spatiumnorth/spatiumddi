"""Sweep soft-deleted appliance rows past the retention window
(#170 Wave E follow-up).

When an operator clicks Delete on a Fleet UI row, the row's ``state``
flips to ``revoked`` + ``revoked_at`` is stamped. This sweep
permanently hard-deletes those rows after
``platform_settings.appliance_revoked_retention_days`` (default 30,
``0`` disables auto-purge so an operator must use the per-row
``Permanently delete`` button explicitly).

Runs hourly so a row that crosses the retention threshold drops in a
predictable window without flooding the beat schedule.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete

from app.celery_app import celery_app
from app.db import task_session
from app.models.appliance import APPLIANCE_STATE_REVOKED, Appliance
from app.models.settings import PlatformSettings
from app.tasks._system_audit import add_system_audit

logger = structlog.get_logger(__name__)

_PLATFORM_SINGLETON_ID = 1


async def _sweep() -> dict[str, int]:
    async with task_session() as db:
        ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
        retention_days = ps.appliance_revoked_retention_days if ps is not None else 30
        # ``0`` disables the automatic hard-delete entirely; operator
        # action via the per-row Permanently-delete endpoint is the
        # only path forward in that mode.
        if retention_days <= 0:
            return {"removed": 0, "disabled": True}

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        result = await db.execute(
            delete(Appliance).where(
                Appliance.state == APPLIANCE_STATE_REVOKED,
                Appliance.revoked_at.isnot(None),
                Appliance.revoked_at < cutoff,
            )
        )
        removed = result.rowcount or 0
        if removed:
            # Hard-deleting Fleet rows is a mutation (non-negotiable #4, #1257):
            # one summary row per run.
            add_system_audit(
                db,
                action="appliance-prune-revoked",
                resource_type="appliance",
                resource_id="prune-revoked-appliances",
                resource_display="revoked appliances past retention",
                new_value={"removed": removed, "retention_days": retention_days},
            )
        await db.commit()
        return {"removed": removed, "disabled": False}


@celery_app.task(name="app.tasks.prune_revoked_appliances.prune_revoked_appliances")
def prune_revoked_appliances() -> dict[str, int]:
    result = asyncio.run(_sweep())
    logger.info("revoked_appliances_pruned", **result)
    return result
