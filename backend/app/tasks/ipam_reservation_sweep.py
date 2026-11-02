"""Sweep IPAM reservations whose ``reserved_until`` has passed.

Beat fires every 5 minutes; the task itself gates on
``PlatformSettings.reservation_sweep_enabled`` so operators can opt
out without removing the schedule. Idempotent — only matches rows
whose status is still ``reserved``, so re-running the task picks up
nothing new on a quiet system.

For each match:
  * flip status → ``available``
  * clear ``reserved_until``
  * recount the owning subnets' and blocks' cached utilization
  * write one ``audit_log`` entry per row, attributed to a synthetic
    ``system`` user (``user_id`` null), describing the transition.

The audit row is the operator-facing breadcrumb — searching the
audit log by resource_id surfaces the auto-expiry as the reason a
previously-reserved IP went back into the free pool.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from app.celery_app import celery_app
from app.db import task_session
from app.models.audit import AuditLog
from app.models.ipam import IPAddress
from app.models.settings import PlatformSettings
from app.services.ipam.utilization import recount_subnets_and_blocks

logger = structlog.get_logger(__name__)


async def _sweep() -> dict[str, int]:
    async with task_session() as db:
        settings_row = await db.get(PlatformSettings, 1)
        if settings_row is not None and not settings_row.reservation_sweep_enabled:
            return {"checked": 0, "released": 0, "skipped_disabled": 1}

        now = datetime.now(UTC)
        rows = list(
            (
                await db.execute(
                    select(IPAddress)
                    .where(IPAddress.status == "reserved")
                    .where(IPAddress.reserved_until.is_not(None))
                    .where(IPAddress.reserved_until < now)
                )
            )
            .scalars()
            .all()
        )

        released = 0
        for ip in rows:
            old_reserved_until = ip.reserved_until
            ip.status = "available"
            ip.reserved_until = None
            db.add(
                AuditLog(
                    user_id=None,
                    user_display_name="system",
                    auth_source="system",
                    action="update",
                    resource_type="ip_address",
                    resource_id=str(ip.id),
                    resource_display=str(ip.address),
                    old_value={
                        "status": "reserved",
                        "reserved_until": (
                            old_reserved_until.isoformat() if old_reserved_until else None
                        ),
                    },
                    new_value={
                        "status": "available",
                        "reserved_until": None,
                        "reason": "reservation_ttl_expired",
                    },
                    result="success",
                )
            )
            released += 1

        # An ``available`` row is free for the counters (#2981), so freeing a
        # reservation lowers its subnet's and its blocks' figures: recount them
        # in this pass rather than leaving it to the hourly recount (#3320).
        await recount_subnets_and_blocks(db, (ip.subnet_id for ip in rows))

        await db.commit()
        return {"checked": len(rows), "released": released, "skipped_disabled": 0}


@celery_app.task(name="app.tasks.ipam_reservation_sweep.sweep_expired_reservations")
def sweep_expired_reservations() -> dict[str, int]:
    """Celery entry point. Idempotent — safe to retry."""
    result = asyncio.run(_sweep())
    logger.info("ipam_reservation_sweep_complete", **result)
    return result
