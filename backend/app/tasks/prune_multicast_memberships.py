"""Reaper sweep for stale IGMP-snooping membership rows.

The Phase 3 SNMP populator writes ``MulticastMembership`` rows
tagged ``seen_via='igmp_snooping'`` and bumps ``last_seen_at`` on
every observation. When the underlying join is gone (host left
the group, switch reboots, ARP cache flushes) the populator
simply stops touching the row — there's no IGMP-leave event we
can listen for from the SNMP table.

This sweep prunes any ``igmp_snooping`` membership whose
``last_seen_at`` is older than ``DEFAULT_STALENESS_MINUTES``
(default 30 min). That window is intentionally generous:

* IGMP general-query timers default to 125 s on Cisco; even
  conservative deployments query every few minutes.
* SpatiumDDI's SNMP poll runs at the device's
  ``poll_interval_seconds`` (default 300 s = 5 min).
* So a healthy join refreshes ``last_seen_at`` every 5 min;
  anything past 30 min is genuinely stale rather than a poll
  cycle the populator missed.

``manual`` and ``sap_announce`` rows are NOT touched. Manual
rows are operator-curated; SAP-announce (Phase 3 deferred) has
its own freshness signal.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.db import task_session
from app.models.multicast import MulticastMembership
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)


DEFAULT_STALENESS_MINUTES = 30


async def _sweep_with_session(db: AsyncSession) -> dict[str, int]:
    """Delete ``seen_via='igmp_snooping'`` membership rows whose
    ``last_seen_at`` is older than the staleness window. Split out
    so tests can run against the pytest session.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=DEFAULT_STALENESS_MINUTES)
    result = await db.execute(
        delete(MulticastMembership).where(
            MulticastMembership.seen_via == "igmp_snooping",
            MulticastMembership.last_seen_at.is_not(None),
            MulticastMembership.last_seen_at < cutoff,
        )
    )
    await db.commit()
    return {
        "removed": result.rowcount or 0,
        "staleness_minutes": DEFAULT_STALENESS_MINUTES,
    }


async def _sweep() -> dict[str, int]:
    async with task_session() as db:
        return await _sweep_with_session(db)


@celery_app.task(name="app.tasks.prune_multicast_memberships.prune_stale_igmp_memberships")
def prune_stale_igmp_memberships() -> dict[str, int]:
    result = run_task(_sweep())
    if result["removed"]:
        logger.info(
            "prune_stale_igmp_memberships",
            removed=result["removed"],
            staleness_minutes=result["staleness_minutes"],
        )
    return result


__all__ = [
    "DEFAULT_STALENESS_MINUTES",
    "_sweep_with_session",
    "prune_stale_igmp_memberships",
]
