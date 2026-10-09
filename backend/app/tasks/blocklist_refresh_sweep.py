"""Periodic refresh of feed-backed DNS blocklists (#1467).

``DNSBlockList.update_interval_hours`` was stored and shown but nothing read
it: a feed list was fetched once, on create, and then only when someone
pressed Refresh. This beat-fired sweep queues ``refresh_blocklist_feed`` for
every enabled URL list whose last sync is at least ``update_interval_hours``
old. ``0`` keeps a list manual-only, as the field always documented.

``last_synced_at`` is stamped on a failed fetch too, so a broken feed is
retried once per interval rather than on every tick; the Refresh button is
still there for an immediate retry. Due lists are queued a minute apart so
several large feeds don't all parse at once on one worker, and a tick queues
no more than fit before the next one: ``last_synced_at`` only moves when a
refresh has run, so a list still waiting on its countdown at the next tick
would be queued again and parsed twice (#1466's memory spike). The rest wait
for the next tick, longest-overdue first.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.celery_app import celery_app
from app.config import settings
from app.models.dns import DNSBlockList
from app.services.feature_modules import is_module_enabled

logger = structlog.get_logger(__name__)

# Gap between two refreshes queued by the same sweep.
STAGGER_SECONDS = 60
# Beat period of ``dns-blocklist-refresh`` (celery_app beat_schedule).
SWEEP_PERIOD_SECONDS = 3600
# Every refresh a tick queues must have run before the next tick, with room
# for the last one to finish: 55 lists at the 60 s stagger.
MAX_PER_TICK = (SWEEP_PERIOD_SECONDS - 300) // STAGGER_SECONDS


async def due_blocklist_ids(db: AsyncSession, now: datetime) -> list[str]:
    """Enabled URL lists whose interval has elapsed, longest-overdue first."""
    rows = (
        (
            await db.execute(
                select(DNSBlockList).where(
                    DNSBlockList.enabled.is_(True),
                    DNSBlockList.source_type == "url",
                    DNSBlockList.feed_url.is_not(None),
                    DNSBlockList.feed_url != "",
                    DNSBlockList.update_interval_hours > 0,
                )
            )
        )
        .scalars()
        .all()
    )
    due = [
        bl
        for bl in rows
        if bl.last_synced_at is None
        or bl.last_synced_at + timedelta(hours=bl.update_interval_hours) <= now
    ]
    epoch = datetime.min.replace(tzinfo=UTC)
    due.sort(key=lambda bl: bl.last_synced_at or epoch)
    return [str(bl.id) for bl in due]


async def _dispatch_due_async() -> int:
    from app.tasks.dns import refresh_blocklist_feed

    engine = create_async_engine(settings.database_url, future=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale.
            if not await is_module_enabled(db, "core.dns"):
                return 0
            ids = await due_blocklist_ids(db, datetime.now(UTC))
    finally:
        await engine.dispose()

    deferred = max(0, len(ids) - MAX_PER_TICK)
    ids = ids[:MAX_PER_TICK]
    queued = 0
    for i, list_id in enumerate(ids):
        try:
            refresh_blocklist_feed.apply_async(args=[list_id], countdown=i * STAGGER_SECONDS)
            queued += 1
        except Exception as exc:  # noqa: BLE001 — broker down? the next tick retries
            logger.warning("blocklist_refresh_enqueue_failed", list_id=list_id, error=str(exc))
            break
    if queued or deferred:
        logger.info("blocklist_refresh_dispatched", queued=queued, deferred=deferred)
    return queued


@celery_app.task(name="app.tasks.blocklist_refresh_sweep.dispatch_due_blocklists", bind=True)
def dispatch_due_blocklists(self: Any) -> int:  # noqa: ARG001
    """Beat-fired sweep — queues ``refresh_blocklist_feed`` per due list."""
    return asyncio.run(_dispatch_due_async())


__all__ = ["dispatch_due_blocklists", "due_blocklist_ids"]
