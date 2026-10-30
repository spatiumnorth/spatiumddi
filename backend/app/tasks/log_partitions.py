"""Create and retire the partitions of the agent-shipped log tables (#2185).

Runs every 15 minutes. For each of ``dns_query_log_entry``,
``dhcp_log_entry`` and ``dns_rpz_hit`` it creates the next partitions ahead
of the clock and drops the ones whose whole range is past the retention
window; see :mod:`app.services.logs.partitions` for how, and for why there is
no default partition.

Safe to retry and to overlap (non-negotiable #9): every step is idempotent
and a session advisory lock per table makes a second worker skip the table.
A table that fails (a lock that could not be taken in time, a dropped
connection) is retried by the next tick; the others are not held up by it,
each runs on a session of its own.

Also queued when beat or a worker starts, so a stretch with neither running
does not wait up to 15 minutes more before partitions are made again.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from app.celery_app import celery_app
from app.db import task_sessionmaker
from app.services.logs.partitions import maintain_all

logger = structlog.get_logger(__name__)


async def _maintain_all() -> dict[str, Any]:
    async with task_sessionmaker() as sessions:
        return await maintain_all(sessions)


@celery_app.task(name="app.tasks.log_partitions.maintain_log_partitions")
def maintain_log_partitions() -> dict[str, Any]:
    result = asyncio.run(_maintain_all())
    logger.info("log_partitions_maintained", **result)
    return result
