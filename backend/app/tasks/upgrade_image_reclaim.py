"""Reclaim stored upgrade images every node has committed to (#2400).

A 1.5 GiB ``.raw.xz`` stayed in the upgrade-image store on the control
plane's ``/var`` after every node was running it, until somebody deleted
it in Fleet by hand. On a 15 GB ``/var`` that is the difference between
headroom and kubelet eviction.

The decision and its locking live in
``app.api.v1.appliance.upgrade_images.reclaim_committed_upgrade_images``;
this is the periodic driver. A beat task rather than a heartbeat hook so
it re-evaluates on its own (a rolling run turns ``succeeded`` long after
the last node's heartbeat changed anything) and a slow mirror can never
hold a supervisor heartbeat open.

Idempotent and safe to retry: every pass re-derives everything from the
database under ``pg_try_advisory_xact_lock``, so an overlapping pass (a
second beat, a retry) does nothing and the next tick picks up the rest.
The worker mounts the same slot-images store the api writes (chart:
appliance host mounts; compose: the shared named volume).
"""

from __future__ import annotations

import asyncio

import structlog

from app.celery_app import celery_app
from app.db import task_session

logger = structlog.get_logger(__name__)


async def _sweep() -> list[str]:
    from app.api.v1.appliance.upgrade_images import (  # noqa: PLC0415
        reclaim_committed_upgrade_images,
    )

    async with task_session() as db:
        return await reclaim_committed_upgrade_images(db)


@celery_app.task(name="app.tasks.upgrade_image_reclaim.reclaim_upgrade_images")
def reclaim_upgrade_images() -> dict[str, int]:
    reclaimed = asyncio.run(_sweep())
    if reclaimed:
        logger.info("upgrade_images_reclaimed", images=reclaimed)
    return {"reclaimed": len(reclaimed)}
