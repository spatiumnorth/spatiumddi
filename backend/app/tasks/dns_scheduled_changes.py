"""Run DNS record changes that have come due (#4830).

Beat fires every 30 s. Each due change is claimed with a conditional UPDATE, so
two workers (or two control-plane nodes) never run the same one, and a retried
tick finds nothing left to claim. See ``app.services.dns.scheduled_changes``.
"""

from __future__ import annotations

import asyncio

from app.celery_app import celery_app
from app.db import task_session
from app.services.dns import scheduled_changes
from app.tasks.module_gate import module_gated


async def _run() -> dict[str, int]:
    async with task_session() as db:
        return await scheduled_changes.run_due(db)


@celery_app.task(name="app.tasks.dns_scheduled_changes.run_due")
@module_gated("core.dns")
def run_due() -> dict[str, int]:
    """Celery beat task — apply every scheduled DNS record change that is due."""
    return asyncio.run(_run())
