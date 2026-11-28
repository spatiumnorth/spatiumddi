"""Celery beat task that drains the typed-event outbox.

Runs every 10 s by default — enough for "near real-time" downstream
automation while keeping the worker pressure low. The task itself is
idempotent: ``process_due_outbox`` uses ``SELECT … FOR UPDATE SKIP
LOCKED`` so multiple worker replicas (or beat-late ticks) cooperate
without double-delivery.
"""

from __future__ import annotations

import structlog
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import celery_app
from app.services.event_delivery import process_due_outbox
from app.task_runtime import release_task_engine, run_task, task_engine

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="app.tasks.event_outbox.process_event_outbox",
    bind=True,
    # Issue #221 — autoretry on DB connection drops so a transient
    # outage doesn't cost a beat tick. Backoff caps at 30 s so a
    # retry storm never overlaps the next 10 s beat firing.
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=30,
    retry_jitter=True,
    max_retries=3,
)
def process_event_outbox(self: object) -> dict[str, object]:  # type: ignore[type-arg]
    """Tick the event outbox worker.

    Runs on the child's one loop with its shared task engine (#4515), so the
    pooled connections stay on the loop that opened them. Outside a child the
    tick gets a throwaway engine on its own ``asyncio.run`` loop, disposed
    at the end (previously a ``NullPool`` engine, for the same reason).
    """

    async def _run() -> dict[str, int]:
        engine = task_engine()
        try:
            async with AsyncSession(engine, expire_on_commit=False) as session:
                return await process_due_outbox(session)
        finally:
            await release_task_engine(engine)

    try:
        return dict(run_task(_run()))
    except (SQLAlchemyError, ConnectionError, OSError):
        # Let Celery autoretry these — re-raise unchanged.
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("event_outbox_tick_failed", error=str(exc))
        return {"claimed": 0, "delivered": 0, "failed": 0, "dead": 0, "error": str(exc)}
