"""Celery entry point for the alerts evaluator.

Beat fires this every 60 s (see ``celery_app.py``). The task body is
idempotent — ``services.alerts.evaluate_all`` reads current state, opens
events for fresh matches, and resolves events whose condition cleared.
No internal gate: alerts always run when beat ticks. Individual rules
can be disabled via ``AlertRule.enabled``.
"""

from __future__ import annotations

import structlog
from sqlalchemy.exc import SQLAlchemyError

from app.celery_app import celery_app
from app.db import task_session
from app.services import alerts as alert_service
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="app.tasks.alerts.evaluate_alerts",
    bind=True,
    # Issue #222 — autoretry on transient DB / network classes so a
    # missed tick doesn't have to wait for the next 60 s beat firing.
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=30,
    retry_jitter=True,
    max_retries=3,
)
def evaluate_alerts(self: object) -> dict[str, int]:  # type: ignore[type-arg]
    return run_task(_run())


async def _run() -> dict[str, int]:
    async with task_session() as session:
        try:
            result = await alert_service.evaluate_all(session)
            if result["opened"] or result["resolved"]:
                logger.info("alerts_evaluated", **result)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.exception("alerts_evaluate_failed", error=str(exc))
            raise
