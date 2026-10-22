"""Celery entry point for the conformity evaluator.

Beat fires this every minute (see ``celery_app.py``). The task body is
idempotent — ``services.conformity.evaluate_due_policies`` only runs
policies whose ``last_evaluated_at + eval_interval_hours`` is in
the past, so the practical cadence is the per-policy
``eval_interval_hours`` (default 24 h).
"""

from __future__ import annotations

import asyncio

import structlog
from sqlalchemy.exc import SQLAlchemyError

from app.celery_app import celery_app
from app.db import task_session
from app.services.conformity import evaluate_due_policies, resolve_orphaned_policy_alerts

logger = structlog.get_logger(__name__)


@celery_app.task(
    name="app.tasks.conformity.evaluate_conformity",
    bind=True,
    # Issue #222 — autoretry on transient DB / network classes so a
    # missed tick doesn't have to wait for the next 60 s beat firing.
    autoretry_for=(SQLAlchemyError, ConnectionError, OSError),
    retry_backoff=True,
    retry_backoff_max=30,
    retry_jitter=True,
    max_retries=3,
)
def evaluate_conformity(self: object) -> dict[str, int]:  # type: ignore[type-arg]
    return asyncio.run(_run())


async def _run() -> dict[str, int]:
    async with task_session() as session:
        try:
            # #2277 — close events a disabled / deleted / re-wired policy
            # left open. Isolated: a sweep failure must not stop the
            # evaluation pass behind it.
            try:
                if await resolve_orphaned_policy_alerts(session):
                    await session.commit()
            except SQLAlchemyError:
                await session.rollback()
                logger.exception("conformity_orphan_sweep_failed")
            result = await evaluate_due_policies(session)
            if result["policies_evaluated"]:
                logger.info("conformity_evaluated", **result)
            return result
        except Exception as exc:  # noqa: BLE001
            logger.exception("conformity_evaluate_failed", error=str(exc))
            raise
