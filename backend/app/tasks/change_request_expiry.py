"""Sweep change requests whose ``expires_at`` has passed — issue #62.

Beat fires every 60 s (always-on; the per-row ``expires_at`` is the only
knob — stamped at request time from the matched policy's ``ttl_hours``).
Idempotent: only matches rows that are still ``pending`` AND past
``expires_at``, so re-running on a quiet system picks up nothing new and a
row that an approver/requester already decided is never touched.

For each match the sweep flips ``pending`` → ``expired`` (terminal) and
writes one ``change_request.expired`` audit row attributed to the
synthetic ``system`` actor (NN #4 — every state change is audited). The
approve endpoint also lazily expires a row it finds stale on read, so a
request never executes past its TTL regardless of when this sweep runs;
the sweep is the durable bookkeeping layer that clears the queue.

Resilience (#12): the sweep processes one row at a time, each re-locked
``FOR UPDATE`` and re-checked for ``state == "pending"`` inside its own
transaction. A row an approver / requester flips out of ``pending`` between
the candidate SELECT and the per-row lock is skipped (not an error), and a
single row that raises is logged + skipped rather than aborting the whole
batch — so one wedged row can't strand the queue.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from app.celery_app import celery_app
from app.db import task_session
from app.models.change_request import ChangeRequest
from app.services.approvals.service import get_change_request, mark_expired
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)


async def _sweep() -> dict[str, int]:
    async with task_session() as db:
        now = datetime.now(UTC)
        # Candidate ids only — re-load each FOR UPDATE so a mid-loop decision
        # by an approver/requester is observed under the lock (#12).
        # #10: ``expires_at <= now`` is the single "expired" convention,
        # matching the approve-path check + the per-row recheck below.
        candidate_ids = list(
            (
                await db.execute(
                    select(ChangeRequest.id)
                    .where(ChangeRequest.state == "pending")
                    .where(ChangeRequest.expires_at <= now)
                )
            )
            .scalars()
            .all()
        )

        checked = 0
        expired = 0
        skipped = 0
        for cr_id in candidate_ids:
            checked += 1
            try:
                cr = await get_change_request(db, cr_id, for_update=True)
                # Re-check under the lock: an approver/requester may have
                # flipped it out of pending. #10: ``expires_at > now`` (the
                # negation of ``<= now``) means not-yet-expired → skip.
                if cr is None or cr.state != "pending" or cr.expires_at > datetime.now(UTC):
                    skipped += 1
                    await db.commit()  # release the row lock
                    continue
                await mark_expired(db, cr)
                await db.commit()
                expired += 1
            except Exception as exc:  # noqa: BLE001 — one bad row can't abort the batch
                skipped += 1
                logger.warning(
                    "change_request_expiry_row_failed",
                    change_request_id=str(cr_id),
                    error=str(exc),
                )
                try:
                    await db.rollback()
                except Exception as rb_exc:  # noqa: BLE001
                    logger.warning("change_request_expiry_rollback_failed", error=str(rb_exc))
        return {"checked": checked, "expired": expired, "skipped": skipped}


@celery_app.task(name="app.tasks.change_request_expiry.sweep_expired_change_requests")
def sweep_expired_change_requests() -> dict[str, int]:
    """Celery entry point. Idempotent — safe to retry."""
    result = run_task(_sweep())
    logger.info("change_request_expiry_sweep_complete", **result)
    return result
