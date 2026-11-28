"""Sweep time-bound grants whose ``expires_at`` has passed — issue #65.

Beat fires every 60 s (always-on; there is no opt-out setting — the per-row
``expires_at`` is the only knob). Idempotent: only matches rows that are
still live (``revoked_at IS NULL`` AND ``expires_at < now()``), so re-running
the task on a quiet system picks up nothing new.

For each match the sweep soft-revokes the row (sets ``revoked_at = now()``,
keeps the row for history) and writes one ``audit_log`` entry attributed to
the synthetic ``system`` user. ``user_has_permission`` already filters
``expires_at > now()`` at request time, so the sweep is the durable
bookkeeping layer rather than the enforcement path — enforcement is immediate
regardless of when the sweep runs.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from app.celery_app import celery_app
from app.db import task_session
from app.models.audit import AuditLog
from app.models.time_bound_grant import TimeBoundGrant
from app.task_runtime import run_task

logger = structlog.get_logger(__name__)


async def _sweep() -> dict[str, int]:
    async with task_session() as db:
        now = datetime.now(UTC)
        rows = list(
            (
                await db.execute(
                    select(TimeBoundGrant)
                    .where(TimeBoundGrant.revoked_at.is_(None))
                    .where(TimeBoundGrant.expires_at < now)
                )
            )
            .scalars()
            .all()
        )

        revoked = 0
        for grant in rows:
            grant.revoked_at = now
            db.add(
                AuditLog(
                    user_id=None,
                    user_display_name="system",
                    auth_source="system",
                    action="permission_change",
                    resource_type="time_bound_grant",
                    resource_id=str(grant.id),
                    resource_display=(
                        f"Expired {grant.action} on {grant.resource_type}"
                        f"{('/' + grant.resource_id) if grant.resource_id else ''} "
                        f"for group {grant.group_id}"
                    ),
                    old_value={"revoked_at": None},
                    new_value={
                        "revoked_at": now.isoformat(),
                        "reason": "time_bound_grant_expired",
                    },
                    result="success",
                )
            )
            revoked += 1

        await db.commit()
        return {"checked": len(rows), "revoked": revoked}


@celery_app.task(name="app.tasks.time_bound_grant_sweep.sweep_expired_grants")
def sweep_expired_grants() -> dict[str, int]:
    """Celery entry point. Idempotent — safe to retry."""
    result = run_task(_sweep())
    logger.info("time_bound_grant_sweep_complete", **result)
    return result
