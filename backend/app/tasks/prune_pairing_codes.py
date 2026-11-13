"""Sweep stale pairing codes (#169).

Pairing codes are short-lived (default 15 min expiry, max 60 min) and
single-use. Once a row is past its grace window — claimed,
revoked, or just expired long enough that no operator is still
expecting to use it — there's no operational reason to keep it
around. We sweep them so the table stays small and the
``GET /api/v1/appliance/pairing-codes`` list stays scannable.

Three independent retention buckets:

* **Claimed** rows prune after 30 days. Useful for "who paired which
  agent and when" forensics during onboarding, but past a month the
  audit log carries the same signal. A code is considered claimed if
  at least one ``PairingClaim`` row references it, with the earliest
  claim older than the retention window.
* **Revoked** rows prune after 7 days. Operator-driven cancellation
  is a transient state; once it's a week old it's just noise.
* **Expired without claim** rows prune after 24 h past their grace
  window. Most expiries are operator-noise ("generated, walked
  away, generated again later"); short retention keeps the list
  clean.

Runs every 30 minutes so a freshly-expired code drops off the
operator's view in a predictable window without flooding the beat
schedule.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, exists, func, select

from app.celery_app import celery_app
from app.db import task_session
from app.models.appliance import PairingClaim, PairingCode
from app.tasks._system_audit import add_system_audit

logger = structlog.get_logger(__name__)

CLAIMED_RETENTION_DAYS = 30
REVOKED_RETENTION_DAYS = 7
EXPIRED_RETENTION_HOURS = 24
# Grace window must match the consume endpoint's tolerance so a row
# that's "expired but still in grace" doesn't get prematurely swept.
_GRACE_AFTER_EXPIRY = timedelta(minutes=30)


async def _sweep() -> dict[str, int]:
    async with task_session() as db:
        now = datetime.now(UTC)
        claimed_cutoff = now - timedelta(days=CLAIMED_RETENTION_DAYS)
        revoked_cutoff = now - timedelta(days=REVOKED_RETENTION_DAYS)
        expired_cutoff = now - _GRACE_AFTER_EXPIRY - timedelta(hours=EXPIRED_RETENTION_HOURS)

        # Claimed codes: has at least one PairingClaim row whose
        # claimed_at is older than the retention window. Using a
        # correlated EXISTS + MIN(claimed_at) subquery avoids loading
        # claim rows into Python.
        claimed_subq = (
            select(PairingClaim.pairing_code_id)
            .group_by(PairingClaim.pairing_code_id)
            .having(func.max(PairingClaim.claimed_at) < claimed_cutoff)
            .scalar_subquery()
        )
        claimed_del = await db.execute(
            delete(PairingCode).where(
                PairingCode.revoked_at.is_(None),
                PairingCode.id.in_(claimed_subq),
            )
        )

        # Revoked codes: revoked_at set and old enough.
        revoked_del = await db.execute(
            delete(PairingCode).where(
                PairingCode.revoked_at.isnot(None),
                PairingCode.revoked_at < revoked_cutoff,
            )
        )

        # Expired-without-claim: past the grace window, not revoked,
        # and no PairingClaim rows exist for this code.
        no_claims_subq = ~exists().where(PairingClaim.pairing_code_id == PairingCode.id)
        expired_del = await db.execute(
            delete(PairingCode).where(
                PairingCode.revoked_at.is_(None),
                PairingCode.expires_at.isnot(None),
                PairingCode.expires_at < expired_cutoff,
                no_claims_subq,
            )
        )
        counts = {
            "claimed_removed": claimed_del.rowcount or 0,
            "revoked_removed": revoked_del.rowcount or 0,
            "expired_removed": expired_del.rowcount or 0,
        }
        if any(counts.values()):
            # Deleting pairing codes is a mutation (non-negotiable #4, #1257):
            # one summary row per run, counts only (no code material).
            add_system_audit(
                db,
                action="pairing-code-prune",
                resource_type="pairing_code",
                resource_id="prune-pairing-codes",
                resource_display="spent pairing codes",
                new_value=dict(counts),
            )
        await db.commit()
        return counts


@celery_app.task(name="app.tasks.prune_pairing_codes.prune_pairing_codes")
def prune_pairing_codes() -> dict[str, int]:
    result = asyncio.run(_sweep())
    logger.info("pairing_codes_pruned", **result)
    return result
