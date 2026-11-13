"""Record refused supervisor registrations for the Fleet pairing tab (#2225).

``POST /appliance/supervisor/register`` is unauthenticated and answers every
refusal with the same 403, so a joiner (and a guesser) learns nothing about
the code. The operator, though, needs to see "node 3 tried and the code was
already used". This keeps that, readable only through the superadmin
pairing API.

Everything stored here is bounded, because the caller is anonymous:

* one row per (code, hostname, reason), repeats counted rather than added;
* at most ``MAX_KNOWN_ROWS`` rows against a real code and ``MAX_UNKNOWN_ROWS``
  against codes that matched nothing, oldest dropped first, so a guesser
  cycling hostnames can only evict other guesses;
* nothing older than ``RETENTION`` survives the next insert.

The submitted code is never stored; ``pairing_code_id`` is set only when it
matched a row the operator already owns.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import PairingAttempt

MAX_KNOWN_ROWS = 200
MAX_UNKNOWN_ROWS = 50
RETENTION = timedelta(days=30)


async def record_pairing_attempt(
    db: AsyncSession,
    *,
    code_id: uuid.UUID | None,
    reason: str,
    hostname: str,
    source_ip: str | None,
) -> None:
    """Add (or bump) the row for one refused attempt. Does not commit."""
    now = datetime.now(UTC)
    hostname = hostname[:255]
    stmt = select(PairingAttempt).where(
        PairingAttempt.hostname == hostname,
        PairingAttempt.reason == reason,
        (
            PairingAttempt.pairing_code_id.is_(None)
            if code_id is None
            else PairingAttempt.pairing_code_id == code_id
        ),
    )
    row = (await db.execute(stmt.limit(1))).scalar_one_or_none()
    if row is not None:
        row.attempts += 1
        row.last_attempted_at = now
        row.source_ip = source_ip
    else:
        db.add(
            PairingAttempt(
                pairing_code_id=code_id,
                reason=reason,
                hostname=hostname,
                source_ip=source_ip,
                attempts=1,
                first_attempted_at=now,
                last_attempted_at=now,
            )
        )
        await db.flush()
        await _trim(db, known=code_id is not None, now=now)


async def _trim(db: AsyncSession, *, known: bool, now: datetime) -> None:
    await db.execute(
        delete(PairingAttempt).where(PairingAttempt.last_attempted_at < now - RETENTION)
    )
    cap = MAX_KNOWN_ROWS if known else MAX_UNKNOWN_ROWS
    scope = (
        PairingAttempt.pairing_code_id.isnot(None)
        if known
        else PairingAttempt.pairing_code_id.is_(None)
    )
    keep = (
        select(PairingAttempt.id)
        .where(scope)
        .order_by(PairingAttempt.last_attempted_at.desc())
        .limit(cap)
    )
    await db.execute(delete(PairingAttempt).where(scope, PairingAttempt.id.notin_(keep)))
