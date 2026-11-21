"""Revoking and counting a user's API tokens (#3432, #1359).

One implementation for every path that ends a user's tokens: disabling or
re-enabling the account, a password change / admin reset that opts in
(``revoke_api_tokens``), and the explicit "revoke all" actions. Each revoked
token gets its own ``api_token`` audit row shaped like a PATCH revoke, so a
token's history says why it went inactive.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import APIToken, User


def _live_filter(now: datetime) -> list:
    """Active and not past ``expires_at`` — the tokens that still authenticate."""
    return [
        APIToken.is_active.is_(True),
        or_(APIToken.expires_at.is_(None), APIToken.expires_at > now),
    ]


async def count_live_api_tokens(db: AsyncSession, user_id: uuid.UUID) -> int:
    now = datetime.now(UTC)
    return int(
        (
            await db.execute(
                select(func.count())
                .select_from(APIToken)
                .where(APIToken.user_id == user_id, *_live_filter(now))
            )
        ).scalar_one()
    )


async def count_live_api_tokens_by_user(db: AsyncSession) -> dict[uuid.UUID, int]:
    now = datetime.now(UTC)
    rows = await db.execute(
        select(APIToken.user_id, func.count())
        .where(APIToken.user_id.is_not(None), *_live_filter(now))
        .group_by(APIToken.user_id)
    )
    return {uid: n for uid, n in rows.all()}


async def revoke_user_api_tokens(
    db: AsyncSession, actor: User, target_id: uuid.UUID, reason: str
) -> int:
    """Deactivate every live (active, unexpired) token of ``target_id``; returns how many.

    The account row is locked first: ``create_token`` re-reads the owner's
    ``is_active`` under a share lock, so a mint racing a disable either
    commits before the SELECT below (and is revoked by it) or waits for this
    commit and is refused. The caller commits.
    """
    await db.execute(select(User.id).where(User.id == target_id).with_for_update())
    # Live tokens only: an expired one can no longer authenticate, so it is
    # neither counted nor audited as revoked.
    live = (
        await db.execute(
            select(APIToken.id, APIToken.name).where(
                APIToken.user_id == target_id, *_live_filter(datetime.now(UTC))
            )
        )
    ).all()
    if live:
        await db.execute(
            update(APIToken)
            .where(APIToken.id.in_([tid for tid, _ in live]))
            .values(is_active=False)
        )
    for tid, name in live:
        db.add(
            AuditLog(
                user_id=actor.id,
                user_display_name=actor.display_name,
                auth_source=actor.auth_source,
                action="update",
                resource_type="api_token",
                resource_id=str(tid),
                resource_display=name,
                result="success",
                changed_fields=["is_active"],
                new_value={"is_active": False, "reason": reason},
            )
        )
    return len(live)
