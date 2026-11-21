"""Revoke every live API token an account owns (#3432, #2144).

Disabling an account is how an administrator contains it, and a bearer token
authenticates as its owner, so a token left live would outlast that
containment and work again the moment the account is re-enabled. Both the
user admin (``PUT /users/{id}``) and the service-account admin
(``PATCH /service-accounts/{id}``) call this on any change of ``is_active``,
so the two cannot drift.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import APIToken, User


async def revoke_owner_tokens(
    db: AsyncSession, owner_id: uuid.UUID, *, actor: User, reason: str
) -> int:
    """Set ``is_active=False`` on every live token ``owner_id`` holds, with one
    audit row per token shaped like the token's own revoke (PATCH
    ``is_active: false``), so a token's history says why it went inactive.
    Returns how many were revoked. Does not commit.

    The owner row is locked first: ``create_token`` re-reads the owner's
    ``is_active`` under a share lock, so a mint racing a disable either commits
    before the SELECT below (and is revoked by it) or waits for the caller's
    commit and is refused.
    """
    await db.execute(select(User.id).where(User.id == owner_id).with_for_update())
    live = (
        await db.execute(
            select(APIToken.id, APIToken.name).where(
                APIToken.user_id == owner_id, APIToken.is_active.is_(True)
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
