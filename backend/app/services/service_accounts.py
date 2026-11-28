"""Shared reads for service accounts (#2144).

The REST surface (``/service-accounts``) and the ``find_service_accounts``
copilot tool report the same token summary per account, from this one query,
so the two cannot disagree about which tokens count as live.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import APIToken


@dataclass(frozen=True)
class TokenSummary:
    #: Tokens that would authenticate now: active and unexpired.
    active_count: int = 0
    #: When any of the account's tokens was last used.
    last_used_at: datetime | None = None
    #: The soonest expiry among its live tokens; None when none expires.
    next_expiry: datetime | None = None


async def token_summaries(
    db: AsyncSession, owner_ids: list[uuid.UUID]
) -> dict[uuid.UUID, TokenSummary]:
    """One :class:`TokenSummary` per owner that holds any token. An owner
    with none is absent; read it as ``TokenSummary()``."""
    if not owner_ids:
        return {}
    live = APIToken.is_active.is_(True) & (
        APIToken.expires_at.is_(None) | (APIToken.expires_at > func.now())
    )
    rows = await db.execute(
        select(
            APIToken.user_id,
            func.count(APIToken.id).filter(live),
            func.max(APIToken.last_used_at),
            func.min(APIToken.expires_at).filter(live),
        )
        .where(APIToken.user_id.in_(owner_ids))
        .group_by(APIToken.user_id)
    )
    return {
        uid: TokenSummary(active_count=count, last_used_at=last, next_expiry=nxt)
        for uid, count, last, nxt in rows.all()
    }
