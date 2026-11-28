"""Operator Copilot read tool for API-token usage (#4491).

``find_api_tokens`` lists the caller's own API tokens (a superadmin sees
everyone's) with last-used time, last client address and calls in the last
30 days, optionally only the idle ones. The token secret and hash are never
returned. Read-only: revoking a token stays a UI / REST action.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import APIToken, APITokenUsageDaily, User
from app.services.ai.tools.base import register_tool


class FindApiTokensArgs(BaseModel):
    idle_days: int | None = Field(
        default=None,
        ge=1,
        le=3650,
        description="Only tokens not used in this many days (never-used ones included).",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_api_tokens",
    permission="self",
    description=(
        "List API tokens with last-used time, last client address and the "
        "number of calls in the last 30 days. Set idle_days to find tokens "
        "not used for that long (candidates to revoke). Shows your own "
        "tokens; a superadmin sees all. Read-only, never shows the secret."
    ),
    args_model=FindApiTokensArgs,
    category="read",
    default_enabled=True,
)
async def find_api_tokens(db: AsyncSession, user: User, args: FindApiTokensArgs) -> dict[str, Any]:
    stmt = select(APIToken).order_by(APIToken.created_at.desc()).limit(args.limit)
    if not is_effective_superadmin(user):
        stmt = stmt.where(APIToken.user_id == user.id)
    if args.idle_days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=args.idle_days)
        stmt = stmt.where(
            or_(
                APIToken.last_used_at < cutoff,
                (APIToken.last_used_at.is_(None)) & (APIToken.created_at < cutoff),
            )
        )
    rows = list((await db.execute(stmt)).scalars().all())
    since = datetime.now(UTC).date() - timedelta(days=29)
    calls: dict[Any, int] = {}
    if rows:
        res = await db.execute(
            select(APITokenUsageDaily.token_id, func.sum(APITokenUsageDaily.calls))
            .where(
                APITokenUsageDaily.token_id.in_([t.id for t in rows]),
                APITokenUsageDaily.day >= since,
            )
            .group_by(APITokenUsageDaily.token_id)
        )
        calls = {tid: int(n) for tid, n in res.all()}
    return {
        "api_tokens": [
            {
                "id": str(t.id),
                "name": t.name,
                "prefix": t.prefix,
                "is_active": t.is_active,
                "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
                "last_client_ip": t.last_client_ip,
                "calls_30d": calls.get(t.id, 0),
            }
            for t in rows
        ],
        "count": len(rows),
    }


__all__ = ["find_api_tokens"]
