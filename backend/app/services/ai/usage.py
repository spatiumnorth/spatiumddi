"""Operator Copilot usage stats + cap enforcement (issue #90 Wave 4).

Two responsibilities:

1. **Cap enforcement** — pre-call check that a user hasn't blown
   past their daily token / cost cap. Raises :class:`UsageCapExceeded`
   so the chat endpoint can map it to a 429 with ``Retry-After``.

2. **Usage stats** — per-user "today" aggregates (used by the chat
   drawer's progress bar) and admin "across all users" aggregates
   (used by the platform-insights AI usage card).

Both run off the same ``ai_chat_message`` rows the orchestrator
writes — no separate metering layer.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai import AIChatMessage, AIChatSession
from app.models.auth import User
from app.models.settings import PlatformSettings


@dataclass(frozen=True)
class UsageSnapshot:
    """Aggregated usage for a window. ``cap_*`` fields are populated
    only by ``current_user_usage_today`` since caps are per-user.
    """

    messages: int
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    cap_token: int | None = None
    cap_cost_usd: Decimal | None = None


class UsageCapExceeded(Exception):
    """Raised by :func:`check_user_caps` when the user has spent past
    their daily allowance. Carries a ``retry_after_seconds`` hint so
    the HTTP layer can populate ``Retry-After``.
    """

    def __init__(
        self,
        kind: str,  # "tokens" | "cost"
        used: int | Decimal,
        cap: int | Decimal,
        retry_after_seconds: int,
    ) -> None:
        super().__init__(
            f"daily {kind} cap exceeded: {used} of {cap} (resets in " f"{retry_after_seconds}s)"
        )
        self.kind = kind
        self.used = used
        self.cap = cap
        self.retry_after_seconds = retry_after_seconds


def _utc_midnight(now: datetime | None = None) -> datetime:
    n = (now or datetime.now(UTC)).astimezone(UTC)
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


def _seconds_until_next_midnight() -> int:
    now = datetime.now(UTC)
    tomorrow = _utc_midnight(now) + timedelta(days=1)
    return max(1, int((tomorrow - now).total_seconds()))


# ── Per-user today (used by drawer progress + cap enforcement) ────────


async def current_user_usage_today(db: AsyncSession, user: User) -> UsageSnapshot:
    """Aggregate this user's chat usage since UTC midnight. Cheap —
    one indexed query against ``ai_chat_message`` joined on the
    user's session list.
    """
    settings = await db.scalar(select(PlatformSettings))
    cap_token = (
        int(settings.ai_per_user_daily_token_cap)
        if settings and settings.ai_per_user_daily_token_cap is not None
        else None
    )
    cap_cost = (
        Decimal(settings.ai_per_user_daily_cost_cap_usd)
        if settings and settings.ai_per_user_daily_cost_cap_usd is not None
        else None
    )

    since = _utc_midnight()
    stmt = (
        select(
            func.count(AIChatMessage.id),
            func.coalesce(func.sum(AIChatMessage.tokens_in), 0),
            func.coalesce(func.sum(AIChatMessage.tokens_out), 0),
            func.coalesce(func.sum(AIChatMessage.cost_usd), Decimal("0")),
        )
        .select_from(AIChatMessage)
        .join(AIChatSession, AIChatMessage.session_id == AIChatSession.id)
        .where(AIChatSession.user_id == user.id)
        .where(AIChatMessage.created_at >= since)
        .where(AIChatMessage.role == "assistant")
    )
    row = (await db.execute(stmt)).one()
    return UsageSnapshot(
        messages=int(row[0] or 0),
        tokens_in=int(row[1] or 0),
        tokens_out=int(row[2] or 0),
        cost_usd=Decimal(row[3] or 0),
        cap_token=cap_token,
        cap_cost_usd=cap_cost,
    )


async def check_user_caps(db: AsyncSession, user: User) -> None:
    """Raise :class:`UsageCapExceeded` if the user has hit either
    their daily token or daily cost cap. No-op when neither cap is
    configured. Called by the chat endpoint before forwarding to the
    orchestrator.
    """
    snap = await current_user_usage_today(db, user)
    if snap.cap_token is not None:
        used_tokens = snap.tokens_in + snap.tokens_out
        if used_tokens >= snap.cap_token:
            raise UsageCapExceeded(
                "tokens",
                used_tokens,
                snap.cap_token,
                _seconds_until_next_midnight(),
            )
    if snap.cap_cost_usd is not None and snap.cost_usd >= snap.cap_cost_usd:
        raise UsageCapExceeded(
            "cost",
            snap.cost_usd,
            snap.cap_cost_usd,
            _seconds_until_next_midnight(),
        )


# ── Aggregate stats (admin / platform-insights card) ──────────────────


@dataclass(frozen=True)
class AdminUsageStats:
    today: UsageSnapshot
    last_7d: UsageSnapshot
    last_30d: UsageSnapshot
    top_users_today: list[dict[str, Any]]


async def _aggregate_window(db: AsyncSession, since: datetime) -> UsageSnapshot:
    row = (
        await db.execute(
            select(
                func.count(AIChatMessage.id),
                func.coalesce(func.sum(AIChatMessage.tokens_in), 0),
                func.coalesce(func.sum(AIChatMessage.tokens_out), 0),
                func.coalesce(func.sum(AIChatMessage.cost_usd), Decimal("0")),
            )
            .select_from(AIChatMessage)
            .where(AIChatMessage.created_at >= since)
            .where(AIChatMessage.role == "assistant")
        )
    ).one()
    return UsageSnapshot(
        messages=int(row[0] or 0),
        tokens_in=int(row[1] or 0),
        tokens_out=int(row[2] or 0),
        cost_usd=Decimal(row[3] or 0),
    )


async def admin_usage_stats(db: AsyncSession) -> AdminUsageStats:
    """One-shot dashboard summary. Three time windows + top-5 users
    today. Used by the platform-insights AI usage card.
    """
    today = _utc_midnight()
    week = today - timedelta(days=6)
    month = today - timedelta(days=29)

    today_snap = await _aggregate_window(db, today)
    week_snap = await _aggregate_window(db, week)
    month_snap = await _aggregate_window(db, month)

    top_rows = (
        await db.execute(
            select(
                AIChatSession.user_id,
                User.username,
                func.count(AIChatMessage.id).label("messages"),
                func.coalesce(func.sum(AIChatMessage.tokens_in), 0).label("tokens_in"),
                func.coalesce(func.sum(AIChatMessage.tokens_out), 0).label("tokens_out"),
                func.coalesce(func.sum(AIChatMessage.cost_usd), Decimal("0")).label("cost_usd"),
            )
            .select_from(AIChatMessage)
            .join(AIChatSession, AIChatMessage.session_id == AIChatSession.id)
            .join(User, AIChatSession.user_id == User.id)
            .where(AIChatMessage.created_at >= today)
            .where(AIChatMessage.role == "assistant")
            .group_by(AIChatSession.user_id, User.username)
            .order_by(desc("messages"))
            .limit(5)
        )
    ).all()

    return AdminUsageStats(
        today=today_snap,
        last_7d=week_snap,
        last_30d=month_snap,
        top_users_today=[
            {
                "user_id": str(uid),
                "username": uname,
                "messages": int(msgs),
                "tokens_in": int(tin or 0),
                "tokens_out": int(tout or 0),
                "cost_usd": str(Decimal(cost or 0)),
            }
            for uid, uname, msgs, tin, tout, cost in top_rows
        ],
    )


__all__ = [
    "AdminUsageStats",
    "UsageCapExceeded",
    "UsageSnapshot",
    "admin_usage_stats",
    "check_user_caps",
    "current_user_usage_today",
]


def _coerce_uuid(value: Any) -> uuid.UUID:
    """Tiny helper kept here so the dataclass-only public API can
    convert string IDs returned to JSON callers without each call
    site repeating the cast.
    """
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
