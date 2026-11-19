"""Copilot Watch's own daily budget (issue #4405).

The chat's caps are per user and counted from chat messages. Watch has no
user and no chat messages, so it has a budget of its own, counted from
``ai_watch_run`` rows since UTC midnight: a token budget and a cost
budget, both required before Watch can be enabled.

A model that is not on the rate sheet (most local models) has an unknown
cost, stored as NULL and counted as nothing here. The token budget is the
one that bounds such a provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_watch import AIWatchConfig, AIWatchRun


def utc_midnight(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def next_utc_midnight(now: datetime) -> datetime:
    return utc_midnight(now) + timedelta(days=1)


@dataclass(frozen=True)
class WatchUsage:
    """What Watch has spent since UTC midnight, against its budget."""

    runs: int
    tokens: int
    cost_usd: Decimal
    token_budget: int
    cost_budget_usd: Decimal

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.token_budget - self.tokens)

    @property
    def exhausted(self) -> str | None:
        """``tokens`` or ``cost`` when that budget is used up, else None."""
        if self.tokens >= self.token_budget:
            return "tokens"
        if self.cost_usd >= self.cost_budget_usd:
            return "cost"
        return None


async def usage_today(db: AsyncSession, config: AIWatchConfig, now: datetime) -> WatchUsage:
    row = (
        await db.execute(
            select(
                func.count(AIWatchRun.id),
                func.coalesce(func.sum(AIWatchRun.tokens_in + AIWatchRun.tokens_out), 0),
                func.coalesce(func.sum(AIWatchRun.cost_usd), Decimal("0")),
            ).where(AIWatchRun.started_at >= utc_midnight(now))
        )
    ).one()
    return WatchUsage(
        runs=int(row[0] or 0),
        tokens=int(row[1] or 0),
        cost_usd=Decimal(row[2] or 0),
        token_budget=int(config.daily_token_budget),
        cost_budget_usd=Decimal(config.daily_cost_budget_usd),
    )


__all__ = ["WatchUsage", "next_utc_midnight", "usage_today", "utc_midnight"]
