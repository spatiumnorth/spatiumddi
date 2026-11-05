"""#3514: the E911 lookup trail is bounded — retention prune + logging budget."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import E911ResolutionLog
from app.tasks.prune_e911_resolution_log import RETENTION_DAYS, _sweep


def _row(age_days: int) -> E911ResolutionLog:
    return E911ResolutionLog(
        queried_at=datetime.now(UTC) - timedelta(days=age_days),
        identity_kind="ip",
        identity_value="10.0.0.1",
        actor_kind="api_token",
        confidence="exact",
    )


async def test_sweep_drops_only_rows_past_retention(db_session: AsyncSession) -> None:
    db_session.add_all([_row(RETENTION_DAYS + 5), _row(1)])
    await db_session.commit()
    assert await _sweep() == 1
    assert await _sweep() == 0  # idempotent
    n = (await db_session.execute(select(func.count()).select_from(E911ResolutionLog))).scalar()
    assert n == 1


async def test_log_budget_exhausted_skips_row_but_still_answers() -> None:
    from app.core import auth_throttle

    class FakeRedis:
        n = 0

        async def eval(self, *a):  # type: ignore[no-untyped-def]
            FakeRedis.n += 1
            return FakeRedis.n

        async def aclose(self) -> None:
            pass

    with patch.object(auth_throttle, "make_async_redis", lambda *a, **k: FakeRedis()):
        results = [
            await auth_throttle.e911_lookup_log_rate_limited("t")
            for _ in range(auth_throttle._E911_LOG_RL_MAX + 2)
        ]
    assert results[: auth_throttle._E911_LOG_RL_MAX] == [False] * auth_throttle._E911_LOG_RL_MAX
    assert results[-1] is True
