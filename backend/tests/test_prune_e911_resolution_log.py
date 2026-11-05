"""#3514: the E911 lookup trail is bounded — retention prune + logging budget,
both read from ``PlatformSettings``."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import E911ResolutionLog
from app.models.settings import PlatformSettings
from app.tasks.prune_e911_resolution_log import DEFAULT_RETENTION_DAYS, _sweep
from tests.test_retention_settings import _settings_row, _superadmin


def _row(age_days: int) -> E911ResolutionLog:
    return E911ResolutionLog(
        queried_at=datetime.now(UTC) - timedelta(days=age_days),
        identity_kind="ip",
        identity_value="10.0.0.1",
        actor_kind="api_token",
        confidence="exact",
    )


async def _count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(E911ResolutionLog))).scalar_one()


async def test_sweep_drops_only_rows_past_retention(db_session: AsyncSession) -> None:
    db_session.add_all([_row(DEFAULT_RETENTION_DAYS + 5), _row(1)])
    await db_session.commit()
    assert await _sweep() == 1
    assert await _sweep() == 0  # idempotent
    assert await _count(db_session) == 1


async def test_sweep_honours_the_retention_setting(db_session: AsyncSession) -> None:
    row = await _settings_row(db_session)
    row.e911_resolution_log_retention_days = 10
    # 20 days old: kept under the 90-day default, dropped under a 10-day setting.
    db_session.add_all([_row(20), _row(1)])
    await db_session.commit()
    assert await _sweep() == 1
    assert await _count(db_session) == 1


async def test_log_budget_is_the_given_limit() -> None:
    from app.core import auth_throttle

    class FakeRedis:
        n = 0

        async def eval(self, *a):  # type: ignore[no-untyped-def]
            FakeRedis.n += 1
            return FakeRedis.n

        async def aclose(self) -> None:
            pass

    with patch.object(auth_throttle, "make_async_redis", lambda *a, **k: FakeRedis()):
        results = [await auth_throttle.e911_lookup_log_rate_limited("t", 3) for _ in range(5)]
    assert results == [False, False, False, True, True]


async def test_log_budget_fails_open_when_redis_is_down() -> None:
    from app.core import auth_throttle

    def boom(*a, **k):  # type: ignore[no-untyped-def]
        raise ConnectionError("redis down")

    with patch.object(auth_throttle, "make_async_redis", boom):
        assert await auth_throttle.e911_lookup_log_rate_limited("t", 1) is False


@pytest.mark.asyncio
async def test_budget_setting_round_trips_and_is_bounded(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    await _settings_row(db_session)
    r = await client.get("/api/v1/settings", headers=headers)
    assert r.json()["e911_lookup_log_budget_per_minute"] == 120
    for bad in (0, 6001):
        r = await client.put(
            "/api/v1/settings", headers=headers, json={"e911_lookup_log_budget_per_minute": bad}
        )
        assert r.status_code == 422, bad
    r = await client.put(
        "/api/v1/settings", headers=headers, json={"e911_lookup_log_budget_per_minute": 30}
    )
    assert r.status_code == 200, r.text
    assert r.json()["e911_lookup_log_budget_per_minute"] == 30
    db_session.expire_all()
    row = await db_session.get(PlatformSettings, 1)
    assert row is not None and row.e911_lookup_log_budget_per_minute == 30
