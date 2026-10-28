"""The beat component must not blame beat for a fault it cannot see (#925).

The detail used to read "no heartbeat — beat is stopped". That is an
assertion the check is not able to make: beat *schedules*
``app.tasks.heartbeat.beat_tick`` and a **worker** executes it, so the key
is a round trip and its absence indicts either end.

The wording had a cost. On the reported appliance beat was running
perfectly and the real fault was every worker prefork slot blocked on an
unbounded Redis connect — a state ``inspect ping`` reports as healthy,
because the MainProcess answers it without involving the pool. So the one
red component named the one process that was fine, and the investigation
went there.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from ._signed_in import signed_in_headers


def _beat(body: dict) -> dict:
    return next(c for c in body["components"] if c["name"] == "celery-beat")


class _FakeRedis:
    """Stands in for the platform-health Redis client."""

    def __init__(self, value: str | None) -> None:
        self._value = value

    async def get(self, _key: str) -> bytes | None:
        return self._value.encode() if self._value is not None else None

    async def ping(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_missing_key_does_not_claim_beat_is_stopped(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis(None))
    body = (
        await client.get("/health/platform", headers=await signed_in_headers(db_session))
    ).json()
    beat = _beat(body)

    assert beat["status"] == "error"
    detail = beat["detail"].lower()
    assert "beat is stopped" not in detail, "re-asserting a fault the check cannot see"
    # It must name the other suspect, or the reader draws the old conclusion.
    assert "worker" in detail


@pytest.mark.asyncio
async def test_fresh_tick_is_ok(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    stamp = datetime.now(UTC).isoformat()
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis(stamp))
    beat = _beat(
        (await client.get("/health/platform", headers=await signed_in_headers(db_session))).json()
    )
    assert beat["status"] == "ok"


@pytest.mark.asyncio
async def test_stale_tick_warns(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    stamp = (datetime.now(UTC) - timedelta(seconds=300)).isoformat()
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis(stamp))
    beat = _beat(
        (await client.get("/health/platform", headers=await signed_in_headers(db_session))).json()
    )
    assert beat["status"] == "warn"
    assert "stalled" in beat["detail"]


@pytest.mark.asyncio
async def test_small_forward_skew_renders_sensibly(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sub-threshold skew between two nodes is normal and stays ``ok`` — but
    it must not render as ``last tick -45s ago``, which is nonsense on a
    dashboard and was what the bare subtraction produced."""
    stamp = (datetime.now(UTC) + timedelta(seconds=45)).isoformat()
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis(stamp))
    beat = _beat(
        (await client.get("/health/platform", headers=await signed_in_headers(db_session))).json()
    )
    assert beat["status"] == "ok"
    assert "-" not in beat["detail"], beat["detail"]


@pytest.mark.asyncio
async def test_tick_stamped_in_the_future_is_not_reported_healthy(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clock skew between the node that ran the tick and this one.

    The plain ``age_s > 90`` test read a future stamp as perfectly fresh, so
    a skewed worker clock could mask a beat that had genuinely stopped —
    the age only grows back through the window once the skew is exceeded.
    """
    stamp = (datetime.now(UTC) + timedelta(seconds=600)).isoformat()
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis(stamp))
    beat = _beat(
        (await client.get("/health/platform", headers=await signed_in_headers(db_session))).json()
    )
    assert beat["status"] == "warn"
    assert "skew" in beat["detail"]
