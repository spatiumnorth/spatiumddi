"""``/health/platform`` must not let anonymous callers exhaust the broker pool.

GHSA-c58p-8cq9-g3gm: the endpoint is unauthenticated, and every request ran
its own ``celery_app.control.inspect().ping()`` in a worker thread. A
broadcast holds one pooled broker connection while it acquires a second for
its producer, and ``asyncio.wait_for`` abandons the request at 3 s without
stopping the thread — so a burst of requests filled kombu's connection pool
with hold-and-wait pings, and the next inline ``.delay()`` on the event loop
blocked forever waiting for a connection. Every request, ``/health/live``
included, then hung until the api was restarted.

Two properties close it: the ping is single-flight with a short result cache
(N concurrent callers cost one broadcast, and a ping still hung past its
timeout is joined rather than duplicated), and acquiring from an exhausted
broker pool raises instead of blocking forever.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest
from httpx import AsyncClient

from app.api import health as health_module


class _FakeRedis:
    async def get(self, _key: str) -> bytes | None:
        return None

    async def ping(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


class _CountingControl:
    """Stands in for ``celery_app.control``; counts broker broadcasts."""

    def __init__(self, delay: float = 0.0, gate: threading.Event | None = None) -> None:
        self.calls = 0
        self._lock = threading.Lock()
        self._delay = delay
        self._gate = gate

    def inspect(self, timeout: float = 1.0) -> _CountingControl:
        return self

    def ping(self) -> dict[str, Any]:
        with self._lock:
            self.calls += 1
        if self._gate is not None:
            self._gate.wait(10)
        if self._delay:
            time.sleep(self._delay)
        return {"celery@w1": {"ok": "pong"}}


@pytest.fixture
def control(monkeypatch: pytest.MonkeyPatch) -> _CountingControl:
    from app.celery_app import celery_app

    ctl = _CountingControl(delay=0.3)
    monkeypatch.setattr(celery_app, "control", ctl)
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis())
    return ctl


def _workers(body: dict) -> dict:
    return next(c for c in body["components"] if c["name"] == "celery-workers")


@pytest.mark.asyncio
async def test_concurrent_requests_share_one_ping(
    client: AsyncClient, control: _CountingControl
) -> None:
    responses = await asyncio.gather(*(client.get("/health/platform") for _ in range(20)))

    assert control.calls == 1, f"{control.calls} broadcasts for 20 concurrent requests"
    for r in responses:
        assert r.status_code == 200
        assert _workers(r.json())["status"] == "ok"
        assert _workers(r.json())["workers"] == ["celery@w1"]


@pytest.mark.asyncio
async def test_result_is_cached_then_refreshed(
    client: AsyncClient, control: _CountingControl, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [1000.0]
    monkeypatch.setattr(health_module, "monotonic", lambda: now[0], raising=True)

    await client.get("/health/platform")
    now[0] += 1.0
    await client.get("/health/platform")
    assert control.calls == 1, "a ping inside the cache window was not reused"

    now[0] += 60.0
    body = (await client.get("/health/platform")).json()
    assert control.calls == 2, "an expired cached ping was not refreshed"
    assert _workers(body)["status"] == "ok"


@pytest.mark.asyncio
async def test_hung_ping_is_joined_not_duplicated(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ping still running past the request timeout must not be re-issued.

    This is the accumulation that filled the pool: each timed-out request
    left its thread behind and the next request started another.
    """
    from app.celery_app import celery_app

    gate = threading.Event()
    ctl = _CountingControl(gate=gate)
    monkeypatch.setattr(celery_app, "control", ctl)
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _FakeRedis())
    monkeypatch.setattr(health_module, "WORKER_PING_TIMEOUT_S", 0.2, raising=False)
    try:
        for _ in range(3):
            body = (await client.get("/health/platform")).json()
            assert _workers(body)["status"] == "error"
            assert _workers(body)["detail"] == "inspect timed out"
        assert ctl.calls == 1, f"{ctl.calls} pings in flight for one hung broker"
    finally:
        gate.set()
    # Let the released thread finish so it does not outlive the test.
    await asyncio.sleep(0.05)


def test_broker_pool_limit_is_explicit() -> None:
    from app.celery_app import BROKER_POOL_LIMIT, celery_app

    assert "broker_pool_limit" in celery_app.conf.changes
    assert celery_app.conf.broker_pool_limit == BROKER_POOL_LIMIT
    assert BROKER_POOL_LIMIT and BROKER_POOL_LIMIT > 0


def test_exhausted_broker_pool_raises_instead_of_hanging(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both pools kombu blocks on (connections and producers) must time out."""
    from kombu import Connection
    from kombu.exceptions import LimitExceeded
    from kombu.pools import ProducerPool

    monkeypatch.setattr("app.celery_app.BROKER_POOL_ACQUIRE_TIMEOUT_S", 0.3)

    conns = Connection("memory://").Pool(limit=1)
    producers = ProducerPool(conns, limit=2)
    held = conns.acquire(block=True)

    outcome: dict[str, Exception | None] = {}

    def _try(name: str, fn: Any) -> None:
        try:
            fn()
            outcome[name] = None
        except Exception as exc:  # noqa: BLE001 — recorded for the assertion
            outcome[name] = exc

    threads = [
        threading.Thread(
            target=_try, args=("conn", lambda: conns.acquire(block=True)), daemon=True
        ),
        # The producer slot is free; preparing it needs a connection, which
        # is the exact acquire the reproduced deadlock was parked in.
        threading.Thread(
            target=_try, args=("producer", lambda: producers.acquire(block=True)), daemon=True
        ),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    try:
        assert not any(t.is_alive() for t in threads), "acquire blocked on an exhausted pool"
        assert isinstance(outcome["conn"], LimitExceeded)
        assert isinstance(outcome["producer"], LimitExceeded)
    finally:
        held.release()
