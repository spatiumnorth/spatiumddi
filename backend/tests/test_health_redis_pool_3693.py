"""#3693 — the health probes reuse one pooled Redis client.

``/health/ready`` built a client (a fresh connection pool) on every call and
closed it again, so every probe paid a TCP connect plus redis-py's connect
handshake for one PING. Measured on one api CPU at 16 concurrent clients:
237 rps with redis-py 6.4.0 and 176 with 8.1.0 before, ~300 / ~286 after.
These tests pin the observable half: N probes construct ONE client and close
none, a failing Redis still answers 503, and a client never crosses loops.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest
from httpx import AsyncClient

from app.core import redis_client


class _CountingFactory:
    def __init__(self, fail: bool = False) -> None:
        self.built = 0
        self.closed = 0
        self.pings = 0
        self.fail = fail

    def __call__(self, *_a: Any, **_k: Any) -> Any:
        self.built += 1
        factory = self

        class _Client:
            async def ping(self) -> bool:
                factory.pings += 1
                if factory.fail:
                    raise ConnectionError("redis is down")
                return True

            async def get(self, _key: str) -> None:
                return None

            async def aclose(self) -> None:
                factory.closed += 1

        return _Client()


@pytest.mark.asyncio
async def test_readiness_probes_share_one_redis_client(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory = _CountingFactory()
    monkeypatch.setattr(redis_client, "make_async_redis", factory)

    for _ in range(5):
        resp = await client.get("/health/ready")
        assert resp.json()["checks"]["redis"] == "ok"

    assert factory.pings == 5
    assert factory.built == 1, "each probe built its own client (a new connection pool)"
    assert factory.closed == 0, "the shared client must not be closed by a probe"


@pytest.mark.asyncio
async def test_readiness_still_fails_when_redis_is_down(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory = _CountingFactory(fail=True)
    monkeypatch.setattr(redis_client, "make_async_redis", factory)

    for _ in range(2):
        resp = await client.get("/health/ready")
        assert resp.status_code == 503
        assert resp.json()["checks"]["redis"].startswith("error:")
    assert factory.built == 1


@pytest.mark.asyncio
async def test_shared_client_is_per_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """An asyncio connection cannot be used from another loop, so a second
    loop (a second worker thread, a test's own loop) gets its own client."""
    factory = _CountingFactory()
    monkeypatch.setattr(redis_client, "make_async_redis", factory)

    async def _get() -> Any:
        return redis_client.shared_async_redis("redis://x:6379/0", socket_timeout=2)

    here = await _get()
    assert await _get() is here

    other: list[Any] = []
    t = threading.Thread(target=lambda: other.append(asyncio.run(_get())))
    t.start()
    t.join()

    assert other[0] is not here
    assert factory.built == 2
