"""Rate-limit counters can never be left without an expiry (#2294).

The login, E911 self-query, step-up and network-tools limiters used to
``INCR`` and then ``EXPIRE`` in a second command. An interruption between the
two left a counting key with no TTL, which then throttled that IP / user
forever. Asserted against real Redis: a TTL-less key is repaired by the next
call, and the window still starts at the first hit.
"""

from __future__ import annotations

import uuid

import pytest

import app.core.auth_throttle as throttle
from app.config import settings
from app.core.redis_client import make_async_redis
from app.services.nettools import throttle as nettools_throttle
from app.services.nettools.budgets import WINDOW_SECONDS, budget_key


@pytest.fixture
async def redis_client():  # type: ignore[no-untyped-def]
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    keys: list[str] = []
    try:
        yield r, keys
        if keys:
            await r.delete(*keys)
    finally:
        await r.aclose()


@pytest.mark.asyncio
async def test_login_counter_gets_a_window_and_repairs_a_ttl_less_key(redis_client) -> None:  # type: ignore[no-untyped-def]
    r, keys = redis_client
    ip = f"198.51.100.{uuid.uuid4().int % 250}-{uuid.uuid4().hex[:6]}"
    key = f"login_rl:{ip}"
    keys.append(key)

    assert await throttle.login_rate_limited(ip) is False
    assert 0 < await r.ttl(key) <= throttle._LOGIN_RL_WINDOW_SECONDS

    await r.persist(key)  # the crash between INCR and EXPIRE
    assert await r.ttl(key) == -1
    await throttle.login_rate_limited(ip)
    assert 0 < await r.ttl(key) <= throttle._LOGIN_RL_WINDOW_SECONDS
    assert int(await r.get(key)) == 2


@pytest.mark.asyncio
async def test_login_window_is_fixed_not_sliding(redis_client) -> None:  # type: ignore[no-untyped-def]
    r, keys = redis_client
    ip = f"203.0.113.{uuid.uuid4().hex[:6]}"
    key = f"login_rl:{ip}"
    keys.append(key)
    await throttle.login_rate_limited(ip)
    await r.expire(key, 7)
    await throttle.login_rate_limited(ip)
    assert 0 < await r.ttl(key) <= 7  # later hits do not extend the window


@pytest.mark.asyncio
async def test_login_limit_trips_after_the_budget(redis_client) -> None:  # type: ignore[no-untyped-def]
    _r, keys = redis_client
    ip = f"192.0.2.{uuid.uuid4().hex[:6]}"
    keys.append(f"login_rl:{ip}")
    results = [await throttle.login_rate_limited(ip) for _ in range(throttle._LOGIN_RL_MAX + 1)]
    assert results[:-1] == [False] * throttle._LOGIN_RL_MAX
    assert results[-1] is True


@pytest.mark.asyncio
async def test_e911_counter_repairs_a_ttl_less_key(redis_client) -> None:  # type: ignore[no-untyped-def]
    r, keys = redis_client
    ip = f"192.0.2.{uuid.uuid4().hex[:6]}"
    key = f"e911_self_rl:{ip}"
    keys.append(key)
    await r.set(key, 4)  # no TTL
    assert await throttle.e911_self_query_rate_limited(ip) is False
    assert 0 < await r.ttl(key) <= throttle._E911_SELF_RL_WINDOW_SECONDS
    assert int(await r.get(key)) == 5


@pytest.mark.asyncio
async def test_stepup_claim_and_failure_repair_a_ttl_less_key(redis_client) -> None:  # type: ignore[no-untyped-def]
    r, keys = redis_client
    uid = uuid.uuid4()
    key = throttle._stepup_key(uid)
    keys.append(key)

    await r.set(key, 1)  # no TTL
    assert await throttle.claim_stepup_attempt(uid) is True
    assert 0 < await r.ttl(key) <= throttle._STEPUP_FAIL_WINDOW_SECONDS

    await r.persist(key)
    await throttle.record_stepup_password_failure(uid)
    assert 0 < await r.ttl(key) <= throttle._STEPUP_FAIL_WINDOW_SECONDS
    assert int(await r.get(key)) == 3


@pytest.mark.asyncio
async def test_stepup_claim_stays_within_budget_then_refuses(redis_client) -> None:  # type: ignore[no-untyped-def]
    _r, keys = redis_client
    uid = uuid.uuid4()
    keys.append(throttle._stepup_key(uid))
    got = [await throttle.claim_stepup_attempt(uid) for _ in range(throttle._STEPUP_FAIL_MAX + 1)]
    assert got == [True] * throttle._STEPUP_FAIL_MAX + [False]


@pytest.mark.asyncio
async def test_nettools_counter_repairs_a_ttl_less_key(redis_client) -> None:  # type: ignore[no-untyped-def]
    r, keys = redis_client
    user = str(uuid.uuid4())
    key = budget_key("default", user)
    keys.append(key)
    await r.set(key, 2)  # no TTL
    assert await nettools_throttle.consume_budget(user, "default") is False
    assert 0 < await r.ttl(key) <= WINDOW_SECONDS
    assert int(await r.get(key)) == 3


@pytest.mark.asyncio
async def test_fail_modes_on_redis_error_are_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    def _down(*_a, **_kw):  # type: ignore[no-untyped-def]
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(throttle, "make_async_redis", _down)
    monkeypatch.setattr(nettools_throttle, "make_async_redis", _down)
    assert await throttle.login_rate_limited("192.0.2.1") is False  # open
    assert await throttle.e911_self_query_rate_limited("192.0.2.1") is True  # closed
    assert await nettools_throttle.consume_budget("u", "default") is False  # open
    with pytest.raises(throttle.StepupThrottleUnavailable):  # closed
        await throttle.claim_stepup_attempt(uuid.uuid4())
    await throttle.record_stepup_password_failure(uuid.uuid4())  # best effort, no raise
