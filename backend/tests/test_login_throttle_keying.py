"""Sign-in budgets that no choice of source address escapes.

* The per-source budget on ``/auth/login`` counts an IPv6 client by its /64
  and an IPv4-mapped address as its IPv4 address, so a host holding a /64
  does not get a fresh budget from every address in it.
* A failed-password ceiling per submitted username (lower-cased, whether or
  not the account exists) and one across the install, both spent before the
  password is checked and refunded on a right one.
* Both fail open when Redis is unreachable.

The Redis-backed cases run against the real Redis the suite uses, with
per-test keys so parallel runs cannot see each other's counts.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.v1.auth.router as auth_router
import app.core.auth_throttle as throttle
from app.config import settings
from app.core.redis_client import make_async_redis
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.auth import User

_LOGIN = "/api/v1/auth/login"
_PW = "Throttle-keying-pw-1!"


# ── Source keying ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("ip", "key"),
    [
        ("192.0.2.10", "192.0.2.10"),
        ("::ffff:192.0.2.10", "192.0.2.10"),
        ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"),
        ("2001:db8:1:2::1", "2001:db8:1:2::/64"),
        ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
        ("fe80::1", "fe80::/64"),
        ("not-an-address", "not-an-address"),
    ],
)
def test_login_throttle_key(ip: str, key: str) -> None:
    assert throttle.login_throttle_key(ip) == key


@pytest.fixture
async def redis_keys():  # type: ignore[no-untyped-def]
    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    keys: list[str] = []
    try:
        yield r, keys
        if keys:
            await r.delete(*keys)
    finally:
        await r.aclose()


def _fresh_prefix() -> str:
    """A random documentation-range /64, so runs never share a key."""
    h = uuid.uuid4().hex
    return f"2001:db8:{h[:4]}:{h[4:8]}"


@pytest.mark.asyncio
async def test_addresses_in_one_v6_prefix_share_one_budget(redis_keys) -> None:  # type: ignore[no-untyped-def]
    _r, keys = redis_keys
    prefix = _fresh_prefix()
    keys.append(f"login_rl:{prefix}::/64")
    results = [
        await throttle.login_rate_limited(f"{prefix}::{i + 1:x}")
        for i in range(throttle._LOGIN_RL_MAX + 1)
    ]
    assert results[:-1] == [False] * throttle._LOGIN_RL_MAX
    assert results[-1] is True


@pytest.mark.asyncio
async def test_a_mapped_v4_address_shares_the_v4_budget(redis_keys) -> None:  # type: ignore[no-untyped-def]
    _r, keys = redis_keys
    ip = f"198.51.100.{uuid.uuid4().int % 250 + 1}"
    keys.append(f"login_rl:{ip}")
    for _ in range(throttle._LOGIN_RL_MAX):
        assert await throttle.login_rate_limited(ip) is False
    assert await throttle.login_rate_limited(f"::ffff:{ip}") is True


# ── Username + install-wide ceilings ─────────────────────────────────────────


@pytest.fixture
def ceilings(monkeypatch: pytest.MonkeyPatch, redis_keys):  # type: ignore[no-untyped-def]
    """Small ceilings and a per-test install-wide key."""
    _r, keys = redis_keys
    global_key = f"login_fail:global:test-{uuid.uuid4().hex}"
    monkeypatch.setattr(throttle, "_LOGIN_FAIL_GLOBAL_KEY", global_key)
    monkeypatch.setattr(settings, "login_fail_max_per_username", 3)
    monkeypatch.setattr(settings, "login_fail_max_global", 5)
    keys.append(global_key)

    def name() -> str:
        n = f"user-{uuid.uuid4().hex[:10]}"
        keys.append(throttle._login_fail_keys(n)[0])
        return n

    return name, global_key


@pytest.mark.asyncio
async def test_username_ceiling_is_case_insensitive(ceilings) -> None:  # type: ignore[no-untyped-def]
    name, _ = ceilings
    n = name()
    for variant in (n, n.upper(), n.title()):
        assert (await throttle.claim_login_attempt(variant)).allowed
    refused = await throttle.claim_login_attempt(n)
    assert refused.allowed is False
    assert 0 < refused.retry_after <= throttle.LOGIN_FAIL_WINDOW_SECONDS


@pytest.mark.asyncio
async def test_a_username_over_its_ceiling_is_not_charged_install_wide(  # type: ignore[no-untyped-def]
    ceilings, redis_keys
) -> None:
    name, global_key = ceilings
    r, _ = redis_keys
    n = name()
    for _ in range(10):
        await throttle.claim_login_attempt(n)
    assert int(await r.get(global_key)) == 3


@pytest.mark.asyncio
async def test_install_wide_ceiling_refuses_fresh_names_and_refunds_them(  # type: ignore[no-untyped-def]
    ceilings, redis_keys
) -> None:
    name, global_key = ceilings
    r, _ = redis_keys
    names = [name() for _ in range(5)]
    for n in names:
        assert (await throttle.claim_login_attempt(n)).allowed
    late = name()
    refused = await throttle.claim_login_attempt(late)
    assert refused.allowed is False
    assert 0 < refused.retry_after <= throttle.LOGIN_FAIL_WINDOW_SECONDS
    # The refused name got its attempt back.
    assert int(await r.get(throttle._login_fail_keys(late)[0]) or 0) == 0
    assert int(await r.get(global_key)) == 6


@pytest.mark.asyncio
async def test_a_refund_returns_both_attempts(ceilings, redis_keys) -> None:  # type: ignore[no-untyped-def]
    name, global_key = ceilings
    r, _ = redis_keys
    n = name()
    claim = await throttle.claim_login_attempt(n)
    assert claim.username_charged and claim.global_charged
    await throttle.refund_login_attempt(n, claim)
    assert int(await r.get(throttle._login_fail_keys(n)[0])) == 0
    assert int(await r.get(global_key)) == 0


@pytest.mark.asyncio
async def test_zero_turns_a_ceiling_off(ceilings, monkeypatch, redis_keys) -> None:  # type: ignore[no-untyped-def]
    name, global_key = ceilings
    r, _ = redis_keys
    monkeypatch.setattr(settings, "login_fail_max_per_username", 0)
    n = name()
    for _ in range(5):
        claim = await throttle.claim_login_attempt(n)
        assert claim.allowed and not claim.username_charged
    assert await r.get(throttle._login_fail_keys(n)[0]) is None
    assert int(await r.get(global_key)) == 5


@pytest.mark.asyncio
async def test_ceilings_fail_open_without_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    def _down(*_a: Any, **_k: Any) -> Any:
        raise ConnectionError("redis unavailable")

    monkeypatch.setattr(throttle, "make_async_redis", _down)
    claim = await throttle.claim_login_attempt("anyone")
    assert claim.allowed and not claim.username_charged and not claim.global_charged
    await throttle.refund_login_attempt("anyone", claim)  # no raise


# ── Through /auth/login ──────────────────────────────────────────────────────


@pytest.fixture
def api_ceilings(ceilings, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    # The suite's client is one address; the per-source budget is not what
    # these cases are about.
    async def _never(_ip: str | None) -> bool:
        return False

    monkeypatch.setattr(auth_router, "login_rate_limited", _never)
    return ceilings


async def _local_user(db: AsyncSession, username: str) -> User:
    user = User(
        username=username,
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Throttle user",
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_active=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user


@pytest.mark.asyncio
async def test_login_refuses_an_existing_and_an_invented_name_alike(  # type: ignore[no-untyped-def]
    client: AsyncClient,
    db_session: AsyncSession,
    api_ceilings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name, _ = api_ceilings
    # Six failures across two names; keep the install-wide ceiling out of it.
    monkeypatch.setattr(settings, "login_fail_max_global", 100)
    real = name()
    await _local_user(db_session, real)
    invented = name()

    answers = {}
    for n in (real, invented):
        for _ in range(3):
            r = await client.post(_LOGIN, json={"username": n, "password": "wrong"})
            assert r.status_code == 401, r.text
        r = await client.post(_LOGIN, json={"username": n, "password": _PW})
        assert r.status_code == 429, r.text
        assert 0 < int(r.headers["Retry-After"]) <= throttle.LOGIN_FAIL_WINDOW_SECONDS
        answers[n] = r.json()
    assert answers[real] == answers[invented]

    reasons = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "login",
                    AuditLog.resource_display == real,
                )
            )
        )
        .scalars()
        .all()
    )
    throttled = [a for a in reasons if (a.new_value or {}).get("reason") == "login_throttled"]
    assert len(throttled) == 1
    assert throttled[0].user_id is None


@pytest.mark.asyncio
async def test_a_right_password_is_not_counted(  # type: ignore[no-untyped-def]
    client: AsyncClient, db_session: AsyncSession, api_ceilings
) -> None:
    name, _ = api_ceilings
    n = name()
    await _local_user(db_session, n)
    for _ in range(6):
        r = await client.post(_LOGIN, json={"username": n, "password": _PW})
        assert r.status_code == 200, r.text
    r = await client.post(_LOGIN, json={"username": n, "password": "wrong"})
    assert r.status_code == 401, r.text
