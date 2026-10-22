"""The MFA step of sign-in honours account lockout and bounds wrong codes.

``/auth/login/mfa`` checks, before the second factor:

* a locked account is refused as ``/login`` refuses it, and a correct code
  never clears an active lock;
* each account has a wrong-code budget (``MFA_FAIL_MAX`` per
  ``MFA_FAIL_WINDOW_MINUTES``) kept on the user row, which applies with
  lockout disabled and with Redis unavailable;
* each challenge accepts ``MFA_CHALLENGE_FAIL_MAX`` wrong codes and is
  single-use on success.

Wrong codes also count towards the lockout counter (#71).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.core.auth_throttle as throttle
from app.core.security import create_mfa_challenge_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.account_lockout import (
    MFA_FAIL_MAX,
    MFA_FAIL_WINDOW_MINUTES,
    mfa_attempts_exhausted,
    register_mfa_failure,
    register_success,
    unlock,
)
from app.services.mfa import (
    encrypt_recovery_codes,
    encrypt_secret,
    generate_recovery_codes,
    generate_secret,
)

_PW = "Mfa-budget-pw-1!"
_LOGIN = "/api/v1/auth/login"
_MFA = "/api/v1/auth/login/mfa"


class _FakeRedis:
    """Just enough of the async redis client for ``auth_throttle``."""

    def __init__(self, store: dict[str, Any]) -> None:
        self.store = store

    async def incr(self, key: str) -> int:
        self.store[key] = int(self.store.get(key, 0)) + 1
        return int(self.store[key])

    async def expire(self, key: str, _ttl: int) -> bool:
        return True

    async def set(self, key: str, value: Any, ex: int | None = None, nx: bool = False) -> bool:
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def get(self, key: str) -> Any:
        return self.store.get(key)

    async def exists(self, key: str) -> int:
        return int(key in self.store)

    async def aclose(self) -> None:
        return None


@pytest.fixture
def redis_state(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"down": False, "store": {}}

    def _make(*_a: Any, **_k: Any) -> _FakeRedis:
        if state["down"]:
            raise ConnectionError("redis unavailable")
        return _FakeRedis(state["store"])

    monkeypatch.setattr(throttle, "make_async_redis", _make)
    return state


async def _settings(db: AsyncSession, threshold: int) -> None:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
    row.lockout_threshold = threshold
    row.lockout_duration_minutes = 15
    row.lockout_reset_minutes = 15
    await db.commit()


async def _mfa_user(db: AsyncSession) -> tuple[User, str, list[str]]:
    secret = generate_secret()
    codes = generate_recovery_codes()
    user = User(
        username=f"mfa-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="MFA user",
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_active=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
        totp_enabled=True,
        totp_secret_encrypted=encrypt_secret(secret),
        recovery_codes_encrypted=encrypt_recovery_codes(codes),
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user, secret, codes


def _right(secret: str) -> str:
    return pyotp.TOTP(secret).now()


def _wrong(secret: str) -> str:
    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    valid = {totp.at(now + timedelta(seconds=s)) for s in (-60, -30, 0, 30, 60)}
    n = int(totp.now())
    while f"{n:06d}" in valid:
        n = (n + 7919) % 1_000_000
    return f"{n:06d}"


async def _challenge(client: AsyncClient, user: User) -> str:
    r = await client.post(_LOGIN, json={"username": user.username, "password": _PW})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mfa_required"] is True
    return str(body["mfa_token"])


async def _reasons(db: AsyncSession, user: User) -> list[str]:
    rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.user_id == user.id, AuditLog.action == "login")
                .order_by(AuditLog.timestamp)
            )
        )
        .scalars()
        .all()
    )
    return [str((row.new_value or {}).get("reason")) for row in rows]


@pytest.mark.asyncio
async def test_wrong_codes_lock_the_account_and_the_right_code_is_then_refused(
    client: AsyncClient, db_session: AsyncSession, redis_state: dict[str, Any]
) -> None:
    await _settings(db_session, threshold=3)
    user, secret, _ = await _mfa_user(db_session)
    token = await _challenge(client, user)

    for _ in range(3):
        r = await client.post(_MFA, json={"mfa_token": token, "code": _wrong(secret)})
        assert r.status_code == 401, r.text

    await db_session.refresh(user)
    assert user.failed_login_locked_until is not None
    locked_until = user.failed_login_locked_until

    # A challenge minted before the lock, redeemed with the right code.
    early = create_mfa_challenge_token(str(user.id))
    for t in (token, early):
        r = await client.post(_MFA, json={"mfa_token": t, "code": _right(secret)})
        assert r.status_code == 403, r.text
        assert "locked" in r.json()["detail"]

    await db_session.refresh(user)
    assert user.failed_login_locked_until == locked_until  # not cleared
    # The password step refuses the locked account too.
    r = await client.post(_LOGIN, json={"username": user.username, "password": _PW})
    assert r.status_code == 403
    assert "account_locked" in await _reasons(db_session, user)


@pytest.mark.asyncio
async def test_a_challenge_is_spent_after_its_wrong_code_budget(
    client: AsyncClient, db_session: AsyncSession, redis_state: dict[str, Any]
) -> None:
    await _settings(db_session, threshold=0)
    user, secret, _ = await _mfa_user(db_session)
    token = await _challenge(client, user)

    for _ in range(throttle.MFA_CHALLENGE_FAIL_MAX):
        r = await client.post(_MFA, json={"mfa_token": token, "code": _wrong(secret)})
        assert r.status_code == 401, r.text
        assert r.json()["detail"] == "Invalid MFA code"

    r = await client.post(_MFA, json={"mfa_token": token, "code": _right(secret)})
    assert r.status_code == 401, r.text
    assert r.json()["detail"] == "Invalid or expired MFA challenge"
    assert "mfa_challenge_spent" in await _reasons(db_session, user)

    # Starting again from the password works.
    fresh = await _challenge(client, user)
    r = await client.post(_MFA, json={"mfa_token": fresh, "code": _right(secret)})
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]


@pytest.mark.asyncio
async def test_a_challenge_is_single_use_on_success(
    client: AsyncClient, db_session: AsyncSession, redis_state: dict[str, Any]
) -> None:
    await _settings(db_session, threshold=0)
    user, secret, _ = await _mfa_user(db_session)
    token = await _challenge(client, user)

    r = await client.post(_MFA, json={"mfa_token": token, "code": _right(secret)})
    assert r.status_code == 200, r.text
    r = await client.post(_MFA, json={"mfa_token": token, "code": _right(secret)})
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_with_lockout_disabled_and_redis_down_the_account_budget_still_holds(
    client: AsyncClient, db_session: AsyncSession, redis_state: dict[str, Any]
) -> None:
    await _settings(db_session, threshold=0)
    user, secret, _ = await _mfa_user(db_session)
    redis_state["down"] = True  # per-challenge budget + replay guard fail open
    token = await _challenge(client, user)

    for _ in range(MFA_FAIL_MAX):
        r = await client.post(_MFA, json={"mfa_token": token, "code": _wrong(secret)})
        assert r.status_code == 401, r.text

    # The right code, on this challenge or a fresh one, is refused.
    fresh = await _challenge(client, user)
    for t in (token, fresh):
        r = await client.post(_MFA, json={"mfa_token": t, "code": _right(secret)})
        assert r.status_code == 429, r.text
        assert int(r.headers["Retry-After"]) > 0

    await db_session.refresh(user)
    assert user.mfa_failed_count == MFA_FAIL_MAX  # refusals are not counted
    assert user.failed_login_locked_until is None  # lockout itself stays off
    assert "mfa_attempts_exhausted" in await _reasons(db_session, user)
    exhausted = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.user_id == user.id,
                    AuditLog.action == "account.mfa_attempts_exhausted",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(exhausted) == 1

    # Once the window has passed, the right code works and resets the budget.
    user.mfa_last_failed_at = datetime.now(UTC) - timedelta(minutes=MFA_FAIL_WINDOW_MINUTES + 1)
    await db_session.commit()
    r = await client.post(_MFA, json={"mfa_token": fresh, "code": _right(secret)})
    assert r.status_code == 200, r.text
    await db_session.refresh(user)
    assert user.mfa_failed_count == 0
    assert user.mfa_last_failed_at is None


@pytest.mark.asyncio
async def test_a_successful_login_resets_the_counters(
    client: AsyncClient, db_session: AsyncSession, redis_state: dict[str, Any]
) -> None:
    await _settings(db_session, threshold=10)
    user, secret, _ = await _mfa_user(db_session)
    token = await _challenge(client, user)

    for _ in range(2):
        r = await client.post(_MFA, json={"mfa_token": token, "code": _wrong(secret)})
        assert r.status_code == 401, r.text
    await db_session.refresh(user)
    assert user.mfa_failed_count == 2
    assert user.failed_login_count == 2  # wrong codes count towards lockout

    r = await client.post(_MFA, json={"mfa_token": token, "code": _right(secret)})
    assert r.status_code == 200, r.text
    await db_session.refresh(user)
    assert user.mfa_failed_count == 0
    assert user.failed_login_count == 0
    assert user.mfa_last_failed_at is None
    assert user.last_failed_login_at is None


@pytest.mark.asyncio
async def test_recovery_codes_follow_the_same_rules(
    client: AsyncClient, db_session: AsyncSession, redis_state: dict[str, Any]
) -> None:
    await _settings(db_session, threshold=3)
    user, _secret, codes = await _mfa_user(db_session)
    token = await _challenge(client, user)

    for i in range(3):
        r = await client.post(_MFA, json={"mfa_token": token, "recovery_code": f"ZZZZ-000{i}"})
        assert r.status_code == 401, r.text
    await db_session.refresh(user)
    assert user.failed_login_locked_until is not None
    assert user.mfa_failed_count == 3
    blob_before = user.recovery_codes_encrypted

    early = create_mfa_challenge_token(str(user.id))
    r = await client.post(_MFA, json={"mfa_token": early, "recovery_code": codes[0]})
    assert r.status_code == 403, r.text
    await db_session.refresh(user)
    assert user.recovery_codes_encrypted == blob_before  # not consumed

    # Unlocked by an admin, the recovery code works and resets everything.
    unlock(user)
    await db_session.commit()
    fresh = await _challenge(client, user)
    r = await client.post(_MFA, json={"mfa_token": fresh, "recovery_code": codes[0]})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_no_code_reaches_the_audit_log(
    client: AsyncClient, db_session: AsyncSession, redis_state: dict[str, Any]
) -> None:
    await _settings(db_session, threshold=0)
    user, secret, codes = await _mfa_user(db_session)
    token = await _challenge(client, user)
    wrong = _wrong(secret)
    r = await client.post(_MFA, json={"mfa_token": token, "code": wrong})
    assert r.status_code == 401
    r = await client.post(_MFA, json={"mfa_token": token, "recovery_code": codes[1]})
    assert r.status_code == 200, r.text

    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.user_id == user.id)))
        .scalars()
        .all()
    )
    dumped = " ".join(f"{row.new_value} {row.old_value}" for row in rows)
    assert wrong not in dumped
    assert codes[1] not in dumped
    assert token not in dumped


def test_account_budget_window_semantics() -> None:
    user = User(username="x", email="x@example.test", mfa_failed_count=0)
    now = datetime.now(UTC)
    for i in range(MFA_FAIL_MAX - 1):
        assert register_mfa_failure(user, now + timedelta(seconds=i)) is False
    assert not mfa_attempts_exhausted(user, now)
    assert register_mfa_failure(user, now + timedelta(seconds=10)) is True
    assert mfa_attempts_exhausted(user, now + timedelta(seconds=11))
    later = now + timedelta(minutes=MFA_FAIL_WINDOW_MINUTES, seconds=11)
    assert not mfa_attempts_exhausted(user, later)
    # A failure after the window starts a fresh count.
    register_mfa_failure(user, later)
    assert user.mfa_failed_count == 1
    register_success(user)
    assert user.mfa_failed_count == 0 and user.mfa_last_failed_at is None
