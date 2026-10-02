"""A started MFA enrolment is bounded: guesses are budgeted and it expires (#1354).

``/mfa/enroll/verify`` had no attempt budget, and a pending enrolment never
expired and survived logout and password change. So an abandoned enrolment
stayed open to unlimited 6-digit guesses from any of the user's sessions, and
a hit turned MFA on with a secret the user never saw.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import _fernet
from app.core.security import create_access_token, hash_password
from app.models.auth import User, UserSession
from app.services.mfa import (
    PENDING_ENROLMENT_TTL,
    encrypt_secret,
    enrolment_pending,
    generate_secret,
)

_PW = "pw-1354-Abcdef!"


async def _user(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"m-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="m",
        auth_source="local",
        hashed_password=hash_password(_PW),
    )
    user.groups = []
    db.add(user)
    await db.flush()
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=f"t-{uuid.uuid4().hex}",
        auth_source="local",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db.add(session)
    await db.commit()
    token = create_access_token(str(user.id), jti=str(session.id))
    return user, {"Authorization": f"Bearer {token}"}


def _budget(monkeypatch: pytest.MonkeyPatch) -> tuple[list[object], dict[str, bool]]:
    import app.api.v1.auth.router as auth_router

    failures: list[object] = []
    blocked = {"now": False}

    async def _record(user_id: object) -> None:
        failures.append(user_id)

    async def _blocked(_user_id: object) -> bool:
        return blocked["now"]

    monkeypatch.setattr(auth_router, "record_stepup_password_failure", _record)
    monkeypatch.setattr(auth_router, "stepup_password_blocked", _blocked)
    return failures, blocked


async def _begin(client: AsyncClient, headers: dict[str, str]) -> str:
    r = await client.post("/api/v1/auth/mfa/enroll/begin", headers=headers, json={"password": _PW})
    assert r.status_code == 200, r.text
    return r.json()["secret"]


@pytest.mark.asyncio
async def test_wrong_codes_are_budgeted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    failures, blocked = _budget(monkeypatch)
    user, headers = await _user(db_session)
    secret = await _begin(client, headers)
    url = "/api/v1/auth/mfa/enroll/verify"

    # 403, not 401: the SPA would resubmit a 401 and spend two attempts.
    r = await client.post(url, headers=headers, json={"code": "000000"})
    assert r.status_code == 403, r.text
    assert failures == [user.id]

    blocked["now"] = True
    r = await client.post(url, headers=headers, json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 429, r.text  # refused before the code is checked
    await db_session.refresh(user)
    assert user.totp_enabled is False


@pytest.mark.asyncio
async def test_an_expired_enrolment_cannot_be_verified(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _budget(monkeypatch)
    user, headers = await _user(db_session)
    secret = generate_secret()
    minted = int(time.time() - PENDING_ENROLMENT_TTL.total_seconds() - 60)
    user.totp_secret_encrypted = _fernet().encrypt_at_time(secret.encode(), minted)
    await db_session.commit()

    status = await client.get("/api/v1/auth/mfa/status", headers=headers)
    assert status.json()["enrolment_pending"] is False

    r = await client.post(
        "/api/v1/auth/mfa/enroll/verify", headers=headers, json={"code": pyotp.TOTP(secret).now()}
    )
    assert r.status_code == 400, r.text
    assert "expired" in r.json()["detail"]
    await db_session.refresh(user)
    assert user.totp_enabled is False
    assert user.totp_secret_encrypted is None


@pytest.mark.asyncio
async def test_a_fresh_enrolment_still_verifies(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    failures, _ = _budget(monkeypatch)
    user, headers = await _user(db_session)
    secret = await _begin(client, headers)
    assert (await client.get("/api/v1/auth/mfa/status", headers=headers)).json()[
        "enrolment_pending"
    ] is True
    r = await client.post(
        "/api/v1/auth/mfa/enroll/verify", headers=headers, json={"code": pyotp.TOTP(secret).now()}
    )
    assert r.status_code == 204, r.text
    assert failures == []
    await db_session.refresh(user)
    assert user.totp_enabled is True


@pytest.mark.asyncio
async def test_logout_abandons_a_pending_enrolment(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _budget(monkeypatch)
    user, headers = await _user(db_session)
    await _begin(client, headers)
    r = await client.post("/api/v1/auth/logout", headers=headers)
    assert r.status_code == 204, r.text
    await db_session.refresh(user)
    assert user.totp_secret_encrypted is None
    assert user.recovery_codes_encrypted is None


@pytest.mark.asyncio
async def test_logout_keeps_an_enabled_second_factor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _user(db_session)
    user.totp_enabled = True
    user.totp_secret_encrypted = encrypt_secret(generate_secret())
    await db_session.commit()
    r = await client.post("/api/v1/auth/logout", headers=headers)
    assert r.status_code == 204, r.text
    await db_session.refresh(user)
    assert user.totp_enabled is True
    assert user.totp_secret_encrypted is not None


@pytest.mark.asyncio
async def test_a_password_change_abandons_a_pending_enrolment(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _budget(monkeypatch)
    user, headers = await _user(db_session)
    await _begin(client, headers)
    r = await client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": _PW, "new_password": "New-pw-1354-Xyz!"},
    )
    assert r.status_code in (200, 204), r.text
    await db_session.refresh(user)
    assert user.totp_secret_encrypted is None


def test_an_unreadable_token_is_not_pending() -> None:
    class _U:
        totp_enabled = False
        totp_secret_encrypted = b"not-a-token"

    assert enrolment_pending(_U()) is False
