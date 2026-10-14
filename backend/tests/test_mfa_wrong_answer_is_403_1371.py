"""#1371 — a wrong answer on MFA disable or recovery-code regeneration is a
403, so the console spends one step-up answer on one typo.

``POST /auth/mfa/disable`` and ``/auth/mfa/recovery-codes/regenerate``
answered a wrong password or TOTP code with 401. The console's response
interceptor (``frontend/src/lib/api.ts``) reads a 401 from any path other than
``/auth/login`` and ``/auth/refresh`` as an expired access token: it rotates
the session and sends the request again, which fails the same way. One typo
spent two of the five step-up answers (#1241), checked the password or code
twice and rotated the session, and the third typo blocked the account's MFA
changes for 15 minutes. Enrolment already answers 403 for the same reason
(begin since #1241, verify since #1354); these two now do too.
"""

from __future__ import annotations

import time
import uuid

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.mfa import (
    encrypt_recovery_codes,
    encrypt_secret,
    generate_recovery_codes,
    generate_secret,
)

PATHS = ("/api/v1/auth/mfa/disable", "/api/v1/auth/mfa/recovery-codes/regenerate")
PASSWORD = "pw-123456"


async def _mfa_user(db: AsyncSession, *, local: bool) -> tuple[User, str, dict[str, str]]:
    """A user with MFA on: a local account (password + code) or an external
    one (code only, #408)."""
    secret = generate_secret()
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="u",
        auth_source="local" if local else "oidc",
        hashed_password=hash_password(PASSWORD) if local else None,
        totp_enabled=True,
        totp_secret_encrypted=encrypt_secret(secret),
        recovery_codes_encrypted=encrypt_recovery_codes(generate_recovery_codes()),
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user, secret, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _wrong_code(secret: str) -> str:
    """A 6-digit code no step near now accepts (verify allows one step of
    skew; two are excluded, in case the test crosses a step boundary)."""
    totp, now = pyotp.TOTP(secret), time.time()
    valid = {totp.at(now + 30 * step) for step in range(-2, 3)}
    return next(c for c in ("000000", "111111", "222222", "333333", "444444") if c not in valid)


# (local account, wrong password?, the detail it gets)
WRONG_ANSWERS = [
    pytest.param(True, True, "Invalid credentials", id="local-wrong-password"),
    pytest.param(True, False, "Invalid TOTP code", id="local-wrong-code"),
    pytest.param(False, False, "Invalid TOTP code", id="external-wrong-code"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize(("local", "wrong_password", "detail"), WRONG_ANSWERS)
async def test_a_wrong_answer_is_403_and_counts_once(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    local: bool,
    wrong_password: bool,
    detail: str,
) -> None:
    import app.api.v1.auth.router as auth_router

    failures: list[object] = []

    async def _record(user_id: object) -> None:
        failures.append(user_id)

    monkeypatch.setattr(auth_router, "record_stepup_password_failure", _record)
    user, secret, headers = await _mfa_user(db_session, local=local)
    codes_before = user.recovery_codes_encrypted
    body = {"code": pyotp.TOTP(secret).now() if wrong_password else _wrong_code(secret)}
    if local:
        body["password"] = "nope" if wrong_password else PASSWORD

    resp = await client.post(path, headers=headers, json=body)

    # 403: refused, and nothing the console reads as an expired session.
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == detail
    assert failures == [user.id]
    await db_session.refresh(user)
    assert user.totp_enabled is True
    assert user.recovery_codes_encrypted == codes_before


@pytest.mark.asyncio
@pytest.mark.parametrize("path", PATHS)
async def test_five_wrong_answers_are_403_and_the_sixth_is_429(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    """The real step-up budget: one wrong answer is one attempt, so an
    account gets its five before the 15-minute block, as enrolment does."""
    _, secret, headers = await _mfa_user(db_session, local=True)
    body = {"password": PASSWORD, "code": _wrong_code(secret)}

    answers = [(await client.post(path, headers=headers, json=body)).status_code for _ in range(6)]

    assert answers == [403, 403, 403, 403, 403, 429]
