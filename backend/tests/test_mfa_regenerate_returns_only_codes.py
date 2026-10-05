"""Regenerating recovery codes must not hand back the TOTP secret (GHSA-244w-8h9w-g58j).

The regenerate endpoint used the enrolment response model, so every answer
carried the account's existing ``secret`` and ``otpauth_uri`` — the seed of the
second factor, which the UI never reads. Enrolment's own answer still needs it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User, UserSession
from app.services.mfa import encrypt_secret, generate_secret


async def _mfa_user(db: AsyncSession, secret: str) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="u",
        auth_source="local",
        hashed_password=hash_password("pw-123456"),
        totp_enabled=True,
        totp_secret_encrypted=encrypt_secret(secret),
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
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_regenerate_answers_with_the_codes_only(
    client: AsyncClient, db_session: AsyncSession
):
    secret = generate_secret()
    headers = await _mfa_user(db_session, secret)

    r = await client.post(
        "/api/v1/auth/mfa/recovery-codes/regenerate",
        headers=headers,
        json={"password": "pw-123456", "code": pyotp.TOTP(secret).now()},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"recovery_codes"}
    assert body["recovery_codes"]
    assert "secret" not in body and "otpauth_uri" not in body
    # No stretch of the seed rides along in any other field either.
    assert secret[:8] not in r.text and "otpauth" not in r.text


@pytest.mark.asyncio
async def test_regenerate_schema_declares_no_secret(client: AsyncClient):
    spec = (await client.get("/api/openapi.json")).json()
    ref = spec["paths"]["/api/v1/auth/mfa/recovery-codes/regenerate"]["post"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]["$ref"]
    props = spec["components"]["schemas"][ref.rsplit("/", 1)[-1]]["properties"]
    assert set(props) == {"recovery_codes"}


@pytest.mark.asyncio
async def test_enrolment_begin_still_returns_the_secret(
    client: AsyncClient, db_session: AsyncSession
):
    user = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="u",
        auth_source="local",
        hashed_password=hash_password("pw-123456"),
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=f"t-{uuid.uuid4().hex}",
        auth_source="local",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db_session.add(session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id), jti=str(session.id))}"}

    r = await client.post(
        "/api/v1/auth/mfa/enroll/begin", headers=headers, json={"password": "pw-123456"}
    )
    assert r.status_code == 200, r.text
    assert set(r.json()) == {"secret", "otpauth_uri", "recovery_codes"}
