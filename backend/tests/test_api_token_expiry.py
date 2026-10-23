"""#2442: a past API-token expiry is refused, never shown as expiring, never authenticates."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.models.settings import PlatformSettings


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    if await db.get(PlatformSettings, 1) is None:
        db.add(PlatformSettings(id=1))
    u = User(
        username=f"exp-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Expiry admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(u)
    await db.commit()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _mk(
    db: AsyncSession, owner: User, *, expires: datetime | None, active: bool = True
) -> tuple[APIToken, str]:
    raw, _p, h = generate_api_token()
    t = APIToken(
        name=f"t-{uuid.uuid4().hex[:6]}",
        token_hash=h,
        prefix=raw[:10],
        scope="user",
        scopes=[],
        user_id=owner.id,
        created_by_user_id=owner.id,
        expires_at=expires,
        is_active=active,
    )
    db.add(t)
    await db.commit()
    return t, raw


@pytest.mark.asyncio
async def test_create_with_past_expiry_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _u, h = await _admin(db_session)
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    r = await client.post(
        "/api/v1/api-tokens",
        json={"name": "past", "expires_at": past, "stepup_password": "x"},
        headers=h,
    )
    assert r.status_code == 422, r.text
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    ok = await client.post(
        "/api/v1/api-tokens",
        json={"name": "future", "expires_at": future, "stepup_password": "x"},
        headers=h,
    )
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_expired_token_is_refused_at_authentication(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    u, _h = await _admin(db_session)
    _t, raw = await _mk(db_session, u, expires=datetime.now(UTC) - timedelta(seconds=5))
    r = await client.get("/api/v1/ipam/spaces", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 401, r.text
    _t2, raw2 = await _mk(db_session, u, expires=datetime.now(UTC) + timedelta(days=5))
    ok = await client.get("/api/v1/ipam/spaces", headers={"Authorization": f"Bearer {raw2}"})
    assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
async def test_dashboard_expiring_counts_only_active_unexpired(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    u, h = await _admin(db_session)
    now = datetime.now(UTC)
    live, _ = await _mk(db_session, u, expires=now + timedelta(days=10))
    await _mk(db_session, u, expires=now - timedelta(hours=1))  # expired
    await _mk(db_session, u, expires=now + timedelta(days=9), active=False)  # revoked
    await _mk(db_session, u, expires=now + timedelta(days=90))  # not near
    r = await client.get("/api/v1/dashboards/security/summary", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_tokens_expiring_count"] == 1
    assert [x["id"] for x in body["api_tokens_expiring"]] == [str(live.id)]
