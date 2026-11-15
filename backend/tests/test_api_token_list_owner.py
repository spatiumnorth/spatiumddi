"""#2443: the token list names each token's owner, so a superadmin can tell them apart."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.models.settings import PlatformSettings


async def _user(db: AsyncSession, name: str, *, admin: bool) -> User:
    u = User(
        username=f"{name}-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name=f"Display {name}",
        hashed_password=hash_password("x"),
        is_superadmin=admin,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    db.add(u)
    await db.flush()
    return u


async def _token(db: AsyncSession, owner: User, name: str) -> APIToken:
    raw, _p, h = generate_api_token()
    t = APIToken(
        name=name,
        token_hash=h,
        prefix=raw[:10],
        scope="user",
        scopes=[],
        user_id=owner.id,
        created_by_user_id=owner.id,
    )
    db.add(t)
    await db.flush()
    return t


@pytest.mark.asyncio
async def test_superadmin_list_names_each_owner_and_user_sees_only_own(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    if await db_session.get(PlatformSettings, 1) is None:
        db_session.add(PlatformSettings(id=1))
    admin = await _user(db_session, "adm", admin=True)
    bob = await _user(db_session, "bob", admin=False)
    await _token(db_session, admin, "same-name")
    await _token(db_session, bob, "same-name")
    await db_session.commit()

    h = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    rows = (await client.get("/api/v1/api-tokens", headers=h)).json()
    owners = {r["user_id"]: (r["owner_username"], r["owner_display_name"]) for r in rows}
    assert owners[str(bob.id)] == (bob.username, "Display bob")
    assert owners[str(admin.id)] == (admin.username, "Display adm")

    hb = {"Authorization": f"Bearer {create_access_token(str(bob.id))}"}
    mine = (await client.get("/api/v1/api-tokens", headers=hb)).json()
    assert [r["owner_username"] for r in mine] == [bob.username]


@pytest.mark.asyncio
async def test_token_list_reports_effective_status_3784(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    if await db_session.get(PlatformSettings, 1) is None:
        db_session.add(PlatformSettings(id=1))
    admin = await _user(db_session, "adm", admin=True)
    must = await _user(db_session, "must", admin=False)
    must.force_password_change = True
    off = await _user(db_session, "off", admin=False)
    off.is_active = False
    await _token(db_session, admin, "ok")
    await _token(db_session, must, "pw")
    await _token(db_session, off, "dis")
    revoked = await _token(db_session, admin, "rev")
    revoked.is_active = False
    expired = await _token(db_session, admin, "exp")
    expired.expires_at = datetime(2020, 1, 1, tzinfo=UTC)
    await db_session.commit()

    h = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    rows = {r["name"]: r for r in (await client.get("/api/v1/api-tokens", headers=h)).json()}
    assert {n: r["status"] for n, r in rows.items()} == {
        "ok": "active",
        "pw": "password_change_required",
        "dis": "owner_disabled",
        "rev": "revoked",
        "exp": "expired",
    }
    assert rows["ok"]["blocked_reason"] is None
    assert "change their password" in rows["pw"]["blocked_reason"]
    one = await client.get(f"/api/v1/api-tokens/{rows['pw']['id']}", headers=h)
    assert one.json()["status"] == "password_change_required"
