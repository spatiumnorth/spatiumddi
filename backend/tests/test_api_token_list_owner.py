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
