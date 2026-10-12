"""An administrator can admit a new external user with auto-create off (#1291).

``POST /users`` created local accounts only, and ``link-provider`` refuses a
local account, so a provider with ``auto_create_users`` off could sign in only
the accounts it already had: a new employee was refused permanently. Now
``POST /users`` with ``auth_provider_id`` and no password creates a pending
account bound to that provider, which the user's first sign-in claims.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.user_sync import ExternalAuthResult, ExternalSyncRejected, sync_external_user
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, User
from app.models.auth_provider import AuthGroupMapping, AuthProvider


async def _provider(db: AsyncSession, *, auto_create: bool = False) -> AuthProvider:
    group = Group(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(group)
    await db.flush()
    provider = AuthProvider(
        name=f"ldap-{uuid.uuid4().hex[:8]}",
        type="ldap",
        is_enabled=True,
        config={},
        auto_create_users=auto_create,
        auto_update_users=True,
    )
    db.add(provider)
    await db.flush()
    db.add(
        AuthGroupMapping(
            provider_id=provider.id, external_group="staff", internal_group_id=group.id
        )
    )
    await db.flush()
    return provider


async def _headers(db: AsyncSession) -> dict[str, str]:
    admin = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Admin",
        hashed_password=hash_password("pw-1291"),
        is_superadmin=True,
    )
    db.add(admin)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}


def _subject(external_id: str, username: str) -> ExternalAuthResult:
    return ExternalAuthResult(
        external_id=external_id,
        username=username,
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name=username,
        groups=["staff"],
    )


def _body(provider: AuthProvider | None, **extra: object) -> dict[str, object]:
    body: dict[str, object] = {
        "username": f"new-{uuid.uuid4().hex[:6]}",
        "email": f"{uuid.uuid4().hex[:8]}@example.com",
        "display_name": "New Starter",
        **extra,
    }
    if provider is not None:
        body["auth_provider_id"] = str(provider.id)
    return body


@pytest.mark.asyncio
async def test_a_precreated_account_is_claimed_by_the_first_sign_in(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    provider = await _provider(db_session, auto_create=False)
    headers = await _headers(db_session)
    await db_session.commit()
    body = _body(provider)

    resp = await client.post("/api/v1/users", headers=headers, json=body)

    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert created["auth_source"] == "ldap"
    assert created["auth_provider_id"] == str(provider.id)
    user = await sync_external_user(db_session, provider, _subject("CN=new,DC=a", body["username"]))  # type: ignore[arg-type]
    assert str(user.id) == created["id"]
    assert user.external_id == "CN=new,DC=a"
    assert user.hashed_password is None
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "user", AuditLog.resource_id == created["id"]
            )
        )
    ).scalar_one()
    assert audit.new_value["auth_provider_id"] == str(provider.id)


@pytest.mark.asyncio
async def test_without_it_auto_create_off_refuses_the_user(db_session: AsyncSession) -> None:
    provider = await _provider(db_session, auto_create=False)
    await db_session.commit()
    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, provider, _subject("CN=x,DC=a", "nobody-yet"))
    assert exc.value.reason == "auto_create_disabled"


@pytest.mark.asyncio
async def test_the_same_username_through_another_provider_is_still_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    mine = await _provider(db_session)
    other = await _provider(db_session, auto_create=True)
    headers = await _headers(db_session)
    await db_session.commit()
    body = _body(mine)
    assert (await client.post("/api/v1/users", headers=headers, json=body)).status_code == 201

    with pytest.raises(ExternalSyncRejected) as exc:
        await sync_external_user(db_session, other, _subject("CN=y,DC=b", body["username"]))  # type: ignore[arg-type]
    assert exc.value.reason == "username_collision"


@pytest.mark.asyncio
async def test_password_and_provider_are_exclusive(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    provider = await _provider(db_session)
    headers = await _headers(db_session)
    await db_session.commit()

    both = await client.post(
        "/api/v1/users", headers=headers, json=_body(provider, password="Some-pw-1291!")
    )
    neither = await client.post("/api/v1/users", headers=headers, json=_body(None))
    unknown = await client.post(
        "/api/v1/users",
        headers=headers,
        json={**_body(None), "auth_provider_id": str(uuid.uuid4())},
    )

    assert both.status_code == 422, both.text
    assert neither.status_code == 422, neither.text
    assert unknown.status_code == 422, unknown.text


@pytest.mark.asyncio
async def test_a_precreated_superadmin_needs_the_step_up(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.api.stepup as stepup

    async def _not_blocked(_user_id: object) -> bool:
        return False

    monkeypatch.setattr(stepup, "stepup_password_blocked", _not_blocked)
    provider = await _provider(db_session)
    headers = await _headers(db_session)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/users", headers=headers, json=_body(provider, is_superadmin=True)
    )

    assert resp.status_code == 403, resp.text
