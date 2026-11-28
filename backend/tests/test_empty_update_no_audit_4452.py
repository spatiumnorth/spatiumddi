"""An update that changes nothing writes no audit row (#4452).

The Role and Group dialogs sent ``{}`` on an untouched Save and the handlers
wrote an "updated" audit row for it. The same shape sat in the user update.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"a{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("Empty-update-4452!"),
        auth_source="local",
        is_superadmin=True,
        is_active=True,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _updates(db: AsyncSession, resource_type: str, resource_id: str) -> int:
    rows = (
        await db.execute(
            select(AuditLog).where(
                AuditLog.resource_type == resource_type,
                AuditLog.resource_id == resource_id,
                AuditLog.action == "update",
            )
        )
    ).scalars()
    return len(list(rows))


@pytest.mark.asyncio
async def test_empty_role_update_writes_no_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _admin(db_session)
    role = Role(
        name=f"r{uuid.uuid4().hex[:6]}",
        description="d",
        is_builtin=False,
        permissions=[{"action": "read", "resource_type": "subnet"}],
    )
    db_session.add(role)
    await db_session.commit()
    url = f"/api/v1/roles/{role.id}"

    res = await client.put(url, json={}, headers=h)
    assert res.status_code == 200, res.text
    # The whole form resent unchanged is no change either.
    res = await client.put(
        url,
        json={
            "name": role.name,
            "description": "d",
            "permissions": [{"action": "read", "resource_type": "subnet"}],
        },
        headers=h,
    )
    assert res.status_code == 200, res.text
    assert await _updates(db_session, "role", str(role.id)) == 0

    res = await client.put(url, json={"description": "new"}, headers=h)
    assert res.status_code == 200, res.text
    assert await _updates(db_session, "role", str(role.id)) == 1


@pytest.mark.asyncio
async def test_empty_group_update_writes_no_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _admin(db_session)
    group = Group(name=f"g{uuid.uuid4().hex[:6]}", description="d", auth_source="local")
    group.roles = []
    group.users = []
    db_session.add(group)
    await db_session.commit()
    url = f"/api/v1/groups/{group.id}"

    res = await client.put(url, json={}, headers=h)
    assert res.status_code == 200, res.text
    res = await client.put(
        url,
        json={"name": group.name, "description": "d", "role_ids": [], "user_ids": []},
        headers=h,
    )
    assert res.status_code == 200, res.text
    assert await _updates(db_session, "group", str(group.id)) == 0

    res = await client.put(url, json={"description": "new"}, headers=h)
    assert res.status_code == 200, res.text
    assert await _updates(db_session, "group", str(group.id)) == 1


@pytest.mark.asyncio
async def test_empty_user_update_writes_no_audit_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin, h = await _admin(db_session)
    other = User(
        username=f"o{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="other",
        hashed_password=hash_password("Empty-update-4452!"),
        auth_source="local",
        is_superadmin=False,
        is_active=True,
    )
    other.groups = []
    db_session.add(other)
    await db_session.commit()
    url = f"/api/v1/users/{other.id}"

    res = await client.put(url, json={}, headers=h)
    assert res.status_code == 200, res.text
    res = await client.put(url, json={"display_name": "other", "is_active": True}, headers=h)
    assert res.status_code == 200, res.text
    assert await _updates(db_session, "user", str(other.id)) == 0

    res = await client.put(url, json={"display_name": "renamed"}, headers=h)
    assert res.status_code == 200, res.text
    assert await _updates(db_session, "user", str(other.id)) == 1
