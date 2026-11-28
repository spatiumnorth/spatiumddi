"""Who may read the platform settings, the groups and the roles.

``GET /settings`` answers a caller holding ``read`` on ``settings`` with the
full document and every other signed-in caller with the reduced
``SettingsPublicResponse`` (the fields the console shell and the ordinary
pages read). ``/groups`` and ``/roles`` need ``read`` on ``group`` / ``role``.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPSpace

_ADMIN_ONLY = (
    "ssh_authorized_keys",
    "snmp_v3_users",
    "syslog_targets",
    "lockout_threshold",
    "apt_sources",
    "ntp_custom_servers",
    "supervisor_registration_enabled",
)


async def _caller(
    db: AsyncSession, permissions: list[dict] | None = None, superadmin: bool = False
) -> dict[str, str]:
    user = User(
        username=f"rs-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Read Scope",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    user.groups = []
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _read(rtype: str) -> list[dict]:
    return [{"action": "read", "resource_type": rtype}]


def test_public_fields_are_a_subset_of_the_full_response() -> None:
    from app.api.v1.settings.router import SettingsPublicResponse, SettingsResponse

    assert set(SettingsPublicResponse.model_fields) < set(SettingsResponse.model_fields)
    for name in _ADMIN_ONLY:
        assert name in SettingsResponse.model_fields
        assert name not in SettingsPublicResponse.model_fields


@pytest.mark.asyncio
async def test_no_roles_gets_the_reduced_settings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _caller(db_session)
    r = await client.get("/api/v1/settings", headers=h)
    assert r.status_code == 200, r.text
    data = r.json()
    for name in _ADMIN_ONLY:
        assert name not in data
    assert "utilization_warn_threshold" in data
    assert "subnet_tree_default_expanded_depth" in data


@pytest.mark.asyncio
async def test_read_on_settings_and_superadmin_get_the_full_settings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    for h in (
        await _caller(db_session, _read("settings")),
        await _caller(db_session, [{"action": "write", "resource_type": "settings"}]),
        await _caller(db_session, superadmin=True),
    ):
        r = await client.get("/api/v1/settings", headers=h)
        assert r.status_code == 200, r.text
        data = r.json()
        for name in _ADMIN_ONLY:
            assert name in data, name


@pytest.mark.asyncio
async def test_resolver_settings_need_read_on_settings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    none = await _caller(db_session)
    reader = await _caller(db_session, _read("settings"))
    assert (await client.get("/api/v1/settings/resolver", headers=none)).status_code == 403
    assert (await client.get("/api/v1/settings/resolver", headers=reader)).status_code == 200


@pytest.mark.parametrize(
    "rtype,path",
    [("group", "/api/v1/groups"), ("role", "/api/v1/roles")],
)
@pytest.mark.asyncio
async def test_groups_and_roles_need_read(
    client: AsyncClient, db_session: AsyncSession, rtype: str, path: str
) -> None:
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}")
    role = Role(name=f"r-{uuid.uuid4().hex[:6]}", permissions=[])
    db_session.add_all([group, role])
    await db_session.commit()
    one = f"{path}/{group.id if rtype == 'group' else role.id}"

    none = await _caller(db_session)
    reader = await _caller(db_session, _read(rtype))
    sa = await _caller(db_session, superadmin=True)
    for url in (path, one):
        assert (await client.get(url, headers=none)).status_code == 403, url
        assert (await client.get(url, headers=reader)).status_code == 200, url
        assert (await client.get(url, headers=sa)).status_code == 200, url


@pytest.mark.asyncio
async def test_space_scoped_grant_cannot_set_the_default_space_flag(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    h = await _caller(
        db_session,
        [
            {"action": a, "resource_type": "ip_space", "resource_id": str(space.id)}
            for a in ("read", "write")
        ],
    )
    r = await client.put(f"/api/v1/ipam/spaces/{space.id}", json={"is_default": True}, headers=h)
    assert r.status_code == 403, r.text
    # Re-sending the current value is not a change.
    r = await client.put(f"/api/v1/ipam/spaces/{space.id}", json={"is_default": False}, headers=h)
    assert r.status_code == 200, r.text
