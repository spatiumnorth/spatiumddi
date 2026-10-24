"""#2650 — a scope's PXE profile must belong to the scope's server group."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPXEProfile, DHCPServerGroup
from tests.test_dhcp_scope_group_immutable_2479 import _make_token, _subnet_and_group


async def _create(client: AsyncClient, db: AsyncSession):
    token = await _make_token(db)
    subnet, grp = await _subnet_and_group(db)
    await db.commit()
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "s"},
    )
    assert r.status_code in (200, 201), r.text
    return h, r.json(), grp


async def _profile(db: AsyncSession, grp: DHCPServerGroup) -> DHCPPXEProfile:
    p = DHCPPXEProfile(group_id=grp.id, name=f"p-{uuid.uuid4().hex[:6]}", next_server="10.0.0.5")
    db.add(p)
    await db.commit()
    return p


async def test_pxe_profile_from_other_group_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, scope, _ = await _create(client, db_session)
    other = DHCPServerGroup(name=f"o-{uuid.uuid4().hex[:6]}")
    db_session.add(other)
    await db_session.flush()
    prof = await _profile(db_session, other)
    r = await client.put(
        f"/api/v1/dhcp/scopes/{scope['id']}", headers=h, json={"pxe_profile_id": str(prof.id)}
    )
    assert r.status_code == 422, r.text
    got = (await client.get(f"/api/v1/dhcp/scopes/{scope['id']}", headers=h)).json()
    assert got["pxe_profile_id"] is None


async def test_pxe_profile_from_same_group_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, scope, grp = await _create(client, db_session)
    prof = await _profile(db_session, grp)
    r = await client.put(
        f"/api/v1/dhcp/scopes/{scope['id']}", headers=h, json={"pxe_profile_id": str(prof.id)}
    )
    assert r.status_code == 200, r.text
    assert r.json()["pxe_profile_id"] == str(prof.id)
