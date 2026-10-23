"""#2479 — a scope PUT naming another server group is refused, not ignored.

The old ``extra: ignore`` answered 200 and kept the stored group.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet

CIDR = "192.0.2.0/24"


async def _make_token(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _subnet_and_group(db: AsyncSession) -> tuple[Subnet, DHCPServerGroup]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    return subnet, grp


async def _setup(client: AsyncClient, db: AsyncSession) -> tuple[dict, dict, DHCPServerGroup]:
    token = await _make_token(db)
    subnet, grp = await _subnet_and_group(db)
    other = DHCPServerGroup(name=f"g2-{uuid.uuid4().hex[:6]}")
    db.add(other)
    await db.commit()
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "s"},
    )
    assert r.status_code in (200, 201), r.text
    return h, r.json(), other


@pytest.mark.asyncio
async def test_put_with_other_group_is_refused_and_group_kept(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, scope, other = await _setup(client, db_session)
    r = await client.put(
        f"/api/v1/dhcp/scopes/{scope['id']}",
        headers=h,
        json={"group_id": str(other.id), "name": "renamed"},
    )
    assert r.status_code == 422, r.text
    after = (await client.get(f"/api/v1/dhcp/scopes/{scope['id']}", headers=h)).json()
    assert after["group_id"] == scope["group_id"]
    assert after["name"] == "s"  # nothing half-applied


@pytest.mark.asyncio
async def test_put_with_same_group_still_saves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, scope, _ = await _setup(client, db_session)
    r = await client.put(
        f"/api/v1/dhcp/scopes/{scope['id']}",
        headers=h,
        json={"group_id": scope["group_id"], "name": "renamed"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "renamed"
    assert r.json()["group_id"] == scope["group_id"]
