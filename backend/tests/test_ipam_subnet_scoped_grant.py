"""#2438: a grant scoped to ONE subnet reaches that subnet and its children, nothing else."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _user(db: AsyncSession, permissions: list[dict]) -> dict[str, str]:
    user = User(
        username=f"sc-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="scoped",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _two_subnets(db: AsyncSession) -> tuple[Subnet, Subnet, IPBlock]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    other = IPBlock(space_id=space.id, network="10.9.0.0/16", name="b2")
    db.add_all([block, other])
    await db.flush()
    x = Subnet(space_id=space.id, block_id=block.id, network="10.0.5.0/24", name="x")
    y = Subnet(space_id=space.id, block_id=block.id, network="10.0.6.0/24", name="y")
    db.add_all([x, y])
    await db.commit()
    return x, y, other


def _rw(x: Subnet) -> list[dict]:
    return [
        {"action": "read", "resource_type": "subnet", "resource_id": str(x.id)},
        {"action": "write", "resource_type": "subnet", "resource_id": str(x.id)},
    ]


@pytest.mark.asyncio
async def test_scoped_holder_reads_and_edits_only_its_subnet(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, y, _o = await _two_subnets(db_session)
    h = await _user(db_session, _rw(x))
    await db_session.commit()

    assert (await client.get(f"/api/v1/ipam/subnets/{x.id}", headers=h)).status_code == 200
    r = await client.put(f"/api/v1/ipam/subnets/{x.id}", json={"description": "mine"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["description"] == "mine"
    assert (
        await client.get(f"/api/v1/ipam/subnets/{x.id}/addresses", headers=h)
    ).status_code == 200
    c = await client.post(
        f"/api/v1/ipam/subnets/{x.id}/addresses",
        json={"address": "10.0.5.20", "hostname": "h1"},
        headers=h,
    )
    assert c.status_code == 201, c.text
    lst = await client.get("/api/v1/ipam/subnets", headers=h)
    assert lst.status_code == 200
    assert [s["id"] for s in lst.json()] == [str(x.id)]


@pytest.mark.asyncio
async def test_scoped_grant_does_not_reach_other_subnets_or_aggregates(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, y, other = await _two_subnets(db_session)
    h = await _user(db_session, _rw(x))
    await db_session.commit()

    # The sibling subnet Y: every verb refused.
    assert (await client.get(f"/api/v1/ipam/subnets/{y.id}", headers=h)).status_code == 403
    assert (
        await client.put(f"/api/v1/ipam/subnets/{y.id}", json={"description": "no"}, headers=h)
    ).status_code == 403
    assert (
        await client.get(f"/api/v1/ipam/subnets/{y.id}/addresses", headers=h)
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/ipam/subnets/{y.id}/addresses",
            json={"address": "10.0.6.20", "hostname": "h1"},
            headers=h,
        )
    ).status_code == 403
    # Aggregates and structure above the subnet stay closed.
    assert (await client.get("/api/v1/ipam/spaces", headers=h)).status_code == 403
    assert (await client.get("/api/v1/ipam/blocks", headers=h)).status_code == 403
    # Write routes that are not on the allow-list stay refused even for X.
    assert (await client.delete(f"/api/v1/ipam/subnets/{x.id}", headers=h)).status_code == 403
    assert (
        await client.post(
            f"/api/v1/ipam/subnets/{x.id}/resize", json={"new_network": "10.0.5.0/23"}, headers=h
        )
    ).status_code in (403, 422)
    # Re-parenting X under another block touches a resource the grant does not name.
    mv = await client.put(
        f"/api/v1/ipam/subnets/{x.id}", json={"block_id": str(other.id)}, headers=h
    )
    assert mv.status_code == 403, mv.text


@pytest.mark.asyncio
async def test_scoped_read_only_cannot_write(db_session: AsyncSession, client: AsyncClient) -> None:
    x, _y, _o = await _two_subnets(db_session)
    h = await _user(
        db_session, [{"action": "read", "resource_type": "subnet", "resource_id": str(x.id)}]
    )
    await db_session.commit()
    assert (await client.get(f"/api/v1/ipam/subnets/{x.id}", headers=h)).status_code == 200
    assert (
        await client.put(f"/api/v1/ipam/subnets/{x.id}", json={"description": "n"}, headers=h)
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/ipam/subnets/{x.id}/addresses",
            json={"address": "10.0.5.21", "hostname": "h1"},
            headers=h,
        )
    ).status_code == 403


@pytest.mark.asyncio
async def test_type_level_subnet_read_still_lists_everything(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x, y, _o = await _two_subnets(db_session)
    h = await _user(db_session, [{"action": "read", "resource_type": "subnet"}])
    await db_session.commit()
    ids = {s["id"] for s in (await client.get("/api/v1/ipam/subnets", headers=h)).json()}
    assert {str(x.id), str(y.id)} <= ids
