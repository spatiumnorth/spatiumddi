"""#3039: a grant scoped to ONE space / block / customer / site / provider reaches
that item (read, and with write, edit) and nothing else of its type."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.ownership import Customer, Provider, Site


async def _holder(db: AsyncSession, permissions: list[dict], superadmin: bool = False) -> dict:
    user = User(
        username=f"sc-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="scoped",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _rw(rtype: str, rid: uuid.UUID) -> list[dict]:
    return [
        {"action": a, "resource_type": rtype, "resource_id": str(rid)} for a in ("read", "write")
    ]


@pytest.mark.asyncio
async def test_space_scoped_grant(db_session: AsyncSession, client: AsyncClient) -> None:
    x = IPSpace(name=f"x-{uuid.uuid4().hex[:6]}")
    y = IPSpace(name=f"y-{uuid.uuid4().hex[:6]}")
    db_session.add_all([x, y])
    await db_session.flush()
    blk = IPBlock(space_id=x.id, network="10.0.0.0/16", name="b")
    db_session.add(blk)
    h = await _holder(db_session, _rw("ip_space", x.id))
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()

    assert (await client.get(f"/api/v1/ipam/spaces/{x.id}", headers=h)).status_code == 200
    r = await client.put(f"/api/v1/ipam/spaces/{x.id}", json={"description": "mine"}, headers=h)
    assert r.status_code == 200, r.text
    lst = await client.get("/api/v1/ipam/spaces", headers=h)
    assert lst.status_code == 200
    assert [s["id"] for s in lst.json()] == [str(x.id)]
    # Y and everything inside / beside X stays closed.
    assert (await client.get(f"/api/v1/ipam/spaces/{y.id}", headers=h)).status_code == 403
    r = await client.put(f"/api/v1/ipam/spaces/{y.id}", json={"description": "no"}, headers=h)
    assert r.status_code == 403
    assert (await client.get(f"/api/v1/ipam/blocks/{blk.id}", headers=h)).status_code == 403
    assert (await client.get("/api/v1/ipam/blocks", headers=h)).status_code == 403
    assert (await client.delete(f"/api/v1/ipam/spaces/{x.id}", headers=h)).status_code == 403
    # A binding to another resource is not the grant's to change.
    r = await client.put(
        f"/api/v1/ipam/spaces/{x.id}", json={"customer_id": str(uuid.uuid4())}, headers=h
    )
    assert r.status_code == 403
    # Superadmin unaffected.
    assert (await client.get(f"/api/v1/ipam/spaces/{y.id}", headers=sa)).status_code == 200
    assert len((await client.get("/api/v1/ipam/spaces", headers=sa)).json()) >= 2


@pytest.mark.asyncio
async def test_block_scoped_grant(db_session: AsyncSession, client: AsyncClient) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    x = IPBlock(space_id=space.id, network="10.0.0.0/16", name="x")
    y = IPBlock(space_id=space.id, network="10.9.0.0/16", name="y")
    db_session.add_all([x, y])
    await db_session.flush()
    child = IPBlock(space_id=space.id, network="10.0.1.0/24", name="c", parent_block_id=x.id)
    sub = Subnet(space_id=space.id, block_id=x.id, network="10.0.5.0/24", name="s")
    db_session.add_all([child, sub])
    h = await _holder(db_session, _rw("ip_block", x.id))
    ro = await _holder(
        db_session, [{"action": "read", "resource_type": "ip_block", "resource_id": str(x.id)}]
    )
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()

    assert (await client.get(f"/api/v1/ipam/blocks/{x.id}", headers=h)).status_code == 200
    r = await client.put(f"/api/v1/ipam/blocks/{x.id}", json={"description": "mine"}, headers=h)
    assert r.status_code == 200, r.text
    lst = await client.get("/api/v1/ipam/blocks", headers=h)
    assert lst.status_code == 200
    assert [b["id"] for b in lst.json()] == [str(x.id)]
    # Y, the child block and the subnet inside X are not X.
    for other in (y.id, child.id):
        assert (await client.get(f"/api/v1/ipam/blocks/{other}", headers=h)).status_code == 403
        r = await client.put(f"/api/v1/ipam/blocks/{other}", json={"description": "no"}, headers=h)
        assert r.status_code == 403
    assert (await client.get(f"/api/v1/ipam/subnets/{sub.id}", headers=h)).status_code == 403
    assert (await client.get("/api/v1/ipam/spaces", headers=h)).status_code == 403
    assert (await client.delete(f"/api/v1/ipam/blocks/{x.id}", headers=h)).status_code == 403
    # Re-parenting X touches a block the grant does not name.
    r = await client.put(
        f"/api/v1/ipam/blocks/{child.id}", json={"parent_block_id": str(y.id)}, headers=h
    )
    assert r.status_code == 403
    r = await client.put(
        f"/api/v1/ipam/blocks/{x.id}", json={"site_id": str(uuid.uuid4())}, headers=h
    )
    assert r.status_code == 403
    # Read-only grant cannot write.
    assert (await client.get(f"/api/v1/ipam/blocks/{x.id}", headers=ro)).status_code == 200
    r = await client.put(f"/api/v1/ipam/blocks/{x.id}", json={"description": "n"}, headers=ro)
    assert r.status_code == 403
    # Superadmin unaffected.
    assert (await client.get(f"/api/v1/ipam/blocks/{y.id}", headers=sa)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rtype", "url", "make", "body"),
    [
        ("customer", "customers", lambda n: Customer(name=n), {"notes": "mine"}),
        ("site", "sites", lambda n: Site(name=n), {"notes": "mine"}),
        ("provider", "providers", lambda n: Provider(name=n), {"notes": "mine"}),
    ],
)
async def test_ownership_scoped_grant(
    db_session: AsyncSession, client: AsyncClient, rtype: str, url: str, make, body: dict
) -> None:
    x = make(f"x-{uuid.uuid4().hex[:6]}")
    y = make(f"y-{uuid.uuid4().hex[:6]}")
    db_session.add_all([x, y])
    await db_session.flush()
    h = await _holder(db_session, _rw(rtype, x.id))
    sa = await _holder(db_session, [], superadmin=True)
    await db_session.commit()

    base = f"/api/v1/{url}"
    g = await client.get(f"{base}/{x.id}", headers=h)
    assert g.status_code == 200, g.text
    r = await client.put(f"{base}/{x.id}", json=body, headers=h)
    assert r.status_code == 200, r.text
    lst = await client.get(base, headers=h)
    assert lst.status_code == 200, lst.text
    assert [i["id"] for i in lst.json()["items"]] == [str(x.id)]
    assert lst.json()["total"] == 1
    assert (await client.get(f"{base}/{y.id}", headers=h)).status_code == 403
    assert (await client.put(f"{base}/{y.id}", json=body, headers=h)).status_code == 403
    assert (await client.delete(f"{base}/{x.id}", headers=h)).status_code == 403
    assert (await client.post(base, json={"name": "new"}, headers=h)).status_code == 403
    assert (await client.get(f"{base}/{y.id}", headers=sa)).status_code == 200
    assert lst.json()["total"] == 1
    assert (await client.get(base, headers=sa)).json()["total"] >= 2


@pytest.mark.asyncio
async def test_scoped_customer_cannot_reach_summary_or_other_types(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    x = Customer(name=f"x-{uuid.uuid4().hex[:6]}")
    db_session.add(x)
    await db_session.flush()
    h = await _holder(db_session, _rw("customer", x.id))
    await db_session.commit()
    assert (await client.get(f"/api/v1/customers/{x.id}/summary", headers=h)).status_code == 403
    assert (await client.get("/api/v1/sites", headers=h)).status_code == 403
