"""#3892 — VLAN / router / VRF deletes count rows in the Trash.

A subnet (space, block) in the Trash still carries its VLAN (VRF). The FK is
``ON DELETE SET NULL``, so deleting the VLAN cleared the link and a restore did
not bring it back. The deletes now refuse (VRF: unless forced) and say so.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.vlans import VLAN, Router
from app.models.vrf import VRF


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _trashed_subnet_on_vlan(db: AsyncSession) -> tuple[Router, VLAN]:
    router = Router(name=f"r-{uuid.uuid4().hex[:6]}")
    db.add(router)
    await db.flush()
    vlan = VLAN(router_id=router.id, vlan_id=3903, name="v3903")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add_all([vlan, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    sub = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.47.3.0/24",
        name="s",
        vlan_ref_id=vlan.id,
        vlan_id=3903,
    )
    db.add(sub)
    await db.flush()
    await db.execute(
        update(Subnet)
        .where(Subnet.id == sub.id)
        .values(deleted_at=func.now())
        .execution_options(include_deleted=True)
    )
    await db.commit()
    return router, vlan


@pytest.mark.asyncio
async def test_delete_vlan_refused_for_subnet_in_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    _router, vlan = await _trashed_subnet_on_vlan(db_session)
    r = await client.delete(f"/api/v1/vlans/vlans/{vlan.id}", headers=headers)
    assert r.status_code == 409, r.text
    assert "Trash" in r.json()["detail"]


@pytest.mark.asyncio
async def test_delete_router_refused_for_subnet_in_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    router, _vlan = await _trashed_subnet_on_vlan(db_session)
    r = await client.delete(f"/api/v1/vlans/routers/{router.id}", headers=headers)
    assert r.status_code == 409, r.text
    assert "Trash" in r.json()["detail"]


@pytest.mark.asyncio
async def test_delete_vrf_refused_for_block_in_trash_unless_forced(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    vrf = VRF(name=f"v-{uuid.uuid4().hex[:6]}")
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db_session.add_all([vrf, space])
    await db_session.flush()
    blk = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b", vrf_id=vrf.id)
    db_session.add(blk)
    await db_session.flush()
    await db_session.execute(
        update(IPBlock)
        .where(IPBlock.id == blk.id)
        .values(deleted_at=func.now())
        .execution_options(include_deleted=True)
    )
    await db_session.commit()

    r = await client.delete(f"/api/v1/vrfs/{vrf.id}", headers=headers)
    assert r.status_code == 409, r.text
    b = await client.post("/api/v1/vrfs/bulk-delete", headers=headers, json={"ids": [str(vrf.id)]})
    assert b.status_code == 200, b.text
    assert b.json()["deleted"] == 0 and len(b.json()["refused"]) == 1
    f = await client.delete(f"/api/v1/vrfs/{vrf.id}?force=true", headers=headers)
    assert f.status_code == 204, f.text
