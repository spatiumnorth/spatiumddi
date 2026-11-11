"""#3891: a hard delete never silently takes an E911 binding with it.

``erl_binding``'s foreign keys are all ON DELETE CASCADE; #2298 refused the site
delete, this is the same rule for a VLAN, a router, a subnet (Trash purge, the
nightly sweep, the copilot op), an address and a device's interfaces.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.network import NetworkDevice, NetworkInterface
from app.models.vlans import VLAN, Router


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _erl(db: AsyncSession) -> EmergencyResponseLocation:
    erl = EmergencyResponseLocation(name="HQ-3F", country="US", a1="NY", rd="Broadway")
    db.add(erl)
    await db.flush()
    return erl


async def _bindings(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(ERLBinding))).scalar_one()


async def _subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.47.0.0/16", name="b")
    db.add(block)
    await db.flush()
    sub = Subnet(space_id=space.id, block_id=block.id, network="10.47.1.0/24", name="lan")
    db.add(sub)
    await db.flush()
    return sub


async def _vlan(db: AsyncSession) -> tuple[Router, VLAN]:
    r = Router(name=f"r-{uuid.uuid4().hex[:6]}")
    db.add(r)
    await db.flush()
    v = VLAN(router_id=r.id, vlan_id=3901, name="voice")
    db.add(v)
    await db.flush()
    return r, v


@pytest.mark.asyncio
async def test_vlan_delete_refused_while_bound(client: AsyncClient, db_session: AsyncSession):
    h = await _admin(db_session)
    erl = await _erl(db_session)
    _, v = await _vlan(db_session)
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="vlan", vlan_ref_id=v.id))
    await db_session.flush()
    r = await client.delete(f"/api/v1/vlans/vlans/{v.id}", headers=h)
    assert r.status_code == 409, r.text
    assert "HQ-3F" in r.json()["detail"] and "3901" in r.json()["detail"]
    assert await _bindings(db_session) == 1


@pytest.mark.asyncio
async def test_router_delete_refused_while_a_vlan_is_bound(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin(db_session)
    erl = await _erl(db_session)
    rt, v = await _vlan(db_session)
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="vlan", vlan_ref_id=v.id))
    await db_session.flush()
    r = await client.delete(f"/api/v1/vlans/routers/{rt.id}", headers=h)
    assert r.status_code == 409, r.text
    assert "HQ-3F" in r.json()["detail"]
    assert await _bindings(db_session) == 1


@pytest.mark.asyncio
async def test_unbound_vlan_still_deletes(client: AsyncClient, db_session: AsyncSession):
    h = await _admin(db_session)
    _, v = await _vlan(db_session)
    r = await client.delete(f"/api/v1/vlans/vlans/{v.id}", headers=h)
    assert r.status_code == 204, r.text


async def _trashed_bound_subnet(db: AsyncSession, *, via_address: bool = False) -> Subnet:
    erl = await _erl(db)
    sub = await _subnet(db)
    if via_address:
        ip = IPAddress(subnet_id=sub.id, address="10.47.1.9", status="allocated")
        db.add(ip)
        await db.flush()
        db.add(ERLBinding(erl_id=erl.id, rule_kind="ip", ip_address_id=ip.id))
    else:
        db.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=sub.id))
    sub.deleted_at = datetime.now(UTC) - timedelta(days=60)
    await db.flush()
    return sub


@pytest.mark.asyncio
@pytest.mark.parametrize("via_address", [False, True])
async def test_trash_purge_of_subnet_refused_while_bound(
    client: AsyncClient, db_session: AsyncSession, via_address: bool
):
    h = await _admin(db_session)
    sub = await _trashed_bound_subnet(db_session, via_address=via_address)
    r = await client.delete(f"/api/v1/admin/trash/subnet/{sub.id}", headers=h)
    assert r.status_code == 409, r.text
    assert "HQ-3F" in r.json()["detail"]
    assert await _bindings(db_session) == 1


@pytest.mark.asyncio
async def test_nightly_sweep_holds_back_a_bound_subnet(db_session: AsyncSession):
    from app.tasks.trash_purge import _expired_where

    sub = await _trashed_bound_subnet(db_session)
    other = await _subnet_in_same_block(db_session, sub)
    cutoff = datetime.now(UTC) - timedelta(days=30)
    ids = (
        (
            await db_session.execute(
                select(Subnet.id)
                .where(*_expired_where(Subnet, cutoff))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    assert sub.id not in ids
    assert other.id in ids


async def _subnet_in_same_block(db: AsyncSession, sub: Subnet) -> Subnet:
    other = Subnet(
        space_id=sub.space_id,
        block_id=sub.block_id,
        network="10.47.2.0/24",
        name="plain",
        deleted_at=datetime.now(UTC) - timedelta(days=60),
    )
    db.add(other)
    await db.flush()
    return other


@pytest.mark.asyncio
async def test_permanent_address_delete_refused_while_bound(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin(db_session)
    erl = await _erl(db_session)
    sub = await _subnet(db_session)
    ip = IPAddress(subnet_id=sub.id, address="10.47.1.9", status="allocated")
    db_session.add(ip)
    await db_session.flush()
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="ip", ip_address_id=ip.id))
    await db_session.flush()
    r = await client.delete(f"/api/v1/ipam/addresses/{ip.id}?permanent=true", headers=h)
    assert r.status_code == 409, r.text
    assert "10.47.1.9" in r.json()["detail"]
    # the bulk path skips it, with the reason
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        json={"ip_ids": [str(ip.id)], "permanent": True},
        headers=h,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted_count"] == 0 and str(ip.id) in body["skipped_reasons"]
    assert await _bindings(db_session) == 1


@pytest.mark.asyncio
async def test_device_delete_refused_while_a_port_is_bound(
    client: AsyncClient, db_session: AsyncSession
):
    h = await _admin(db_session)
    erl = await _erl(db_session)
    sp = await _subnet(db_session)
    dev = NetworkDevice(name="sw1", hostname="sw1", ip_address="10.0.0.2", ip_space_id=sp.space_id)
    db_session.add(dev)
    await db_session.flush()
    ifc = NetworkInterface(device_id=dev.id, if_index=1, name="Gi1/0/1")
    db_session.add(ifc)
    await db_session.flush()
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="switch_port", network_interface_id=ifc.id))
    await db_session.flush()
    r = await client.delete(f"/api/v1/network-devices/{dev.id}", headers=h)
    assert r.status_code == 409, r.text
    assert "Gi1/0/1" in r.json()["detail"]
    assert await _bindings(db_session) == 1


@pytest.mark.asyncio
async def test_copilot_permanent_subnet_delete_refused_even_with_force(db_session: AsyncSession):
    from fastapi import HTTPException

    from app.services.ai.operations_risky import DeleteSubnetArgs, _apply_delete_subnet

    erl = await _erl(db_session)
    sub = await _subnet(db_session)
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=sub.id))
    user = User(
        username="su",
        email="su@example.com",
        display_name="su",
        hashed_password="x",
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    with pytest.raises(HTTPException) as ei:
        await _apply_delete_subnet(
            db_session, user, DeleteSubnetArgs(subnet_id=sub.id, permanent=True, force=True)
        )
    assert ei.value.status_code == 409
    assert "HQ-3F" in ei.value.detail
