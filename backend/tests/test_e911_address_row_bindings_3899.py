"""#3899 / #3958 / #3964: an automatic delete never silently drops an E911 binding.

``erl_binding.ip_address_id`` / ``subnet_id`` are ON DELETE CASCADE. Split and
Merge deleted the subnet row, Resize and Merge deleted the old Gateway row,
lease expiry / release / purge deleted a lease's mirror row, and a reservation
moving or its scope / subnet going to the Trash deleted the reservation's row,
each taking the binding with it. A binding now follows the row's successor, or
keeps the row.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPStaticAssignment
from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.lease_cleanup import purge_lease
from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics, upsert_ipam_for_static
from app.services.e911.resolver import resolve_location
from app.services.ipam.subnet_merge import commit_subnet_merge, preview_subnet_merge
from app.services.ipam.subnet_split import commit_subnet_split
from tests.test_dhcp_static_readdress_live_lease import (
    NEW,
    OLD,
    _group,
    _lease,
    _move,
    _reservation,
    _row,
    _scope,
    _superadmin_token,
)


async def _erl(db: AsyncSession, name: str = "HQ-3F") -> EmergencyResponseLocation:
    erl = EmergencyResponseLocation(name=name, country="US", a1="NY", rd="Broadway")
    db.add(erl)
    await db.flush()
    return erl


async def _bind_ip(db: AsyncSession, erl: EmergencyResponseLocation, row: IPAddress) -> uuid.UUID:
    b = ERLBinding(erl_id=erl.id, rule_kind="ip", ip_address_id=row.id)
    db.add(b)
    await db.flush()
    return b.id


async def _ip_binding_rows(db: AsyncSession, erl: EmergencyResponseLocation) -> list[IPAddress]:
    erl_id = erl.id
    res = await db.execute(
        select(IPAddress)
        .join(ERLBinding, ERLBinding.ip_address_id == IPAddress.id)
        .where(ERLBinding.erl_id == erl_id)
        .execution_options(populate_existing=True)
    )
    return list(res.scalars().all())


async def _subnets(db: AsyncSession, *cidrs: str) -> list[Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    out = [
        Subnet(space_id=space.id, block_id=block.id, network=c, name="s", total_ips=100)
        for c in cidrs
    ]
    db.add_all(out)
    await db.flush()
    return out


async def _subnet_bindings(db: AsyncSession, erl: EmergencyResponseLocation) -> set[uuid.UUID]:
    erl_id = erl.id
    res = await db.execute(select(ERLBinding.subnet_id).where(ERLBinding.erl_id == erl_id))
    return {s for (s,) in res.all()}


# ── #3899: subnet split / merge ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_split_keeps_the_subnet_binding_on_every_child(db_session: AsyncSession) -> None:
    (p,) = await _subnets(db_session, "10.0.0.0/24")
    erl = await _erl(db_session)
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=p.id))
    await db_session.flush()

    res = await commit_subnet_split(db_session, p, 25, confirm_cidr="10.0.0.0/24")
    child_ids = {c.id for c in res.children}
    assert await _subnet_bindings(db_session, erl) == child_ids


@pytest.mark.asyncio
async def test_merge_keeps_the_subnet_binding_and_refuses_differing_ones(
    db_session: AsyncSession,
) -> None:
    a, b = await _subnets(db_session, "10.0.0.0/25", "10.0.0.128/25")
    erl, other = await _erl(db_session), await _erl(db_session, "HQ-4F")
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=b.id))
    await db_session.flush()

    preview = await preview_subnet_merge(db_session, a, [b.id])
    assert preview.conflicts == []
    assert "E911" in " ".join(preview.warnings)
    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    merged_id = res.merged_subnet.id
    assert await _subnet_bindings(db_session, erl) == {merged_id}

    c, d = await _subnets(db_session, "10.1.0.0/25", "10.1.0.128/25")
    db_session.add_all(
        [
            ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=c.id),
            ERLBinding(erl_id=other.id, rule_kind="subnet", subnet_id=d.id),
        ]
    )
    await db_session.flush()
    preview = await preview_subnet_merge(db_session, c, [d.id])
    assert "e911_binding_conflict" in {x.type for x in preview.conflicts}


# ── #3958: the old Gateway row on Resize and Merge ───────────────────────


@pytest.mark.asyncio
async def test_resize_move_gateway_keeps_a_bound_old_gateway_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.197.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.197.1.128/25",
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    sid = uuid.UUID(r.json()["id"])
    old_gw = (
        await db_session.execute(
            select(IPAddress).where(IPAddress.subnet_id == sid, IPAddress.address == "10.197.1.129")
        )
    ).scalar_one()
    erl = await _erl(db_session)
    await _bind_ip(db_session, erl, old_gw)
    await db_session.commit()

    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize",
        headers=h,
        json={"new_cidr": "10.197.1.0/24", "move_gateway_to_first_usable": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["subnet"]["gateway"] == "10.197.1.1"
    assert [str(x.address) for x in await _ip_binding_rows(db_session, erl)] == ["10.197.1.129"]


@pytest.mark.asyncio
async def test_resize_preview_lists_a_bound_boundary_row_as_kept(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.198.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    await db_session.commit()
    r = await client.post(
        "/api/v1/ipam/subnets",
        headers=h,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.198.1.128/25",
            "skip_reverse_zone": True,
        },
    )
    assert r.status_code == 201, r.text
    sid = uuid.UUID(r.json()["id"])
    net_row = (
        await db_session.execute(
            select(IPAddress).where(IPAddress.subnet_id == sid, IPAddress.address == "10.198.1.128")
        )
    ).scalar_one()
    erl = await _erl(db_session)
    await _bind_ip(db_session, erl, net_row)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize/preview", headers=h, json={"new_cidr": "10.198.1.0/24"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "10.198.1.128" not in [p["ip"] for p in body["placeholders_default_named"]]
    assert "10.198.1.128" in [p["ip"] for p in body["placeholders_renamed"]]


@pytest.mark.asyncio
async def test_merge_keeps_a_bound_retired_gateway_row(db_session: AsyncSession) -> None:
    a, b = await _subnets(db_session, "10.0.0.0/25", "10.0.0.128/25")
    a.gateway, b.gateway = "10.0.0.1", "10.0.0.129"
    for s, gw in ((a, "10.0.0.1"), (b, "10.0.0.129")):
        db_session.add(
            IPAddress(
                subnet_id=s.id,
                address=gw,
                status="reserved",
                hostname="gateway",
                description="Gateway",
            )
        )
    await db_session.flush()
    erl = await _erl(db_session)
    bound = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.129"))
    ).scalar_one()
    await _bind_ip(db_session, erl, bound)

    res = await commit_subnet_merge(db_session, a, [b.id], confirm_cidr="10.0.0.0/24")
    merged_id = res.merged_subnet.id
    (kept,) = await _ip_binding_rows(db_session, erl)
    assert str(kept.address) == "10.0.0.129" and kept.subnet_id == merged_id


# ── #3964: a reservation's row ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_moving_a_reservation_carries_its_binding_to_the_new_row(
    db_session: AsyncSession,
) -> None:
    grp, _ = await _group(db_session, servers=0)
    subnet, scope = await _scope(db_session, grp)
    st = await _reservation(db_session, scope)
    erl = await _erl(db_session)
    await _bind_ip(db_session, erl, await _row(db_session, subnet, OLD))

    await _move(db_session, scope, st)
    (bound,) = await _ip_binding_rows(db_session, erl)
    assert str(bound.address) == NEW and bound.status == "static_dhcp"


@pytest.mark.asyncio
async def test_removing_a_scope_keeps_the_bound_reservation_row(db_session: AsyncSession) -> None:
    grp, _ = await _group(db_session, servers=0)
    subnet, scope = await _scope(db_session, grp)
    await _reservation(db_session, scope)
    other = DHCPStaticAssignment(
        scope_id=scope.id, ip_address="10.0.0.60", mac_address="aa:bb:cc:dd:ee:60", hostname="x"
    )
    db_session.add(other)
    await db_session.flush()
    await upsert_ipam_for_static(db_session, scope, other)
    await db_session.flush()
    erl = await _erl(db_session)
    await _bind_ip(db_session, erl, await _row(db_session, subnet, OLD))

    await remove_ipam_for_scope_statics(db_session, scope.id)
    await db_session.flush()
    (bound,) = await _ip_binding_rows(db_session, erl)
    assert str(bound.address) == OLD and bound.status == "available"
    assert bound.static_assignment_id is None and not bound.hostname
    assert await _row(db_session, subnet, "10.0.0.60") is None  # unbound: still gone


@pytest.mark.asyncio
async def test_scope_and_subnet_delete_endpoints_keep_the_binding(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    grp, _ = await _group(db_session, servers=0)
    s1, scope1 = await _scope(db_session, grp)
    s2, scope2 = await _scope(db_session, grp, network="10.0.1.0/24")
    await _reservation(db_session, scope1)
    await _reservation(db_session, scope2, ip="10.0.1.80")
    erl = await _erl(db_session)
    await _bind_ip(db_session, erl, await _row(db_session, s1, OLD))
    await _bind_ip(db_session, erl, await _row(db_session, s2, "10.0.1.80"))
    await db_session.commit()

    r = await client.delete(f"/api/v1/dhcp/scopes/{scope1.id}", headers=h)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/ipam/subnets/{s2.id}", headers=h)
    assert r.status_code == 204, r.text
    assert sorted(str(x.address) for x in await _ip_binding_rows(db_session, erl)) == [
        OLD,
        "10.0.1.80",
    ]


# ── #3899: the lease mirror ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_purged_lease_keeps_a_bound_mirror_row(db_session: AsyncSession) -> None:
    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    lease = _lease(srv, scope, ip="10.0.0.99", state="expired", expires_in=timedelta(hours=-1))
    db_session.add(lease)
    mirror = IPAddress(
        subnet_id=subnet.id,
        address="10.0.0.99",
        status="dhcp",
        hostname="laptop",
        auto_from_lease=True,
    )
    db_session.add(mirror)
    await db_session.flush()
    erl = await _erl(db_session)
    await _bind_ip(db_session, erl, mirror)

    await purge_lease(db_session, lease, subnet_id=subnet.id, spare_if_peer_holds=False)
    await db_session.flush()
    (bound,) = await _ip_binding_rows(db_session, erl)
    assert bound.status == "available" and not bound.auto_from_lease and not bound.hostname
    # The old device is gone: the next one handed this address must NOT be told
    # it is in the old device's room. Kept, listed, but inactive.
    b = (
        await db_session.execute(select(ERLBinding).where(ERLBinding.ip_address_id == bound.id))
    ).scalar_one()
    await db_session.refresh(b)
    assert b.is_active is False and "re-activate" in b.notes
    res = await resolve_location(db_session, ip="10.0.0.99")
    assert res.erl is None or res.erl.id != erl.id


@pytest.mark.asyncio
async def test_the_expiry_sweep_keeps_a_bound_mirror_row(db_session: AsyncSession) -> None:
    import app.tasks.dhcp_lease_cleanup as cleanup

    grp, (srv,) = await _group(db_session)
    subnet, scope = await _scope(db_session, grp)
    now = datetime.now(UTC)
    db_session.add(
        DHCPLease(
            server_id=srv.id,
            scope_id=scope.id,
            ip_address="10.0.0.98",
            mac_address="aa:bb:cc:dd:ee:98",
            state="active",
            starts_at=now - timedelta(hours=3),
            ends_at=now - timedelta(hours=1),
            expires_at=now - timedelta(hours=1),
            last_seen_at=now - timedelta(hours=2),
        )
    )
    mirror = IPAddress(
        subnet_id=subnet.id, address="10.0.0.98", status="dhcp", auto_from_lease=True
    )
    db_session.add(mirror)
    await db_session.flush()
    erl = await _erl(db_session)
    await _bind_ip(db_session, erl, mirror)
    await db_session.commit()

    await cleanup._sweep()
    (bound,) = await _ip_binding_rows(db_session, erl)
    assert str(bound.address) == "10.0.0.98" and bound.status == "available"
