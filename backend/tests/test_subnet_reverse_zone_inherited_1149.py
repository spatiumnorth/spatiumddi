"""spatiumddi#1149 — a subnet that inherits its DNS gets its reverse zone.

Getting Started promises the matching ``in-addr.arpa`` zone "is created
automatically once the subnet has an effective DNS group/zone". create_subnet
decided from the request body and the subnet's own columns only, and
``ensure_reverse_zone_for_subnet`` resolved no inheritance either, so a subnet
left on "Inherit from parent" (the console's default, which sends no DNS fields
at all) never got one — at create, on its first allocation, or from the
backfill endpoints. Live on nightly-20260923: the subnet's effective DNS
resolved to the block's group and zone and no reverse zone existed.

The helper now falls back to the inherited DNS when the subnet names none of
its own; everything that resolved a group before resolves the same one, and the
#844 cross-space refusal still applies whatever way the group was found.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1149-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group_and_zone(db: AsyncSession, label: str) -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g1149-{label}-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"{label}-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return grp, zone


async def _space(db: AsyncSession, **dns: object) -> IPSpace:
    space = IPSpace(name=f"sp1149-{uuid.uuid4().hex[:8]}", description="", **dns)
    db.add(space)
    await db.flush()
    return space


async def _block(db: AsyncSession, space: IPSpace, network: str, **dns: object) -> IPBlock:
    block = IPBlock(space_id=space.id, network=network, name="b", **dns)
    db.add(block)
    await db.flush()
    return block


async def _create_subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: IPSpace,
    block: IPBlock,
    network: str,
    **extra: object,
) -> str:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={"space_id": str(space.id), "block_id": str(block.id), "network": network, **extra},
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _reverse_zones(db: AsyncSession, name: str) -> list[DNSZone]:
    """Every zone of this name in any group, re-read from the database (the
    handler committed through this session; populate_existing refreshes the
    identity map without expiring it)."""
    stmt = (
        select(DNSZone)
        .where(DNSZone.name == name)
        .execution_options(include_deleted=True, populate_existing=True)
    )
    return list((await db.execute(stmt)).scalars().all())


@pytest.mark.asyncio
async def test_subnet_inheriting_its_blocks_dns_gets_its_reverse_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reproduced case: the block pins a group and zone with inheritance
    off; the subnet is created with no DNS fields at all."""
    headers = await _admin_headers(db_session)
    grp, zone = await _group_and_zone(db_session, "blk")
    space = await _space(db_session)
    block = await _block(
        db_session,
        space,
        "10.77.0.0/16",
        dns_group_ids=[str(grp.id)],
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    await db_session.commit()

    sid = await _create_subnet(client, headers, space, block, "10.77.21.0/24")

    eff = (await client.get(f"/api/v1/ipam/subnets/{sid}/effective-dns", headers=headers)).json()
    assert eff["dns_zone_id"] == str(zone.id), eff
    zones = await _reverse_zones(db_session, "21.77.10.in-addr.arpa.")
    assert len(zones) == 1, [(z.group_id, z.name) for z in zones]
    rz = zones[0]
    assert rz.group_id == grp.id
    assert str(rz.linked_subnet_id) == sid
    assert rz.is_auto_generated is True and rz.kind == "reverse"


@pytest.mark.asyncio
async def test_subnet_inheriting_through_its_block_from_the_space(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp, zone = await _group_and_zone(db_session, "spc")
    space = await _space(db_session, dns_group_ids=[str(grp.id)], dns_zone_id=str(zone.id))
    block = await _block(db_session, space, "10.78.0.0/16")  # inherits (the default)
    await db_session.commit()

    sid = await _create_subnet(client, headers, space, block, "10.78.3.0/24")

    zones = await _reverse_zones(db_session, "3.78.10.in-addr.arpa.")
    assert [(z.group_id, str(z.linked_subnet_id)) for z in zones] == [(grp.id, sid)]


@pytest.mark.asyncio
async def test_inherited_group_without_a_zone_is_enough(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Same rule as an explicit group-only binding: the group names where the
    reverse zone goes, a forward zone is not required."""
    headers = await _admin_headers(db_session)
    grp, _ = await _group_and_zone(db_session, "grp")
    space = await _space(db_session)
    block = await _block(
        db_session, space, "10.79.0.0/16", dns_group_ids=[str(grp.id)], dns_inherit_settings=False
    )
    await db_session.commit()

    sid = await _create_subnet(client, headers, space, block, "10.79.4.0/24")

    zones = await _reverse_zones(db_session, "4.79.10.in-addr.arpa.")
    assert [(z.group_id, str(z.linked_subnet_id)) for z in zones] == [(grp.id, sid)]


@pytest.mark.asyncio
async def test_skip_reverse_zone_still_opts_an_inheriting_subnet_out(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp, zone = await _group_and_zone(db_session, "skip")
    space = await _space(db_session)
    block = await _block(
        db_session,
        space,
        "10.80.0.0/16",
        dns_group_ids=[str(grp.id)],
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    bare_space = await _space(db_session)
    bare_block = await _block(db_session, bare_space, "10.81.0.0/16")
    await db_session.commit()

    await _create_subnet(client, headers, space, block, "10.80.5.0/24", skip_reverse_zone=True)
    # And a subnet with no DNS anywhere up its chain stays a no-op.
    await _create_subnet(client, headers, bare_space, bare_block, "10.81.5.0/24")

    assert await _reverse_zones(db_session, "5.80.10.in-addr.arpa.") == []
    assert await _reverse_zones(db_session, "5.81.10.in-addr.arpa.") == []


@pytest.mark.asyncio
async def test_the_subnets_own_binding_still_wins_over_the_inherited_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    inherited_grp, inherited_zone = await _group_and_zone(db_session, "parent")
    own_grp, own_zone = await _group_and_zone(db_session, "own")
    space = await _space(db_session)
    block = await _block(
        db_session,
        space,
        "10.82.0.0/16",
        dns_group_ids=[str(inherited_grp.id)],
        dns_zone_id=str(inherited_zone.id),
        dns_inherit_settings=False,
    )
    await db_session.commit()

    sid = await _create_subnet(
        client,
        headers,
        space,
        block,
        "10.82.6.0/24",
        dns_group_id=str(own_grp.id),
        dns_zone_id=str(own_zone.id),
    )

    zones = await _reverse_zones(db_session, "6.82.10.in-addr.arpa.")
    assert [(z.group_id, str(z.linked_subnet_id)) for z in zones] == [(own_grp.id, sid)]


@pytest.mark.asyncio
async def test_first_allocation_backfills_the_inherited_reverse_zone_and_its_ptr(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A subnet created before its block had DNS: the per-allocation backfill
    in ``_sync_dns_record`` is the catch-up path, and it resolved no
    inheritance either — the address got its A record and no PTR."""
    headers = await _admin_headers(db_session)
    grp, zone = await _group_and_zone(db_session, "late")
    space = await _space(db_session)
    block = await _block(db_session, space, "10.83.0.0/16")
    await db_session.commit()
    sid = await _create_subnet(client, headers, space, block, "10.83.7.0/24")
    assert await _reverse_zones(db_session, "7.83.10.in-addr.arpa.") == []

    resp = await client.put(
        f"/api/v1/ipam/blocks/{block.id}",
        headers=headers,
        json={
            "dns_group_ids": [str(grp.id)],
            "dns_zone_id": str(zone.id),
            "dns_inherit_settings": False,
        },
    )
    assert resp.status_code == 200, resp.text
    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.83.7.50", "hostname": "host50"},
    )
    assert resp.status_code == 201, resp.text
    ip_id = uuid.UUID(resp.json()["id"])

    zones = await _reverse_zones(db_session, "7.83.10.in-addr.arpa.")
    assert [(z.group_id, str(z.linked_subnet_id)) for z in zones] == [(grp.id, sid)]
    ptrs = (
        (
            await db_session.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == zones[0].id, DNSRecord.ip_address_id == ip_id
                )
            )
        )
        .scalars()
        .all()
    )
    assert [(r.record_type, r.name, r.value) for r in ptrs] == [
        ("PTR", "50", f"host50.{zone.name}")
    ]


@pytest.mark.asyncio
async def test_backfill_endpoint_creates_the_inherited_reverse_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp, zone = await _group_and_zone(db_session, "bf")
    space = await _space(db_session)
    block = await _block(db_session, space, "10.84.0.0/16")
    await db_session.commit()
    sid = await _create_subnet(client, headers, space, block, "10.84.8.0/24")
    block_row = await db_session.get(IPBlock, block.id)
    assert block_row is not None
    block_row.dns_group_ids = [str(grp.id)]
    block_row.dns_zone_id = str(zone.id)
    block_row.dns_inherit_settings = False
    await db_session.commit()

    resp = await client.post(f"/api/v1/ipam/subnets/{sid}/reverse-zones/backfill", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["created"] == [{"subnet": "10.84.8.0/24", "zone": "8.84.10.in-addr.arpa."}]


@pytest.mark.asyncio
async def test_an_inherited_group_keeps_the_844_cross_space_refusal(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Two IP spaces with the same CIDR, one DNS group: the second space's
    subnet inherits the group, computes the same reverse-zone name, and must be
    refused rather than fold its PTRs into the first tenant's zone."""
    headers = await _admin_headers(db_session)
    grp, zone = await _group_and_zone(db_session, "t844")
    space_a = await _space(db_session)
    block_a = await _block(db_session, space_a, "10.85.0.0/16")
    space_b = await _space(db_session)
    block_b = await _block(
        db_session,
        space_b,
        "10.85.0.0/16",
        dns_group_ids=[str(grp.id)],
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    await db_session.commit()

    owner = await _create_subnet(
        client,
        headers,
        space_a,
        block_a,
        "10.85.9.0/24",
        dns_group_id=str(grp.id),
        dns_zone_id=str(zone.id),
    )
    await _create_subnet(client, headers, space_b, block_b, "10.85.9.0/24")

    zones = await _reverse_zones(db_session, "9.85.10.in-addr.arpa.")
    assert [(z.group_id, str(z.linked_subnet_id)) for z in zones] == [(grp.id, owner)]
