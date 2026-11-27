"""A deleted subnet's auto reverse zone is handed only to a survivor the zone
can serve: one in the same DNS group (and view), and never one of another IP
space whose network overlaps. Otherwise the zone is retired with the subnet.

Also: the PTR pick only uses a linked zone that sits in one of the subnet's
effective groups, so a zone already linked across groups stops taking PTRs.
"""

from __future__ import annotations

import ipaddress
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dns.sync_check import resolve_reverse_zone
from tests.test_subnet_delete_reverse_zone_1066 import (
    _admin_headers,
    _subnet_row,
    _zone_row,
)

ZONE = "2.24.172.in-addr.arpa."


async def _group(db: AsyncSession, fwd: str) -> tuple[str, str]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=fwd,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{fwd}",
        admin_email=f"admin.{fwd}",
    )
    db.add(zone)
    await db.flush()
    return str(grp.id), str(zone.id)


async def _space(db: AsyncSession, net: str = "172.24.0.0/16") -> tuple[str, str]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=net, name="b")
    db.add(block)
    await db.flush()
    return str(space.id), str(block.id)


async def _subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: str,
    block: str,
    network: str,
    gid: str,
    zid: str,
) -> str:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": space,
            "block_id": block,
            "network": network,
            "dns_group_id": gid,
            "dns_zone_id": zid,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _two_spaces(client: AsyncClient, db: AsyncSession, headers: dict[str, str]) -> dict:
    g1, f1 = await _group(db, "f1.example.")
    g2, f2 = await _group(db, "f2.example.")
    s1, b1 = await _space(db)
    s2, b2 = await _space(db)
    await db.commit()
    a = await _subnet(client, headers, s1, b1, "172.24.2.0/24", g1, f1)
    b = await _subnet(client, headers, s2, b2, "172.24.2.0/24", g2, f2)
    return dict(g1=g1, g2=g2, f1=f1, f2=f2, s1=s1, s2=s2, b1=b1, b2=b2, a=a, b=b)


async def _one_space_two_groups(
    client: AsyncClient, db: AsyncSession, headers: dict[str, str]
) -> dict:
    g1, f1 = await _group(db, "f1.example.")
    g2, f2 = await _group(db, "f2.example.")
    s1, b1 = await _space(db)
    await db.commit()
    a = await _subnet(client, headers, s1, b1, "172.24.2.0/25", g1, f1)
    b = await _subnet(client, headers, s1, b1, "172.24.2.128/25", g2, f2)
    return dict(g1=g1, g2=g2, f1=f1, f2=f2, s1=s1, b1=b1, a=a, b=b)


async def _ptr_zones(db: AsyncSession, address: str) -> list[uuid.UUID]:
    label = address.split(".")[-1]
    rows = (
        await db.execute(
            select(DNSRecord.zone_id).where(DNSRecord.record_type == "PTR", DNSRecord.name == label)
        )
    ).all()
    return [r[0] for r in rows]


async def _add_address(
    client: AsyncClient, headers: dict[str, str], subnet: str, ip: str, host: str
) -> None:
    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet}/addresses",
        headers=headers,
        json={"address": ip, "hostname": host, "status": "allocated"},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_two_spaces_same_cidr_soft_delete_retires_the_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    e = await _two_spaces(client, db_session, headers)
    assert (await _zone_row(db_session, e["g1"], ZONE)) is not None

    resp = await client.delete(f"/api/v1/ipam/subnets/{e['a']}", headers=headers)
    assert resp.status_code == 204, resp.text

    zone = await _zone_row(db_session, e["g1"], ZONE)
    assert zone is not None and zone.deleted_at is not None
    assert str(zone.linked_subnet_id) == e["a"]
    other = await _zone_row(db_session, e["g2"], ZONE)
    assert other is not None and other.deleted_at is None and str(other.linked_subnet_id) == e["b"]

    # The survivor's addresses publish into its own group only.
    await _add_address(client, headers, e["b"], "172.24.2.10", "h10.f2.example")
    g2_zone = await _zone_row(db_session, e["g2"], ZONE)
    assert g2_zone is not None
    assert await _ptr_zones(db_session, "172.24.2.10") == [g2_zone.id]

    # Restore brings the zone back, still linked to the restored subnet.
    restored = await client.post(f"/api/v1/admin/trash/subnet/{e['a']}/restore", headers=headers)
    assert restored.status_code == 200, restored.text
    zone = await _zone_row(db_session, e["g1"], ZONE)
    assert zone is not None and zone.deleted_at is None and str(zone.linked_subnet_id) == e["a"]


@pytest.mark.asyncio
async def test_two_spaces_same_cidr_permanent_delete_removes_the_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    e = await _two_spaces(client, db_session, headers)
    resp = await client.delete(f"/api/v1/ipam/subnets/{e['a']}?permanent=true", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _subnet_row(db_session, e["a"]) is None
    assert await _zone_row(db_session, e["g1"], ZONE) is None
    other = await _zone_row(db_session, e["g2"], ZONE)
    assert other is not None and str(other.linked_subnet_id) == e["b"]


@pytest.mark.asyncio
async def test_two_spaces_trash_purge_removes_the_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    e = await _two_spaces(client, db_session, headers)
    assert (
        await client.delete(f"/api/v1/ipam/subnets/{e['a']}", headers=headers)
    ).status_code == 204
    # A live zone linked to a trashed subnet, as an older delete left it.
    zone = await _zone_row(db_session, e["g1"], ZONE)
    assert zone is not None
    zone.deleted_at = None
    zone.deletion_batch_id = None
    await db_session.commit()

    resp = await client.delete(f"/api/v1/admin/trash/subnet/{e['a']}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_row(db_session, e["g1"], ZONE) is None
    other = await _zone_row(db_session, e["g2"], ZONE)
    assert other is not None and str(other.linked_subnet_id) == e["b"]


@pytest.mark.asyncio
async def test_two_spaces_space_delete_and_block_delete_retire_the_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    e = await _two_spaces(client, db_session, headers)
    assert (
        await client.delete(f"/api/v1/ipam/spaces/{e['s1']}", headers=headers)
    ).status_code == 204
    zone = await _zone_row(db_session, e["g1"], ZONE)
    assert zone is not None and zone.deleted_at is not None
    assert str(zone.linked_subnet_id) == e["a"]

    e2 = await _two_spaces(client, db_session, headers)
    assert (
        await client.delete(f"/api/v1/ipam/blocks/{e2['b1']}", headers=headers)
    ).status_code == 204
    zone = await _zone_row(db_session, e2["g1"], ZONE)
    assert zone is not None and zone.deleted_at is not None
    assert str(zone.linked_subnet_id) == e2["a"]


@pytest.mark.asyncio
async def test_one_space_two_groups_delete_retires_the_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    e = await _one_space_two_groups(client, db_session, headers)
    assert (await _zone_row(db_session, e["g1"], ZONE)) is not None

    resp = await client.delete(f"/api/v1/ipam/subnets/{e['a']}", headers=headers)
    assert resp.status_code == 204, resp.text
    zone = await _zone_row(db_session, e["g1"], ZONE)
    assert zone is not None and zone.deleted_at is not None

    await _add_address(client, headers, e["b"], "172.24.2.130", "h130.f2.example")
    g2_zone = await _zone_row(db_session, e["g2"], ZONE)
    assert g2_zone is not None
    assert await _ptr_zones(db_session, "172.24.2.130") == [g2_zone.id]
    preview = await client.get(f"/api/v1/ipam/subnets/{e['b']}/dns-sync/preview", headers=headers)
    assert preview.status_code == 200, preview.text
    assert str(zone.id) not in preview.text


@pytest.mark.asyncio
async def test_same_group_survivor_still_inherits_the_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    g1, f1 = await _group(db_session, "f1.example.")
    s1, b1 = await _space(db_session)
    await db_session.commit()
    a = await _subnet(client, headers, s1, b1, "172.24.2.0/25", g1, f1)
    b = await _subnet(client, headers, s1, b1, "172.24.2.128/25", g1, f1)

    assert (await client.delete(f"/api/v1/ipam/subnets/{a}", headers=headers)).status_code == 204
    zone = await _zone_row(db_session, g1, ZONE)
    assert zone is not None and zone.deleted_at is None and str(zone.linked_subnet_id) == b


@pytest.mark.asyncio
async def test_a_zone_linked_across_groups_is_not_picked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A zone already re-linked into another group (data written before the
    fix) is not the survivor's: the PTR pick skips it."""
    headers = await _admin_headers(db_session)
    e = await _one_space_two_groups(client, db_session, headers)
    zone = await _zone_row(db_session, e["g1"], ZONE)
    assert zone is not None
    zone.linked_subnet_id = uuid.UUID(e["b"])
    # The survivor's own group holds no reverse zone of the name yet.
    g2_zone = await _zone_row(db_session, e["g2"], ZONE)
    assert g2_zone is not None
    await db_session.delete(g2_zone)
    await db_session.commit()

    subnet_b = await db_session.get(Subnet, uuid.UUID(e["b"]))
    assert subnet_b is not None
    picked = await resolve_reverse_zone(
        db_session, subnet_b, ipaddress.ip_address("172.24.2.130"), [e["g2"]]
    )
    assert picked is None
