"""spatiumddi#2732 — a zone restore must not publish IPAM records of a trashed or purged subnet.

Zone deleted FIRST, then a subnet whose hosts it published: the zone's batch
holds those auto-generated records, the subnet's delete (#1906) only retracts
live ones. Restoring the zone used to bring them back while the subnet sat in
the Trash, and — once the subnet was purged — as records owned by nothing.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord
from app.models.ipam import Subnet
from tests.test_subnet_trash_retracts_dns_1906 import (
    _address,
    _admin_headers,
    _live_records,
    _setup,
)


async def _zone_first_then_subnet(client, db, headers, cidr, base, host):  # type: ignore[no-untyped-def]
    grp, server, zone, sid, _ = await _setup(client, db, headers, cidr, None, base)
    await _address(client, headers, sid, host, "h1")
    assert ("h1", "A", host) in await _live_records(db, zone.id)

    r = await client.delete(f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert r.status_code == 204, r.text
    return grp, server, zone, sid


async def _forward_a(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str, bool]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.value, DNSRecord.deleted_at.is_(None))
            .where(DNSRecord.zone_id == zone_id, DNSRecord.record_type == "A")
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).all()
    return sorted(tuple(r) for r in rows)


@pytest.mark.asyncio
async def test_zone_restore_leaves_a_trashed_subnets_records_in_the_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    _grp, _server, zone, sid = await _zone_first_then_subnet(
        client, db_session, headers, "10.144.1.0/24", "10.144.0.0/16", "10.144.1.10"
    )

    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    # The zone is back, its IPAM A is not: it waits for its subnet.
    assert await _forward_a(db_session, zone.id) == [("h1", "10.144.1.10", False)]
    assert [h["parent_id"] for h in body["held_back"]] == [sid]
    assert body["held_back"][0]["parent_type"] == "subnet"

    # It now rides the subnet's batch, so the subnet's restore brings it back.
    subnet_batch = (
        await db_session.execute(
            select(Subnet.deletion_batch_id)
            .where(Subnet.id == uuid.UUID(sid))
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    held = (
        await db_session.execute(
            select(DNSRecord.deletion_batch_id)
            .where(DNSRecord.zone_id == zone.id, DNSRecord.record_type == "A")
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).scalar_one()
    assert held == subnet_batch

    r = await client.post(f"/api/v1/admin/trash/subnet/{sid}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _forward_a(db_session, zone.id) == [("h1", "10.144.1.10", True)]


@pytest.mark.asyncio
async def test_zone_restore_after_the_subnet_is_purged_brings_back_no_ownerless_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    _grp, _server, zone, sid = await _zone_first_then_subnet(
        client, db_session, headers, "10.144.2.0/24", "10.144.0.0/16", "10.144.2.10"
    )
    r = await client.delete(f"/api/v1/admin/trash/subnet/{sid}", headers=headers)
    assert r.status_code == 204, r.text
    # The purge takes the record the zone's batch held for the address.
    assert await _forward_a(db_session, zone.id) == []

    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _forward_a(db_session, zone.id) == []
    assert r.json()["held_back"] == []


@pytest.mark.asyncio
async def test_zone_restore_with_its_subnet_live_restores_the_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Control: nothing changes for a zone whose subnet was never deleted."""
    headers = await _admin_headers(db_session)
    grp, _server, zone, sid, _ = await _setup(
        client, db_session, headers, "10.144.3.0/24", None, "10.144.0.0/16"
    )
    await _address(client, headers, sid, "10.144.3.10", "h1")
    r = await client.delete(f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}", headers=headers)
    assert r.status_code == 204, r.text

    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["held_back"] == []
    assert await _forward_a(db_session, zone.id) == [("h1", "10.144.3.10", True)]
