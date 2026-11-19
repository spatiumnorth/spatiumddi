"""DNS Zone "None" keeps an address out of DNS (#2466).

Allocate IP sends ``dns_zone_id: ""`` for "None (no DNS record)", and an
untouched Edit address Save after "None" must not publish records again.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace


async def _setup(client: AsyncClient, db: AsyncSession) -> tuple[dict[str, str], str, DNSZone]:
    user = User(
        username=f"u2122-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    grp = DNSServerGroup(name=f"g2122-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"d{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    space = IPSpace(name=f"sp2122-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.97.0.0/16", name="b")
    db.add(block)
    await db.flush()
    await db.commit()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.97.5.0/24",
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(zone.id),
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    return headers, str(resp.json()["id"]), zone


async def _records(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted((str(n), str(t)) for n, t in rows)


async def _forward(db: AsyncSession, ip_id: str) -> uuid.UUID | None:
    return await db.scalar(
        select(IPAddress.forward_zone_id)
        .where(IPAddress.id == uuid.UUID(ip_id))
        .execution_options(populate_existing=True)
    )


@pytest.mark.asyncio
async def test_allocate_with_none_zone_publishes_nothing(
    client: AsyncClient, db_session: AsyncSession
):
    headers, sid, zone = await _setup(client, db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.97.5.50", "hostname": "nozone", "dns_zone_id": ""},
    )
    assert r.status_code == 201, r.text
    assert await _forward(db_session, r.json()["id"]) is None
    assert await _records(db_session, zone.id) == []


@pytest.mark.asyncio
async def test_next_allocate_with_none_zone_publishes_nothing(
    client: AsyncClient, db_session: AsyncSession
):
    headers, sid, zone = await _setup(client, db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/next",
        headers=headers,
        json={"hostname": "nozone2", "dns_zone_id": ""},
    )
    assert r.status_code == 201, r.text
    assert await _forward(db_session, r.json()["id"]) is None
    assert await _records(db_session, zone.id) == []


@pytest.mark.asyncio
async def test_absent_zone_still_uses_subnet_zone(client: AsyncClient, db_session: AsyncSession):
    headers, sid, zone = await _setup(client, db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.97.5.51", "hostname": "withzone"},
    )
    assert r.status_code == 201, r.text
    assert await _forward(db_session, r.json()["id"]) == zone.id
    assert await _records(db_session, zone.id) == [("withzone", "A")]


@pytest.mark.asyncio
async def test_untouched_save_after_none_stays_out_of_dns(
    client: AsyncClient, db_session: AsyncSession
):
    headers, sid, zone = await _setup(client, db_session)
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.97.5.60", "hostname": "keep1"},
    )
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    assert await _records(db_session, zone.id) == [("keep1", "A")]
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"hostname": "keep1", "dns_zone_id": None},
    )
    assert r.status_code == 200, r.text
    assert await _records(db_session, zone.id) == []
    # The dialog's untouched Save: hostname present, no dns_zone_id.
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"hostname": "keep1", "description": "", "status": "allocated"},
    )
    assert r.status_code == 200, r.text
    assert await _forward(db_session, ip_id) is None
    assert await _records(db_session, zone.id) == []
    # Renaming it is a real change and publishes into the subnet's zone.
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "renamed"}
    )
    assert r.status_code == 200, r.text
    assert await _records(db_session, zone.id) == [("renamed", "A")]
