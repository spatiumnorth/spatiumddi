"""#1974 — updating a DNS pool reconciles its rendered records.

A disabled pool must render nothing (its records are removed), re-enabling
restores healthy + enabled members, and a TTL change lands immediately
instead of waiting for the next health-check tick (which skips disabled
pools entirely).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSPool,
    DNSPoolMember,
    DNSRecord,
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSZone,
)


async def _setup(db: AsyncSession) -> tuple[dict, uuid.UUID, uuid.UUID]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id, name="ns1", driver="bind9", host="10.0.0.1", is_primary=True
    )
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add_all([server, zone])
    await db.flush()
    pool = DNSPool(
        group_id=grp.id,
        zone_id=zone.id,
        name="web",
        record_name="www",
        record_type="A",
        ttl=30,
        enabled=True,
    )
    db.add(pool)
    await db.flush()
    for addr in ("192.0.2.1", "192.0.2.2"):
        m = DNSPoolMember(pool_id=pool.id, address=addr, enabled=True, last_check_state="healthy")
        db.add(m)
        await db.flush()
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name="www",
                fqdn="www.example.com.",
                record_type="A",
                value=addr,
                ttl=30,
                pool_member_id=m.id,
            )
        )
    await db.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return h, pool.id, server.id


async def _records(db: AsyncSession, pool_id: uuid.UUID) -> list[DNSRecord]:
    db.expire_all()
    res = await db.execute(
        select(DNSRecord)
        .join(DNSPoolMember, DNSRecord.pool_member_id == DNSPoolMember.id)
        .where(DNSPoolMember.pool_id == pool_id)
    )
    return list(res.scalars().all())


async def _ops(db: AsyncSession, server_id: uuid.UUID) -> list[DNSRecordOp]:
    res = await db.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == server_id))
    return list(res.scalars().all())


@pytest.mark.asyncio
async def test_disable_removes_records_and_reenable_restores(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pool_id, server_id = await _setup(db_session)

    r = await client.put(f"/api/v1/dns/pools/{pool_id}", headers=h, json={"enabled": False})
    assert r.status_code == 200, r.text
    assert await _records(db_session, pool_id) == []
    deletes = [o for o in await _ops(db_session, server_id) if o.op == "delete"]
    assert sorted(o.record["value"] for o in deletes) == ["192.0.2.1", "192.0.2.2"]

    r = await client.put(f"/api/v1/dns/pools/{pool_id}", headers=h, json={"enabled": True})
    assert r.status_code == 200, r.text
    recs = await _records(db_session, pool_id)
    assert sorted(x.value for x in recs) == ["192.0.2.1", "192.0.2.2"]
    creates = [o for o in await _ops(db_session, server_id) if o.op == "create"]
    assert sorted(o.record["value"] for o in creates) == ["192.0.2.1", "192.0.2.2"]


@pytest.mark.asyncio
async def test_reenable_skips_unhealthy_member(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pool_id, _ = await _setup(db_session)
    await client.put(f"/api/v1/dns/pools/{pool_id}", headers=h, json={"enabled": False})
    res = await db_session.execute(
        select(DNSPoolMember).where(
            DNSPoolMember.pool_id == pool_id, DNSPoolMember.address == "192.0.2.2"
        )
    )
    res.scalar_one().last_check_state = "unhealthy"
    await db_session.commit()
    await client.put(f"/api/v1/dns/pools/{pool_id}", headers=h, json={"enabled": True})
    assert [x.value for x in await _records(db_session, pool_id)] == ["192.0.2.1"]


@pytest.mark.asyncio
async def test_ttl_change_applies_immediately(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pool_id, server_id = await _setup(db_session)
    r = await client.put(f"/api/v1/dns/pools/{pool_id}", headers=h, json={"ttl": 120})
    assert r.status_code == 200, r.text
    assert {x.ttl for x in await _records(db_session, pool_id)} == {120}
    updates = [o for o in await _ops(db_session, server_id) if o.op == "update"]
    assert len(updates) == 2
    assert {o.record["ttl"] for o in updates} == {120}


@pytest.mark.asyncio
async def test_unrelated_update_queues_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pool_id, server_id = await _setup(db_session)
    r = await client.put(f"/api/v1/dns/pools/{pool_id}", headers=h, json={"description": "x"})
    assert r.status_code == 200, r.text
    assert await _ops(db_session, server_id) == []
    assert len(await _records(db_session, pool_id)) == 2
