"""#4390 — a DNS pool writes no record into a zone that is not a primary."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSPool, DNSRecord, DNSServerGroup, DNSZone
from app.services.dns.pool_apply import apply_pool_state


async def _setup(db: AsyncSession) -> tuple[dict, uuid.UUID, uuid.UUID]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([user, grp])
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="p1.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.p1.test.",
        admin_email="admin.p1.test.",
    )
    db.add(zone)
    await db.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return h, grp.id, zone.id


async def _make_pool(client: AsyncClient, h: dict, gid, zid) -> None:
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/pools",
        headers=h,
        json={
            "name": "p",
            "record_name": "www",
            "record_type": "A",
            "hc_type": "none",
            "members": [{"address": "192.0.2.46"}],
        },
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_type", ["secondary", "stub", "forward"])
async def test_type_change_refused_while_a_pool_targets_the_zone(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    h, gid, zid = await _setup(db_session)
    await _make_pool(client, h, gid, zid)
    # a disabled pool holds no row: the record count alone would miss it
    pool = (await db_session.execute(select(DNSPool))).scalar_one()
    pool.enabled = False
    await db_session.commit()
    body: dict = {"zone_type": zone_type}
    if zone_type == "forward":
        body["forwarders"] = ["192.0.2.53"]
    else:
        body["masters"] = ["192.0.2.1"]
    r = await client.put(f"/api/v1/dns/groups/{gid}/zones/{zid}", headers=h, json=body)
    assert r.status_code == 409, r.text
    assert "DNS pool" in r.text and "p" in r.text
    zone = await db_session.get(DNSZone, zid)
    await db_session.refresh(zone)
    assert zone.zone_type == "primary"


@pytest.mark.asyncio
async def test_pool_renders_nothing_into_a_non_primary_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, gid, zid = await _setup(db_session)
    await _make_pool(client, h, gid, zid)
    pool = (await db_session.execute(select(DNSPool))).scalar_one()
    await db_session.refresh(pool, ["members"])
    for m in pool.members:
        m.last_check_state = "healthy"
    # the zone is changed behind the API's back (e.g. before the refusal existed)
    zone = await db_session.get(DNSZone, zid)
    zone.zone_type = "secondary"
    await db_session.commit()
    out = await apply_pool_state(db_session, pool)
    await db_session.commit()
    assert out["created"] == 0
    rows = (await db_session.execute(select(DNSRecord).where(DNSRecord.name == "www"))).all()
    assert rows == []
    # back to primary: the pool renders again
    zone.zone_type = "primary"
    await db_session.commit()
    out = await apply_pool_state(db_session, pool)
    await db_session.commit()
    assert out["created"] == 1


@pytest.mark.asyncio
async def test_existing_pool_rows_withdrawn_from_non_primary_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, gid, zid = await _setup(db_session)
    await _make_pool(client, h, gid, zid)
    pool = (await db_session.execute(select(DNSPool))).scalar_one()
    await db_session.refresh(pool, ["members"])
    for m in pool.members:
        m.last_check_state = "healthy"
    await apply_pool_state(db_session, pool)
    await db_session.commit()
    zone = await db_session.get(DNSZone, zid)
    zone.zone_type = "stub"
    await db_session.commit()
    out = await apply_pool_state(db_session, pool)
    await db_session.commit()
    assert out["deleted"] == 1
    assert (await db_session.execute(select(DNSRecord))).first() is None


@pytest.mark.asyncio
async def test_zone_without_pool_still_changes_type(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, gid, zid = await _setup(db_session)
    r = await client.put(
        f"/api/v1/dns/groups/{gid}/zones/{zid}",
        headers=h,
        json={"zone_type": "secondary", "masters": ["192.0.2.1"]},
    )
    assert r.status_code == 200, r.text
