"""#4260 — a pool's record name meets the record API's A / AAAA owner rules."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
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
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return h, grp.id, zone.id


def _body(name: str) -> dict:
    return {
        "name": f"p-{uuid.uuid4().hex[:6]}",
        "record_name": name,
        "record_type": "A",
        "hc_type": "none",
        "members": [{"address": "192.0.2.56"}],
    }


async def _add_cname(db: AsyncSession, zone_id: uuid.UUID, name: str) -> None:
    db.add(
        DNSRecord(
            zone_id=zone_id,
            name=name,
            fqdn=f"{name}.example.com.",
            record_type="CNAME",
            value="other.example.net.",
            ttl=300,
        )
    )
    await db.commit()


@pytest.mark.asyncio
async def test_underscore_pool_name_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    h, gid, zid = await _setup(db_session)
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/pools", headers=h, json=_body("_xp")
    )
    assert r.status_code == 422, r.text
    assert "not a host name" in r.text
    assert (await db_session.execute(select(DNSPool))).first() is None


@pytest.mark.asyncio
async def test_pool_at_cname_name_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    h, gid, zid = await _setup(db_session)
    await _add_cname(db_session, zid, "www")
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/pools", headers=h, json=_body("www")
    )
    assert r.status_code == 409, r.text
    assert "CNAME" in r.text


@pytest.mark.asyncio
async def test_valid_pool_still_created_and_materializes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, gid, zid = await _setup(db_session)
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/pools", headers=h, json=_body("web")
    )
    assert r.status_code == 201, r.text
    pool = (await db_session.execute(select(DNSPool))).scalar_one()
    await db_session.refresh(pool, ["members"])
    for m in pool.members:
        m.last_check_state = "healthy"
    out = await apply_pool_state(db_session, pool)
    await db_session.commit()
    assert out["created"] == 1
    rows = (await db_session.execute(select(DNSRecord).where(DNSRecord.name == "web"))).scalars()
    assert [x.value for x in rows] == ["192.0.2.56"]


@pytest.mark.asyncio
async def test_cname_added_after_pool_skips_materialization(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, gid, zid = await _setup(db_session)
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/pools", headers=h, json=_body("web")
    )
    assert r.status_code == 201, r.text
    await _add_cname(db_session, zid, "web")  # bypasses the API on purpose
    pool = (await db_session.execute(select(DNSPool))).scalar_one()
    await db_session.refresh(pool, ["members"])
    for m in pool.members:
        m.last_check_state = "healthy"
    out = await apply_pool_state(db_session, pool)
    await db_session.commit()
    assert out["created"] == 0
    types = (
        (await db_session.execute(select(DNSRecord.record_type).where(DNSRecord.name == "web")))
        .scalars()
        .all()
    )
    assert types == ["CNAME"]
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "dns.pool.render_skipped")
            )
        )
        .scalars()
        .all()
    )
    assert len(audit) == 1
    # a second pass must not add a second audit row
    await apply_pool_state(db_session, pool)
    await db_session.commit()
    n = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "dns.pool.render_skipped")
            )
        )
        .scalars()
        .all()
    )
    assert len(n) == 1


@pytest.mark.asyncio
async def test_cname_at_pool_name_refused_by_record_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, gid, zid = await _setup(db_session)
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/pools", headers=h, json=_body("web")
    )
    assert r.status_code == 201, r.text
    r = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/records",
        headers=h,
        json={"name": "web", "record_type": "CNAME", "value": "other.example.net.", "ttl": 300},
    )
    assert r.status_code == 409, r.text
    assert "DNS pool" in r.text
