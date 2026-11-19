"""The record API refuses a value the group's driver cannot hold (#2959).

Linode's CAA record has no flags field, so ``128 issue "ca.org"`` cannot be
carried there. That is a 422 from the record API, before the record is stored,
not a push that fails after it is.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
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


async def _group(db: AsyncSession, driver: str) -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver=driver,
            host=f"{driver}.example.com",
            name=f"srv-{uuid.uuid4().hex[:6]}",
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    return grp, zone


async def _count(db: AsyncSession, zone: DNSZone) -> int:
    return (
        await db.execute(
            select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
        )
    ).scalar_one()


async def test_linode_refuses_nonzero_caa_flags_on_create(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone = await _group(db_session, "linode")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records",
        headers=h,
        json={"name": "@", "record_type": "CAA", "value": '128 issue "ca.org"'},
    )
    assert r.status_code == 422, r.text
    assert "flags" in r.json()["detail"]
    assert await _count(db_session, zone) == 0


async def test_linode_refuses_nonzero_caa_flags_in_bulk(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone = await _group(db_session, "linode")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/bulk-create",
        headers=h,
        json={
            "records": [
                {"name": "a", "record_type": "A", "value": "192.0.2.1"},
                {"name": "@", "record_type": "CAA", "value": '128 issue "ca.org"'},
            ]
        },
    )
    assert r.status_code == 422, r.text
    assert await _count(db_session, zone) == 0


async def test_linode_refuses_nonzero_caa_flags_on_update(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin_headers(db_session)
    grp, zone = await _group(db_session, "linode")
    rec = DNSRecord(
        zone_id=zone.id, name="@", fqdn="example.com.", record_type="CAA", value='0 issue "ca.org"'
    )
    db_session.add(rec)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/{rec.id}",
        headers=h,
        json={"value": '128 issue "ca.org"'},
    )
    assert r.status_code == 422, r.text
    await db_session.refresh(rec)
    assert rec.value == '0 issue "ca.org"'


async def test_bind9_keeps_nonzero_caa_flags(client: AsyncClient, db_session: AsyncSession) -> None:
    # The refusal is Linode's, not a general rule.
    h = await _admin_headers(db_session)
    grp, zone = await _group(db_session, "bind9")
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records",
        headers=h,
        json={"name": "@", "record_type": "CAA", "value": '128 issue "ca.org"'},
    )
    assert r.status_code == 201, r.text
