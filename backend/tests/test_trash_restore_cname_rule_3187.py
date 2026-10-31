"""A Trash restore runs the CNAME-exclusivity rule the record API runs (#3187).

The restore checked a record only against an identical live twin, so a CNAME
came back beside an A created meanwhile (or an A beside a new CNAME): a pair
the record API refuses with a 409 and that BIND and PowerDNS refuse to load,
which holds back every later change to the zone.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"cn-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="CNAME Restore Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@dataclass(frozen=True)
class Z:
    """The zone's plain values: a commit expires the ORM object."""

    id: uuid.UUID
    group_id: uuid.UUID
    name: str


async def _zone(db: AsyncSession) -> Z:
    group = DNSServerGroup(name=f"cn-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db.add(zone)
    await db.flush()
    return Z(zone.id, zone.group_id, zone.name)


def _rec(zone: Z, name: str, rtype: str, value: str, view_id: uuid.UUID | None = None) -> DNSRecord:
    return DNSRecord(
        id=uuid.uuid4(),
        zone_id=zone.id,
        view_id=view_id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type=rtype,
        value=value,
    )


async def _all(db: AsyncSession, zone_id: uuid.UUID) -> dict[uuid.UUID, DNSRecord]:
    stmt = (
        select(DNSRecord)
        .where(DNSRecord.zone_id == zone_id)
        .execution_options(include_deleted=True, populate_existing=True)
    )
    return {r.id: r for r in (await db.execute(stmt)).scalars().all()}


async def _delete(client: AsyncClient, headers: dict[str, str], zone: Z, rid: uuid.UUID):
    resp = await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records/{rid}", headers=headers
    )
    assert resp.status_code == 204, resp.text


@pytest.mark.asyncio
async def test_a_cname_is_not_restored_beside_a_record_created_meanwhile(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    cname = _rec(zone, "cn", "CNAME", "target.example.test.")
    cname_id = cname.id
    db_session.add(cname)
    await db_session.commit()
    await _delete(client, headers, zone, cname_id)
    db_session.add(_rec(zone, "cn", "A", "192.0.2.31"))
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_record/{cname_id}/restore", headers=headers)
    assert resp.status_code == 409, resp.text
    [conflict] = resp.json()["detail"]["conflicts"]
    assert conflict["id"] == str(cname_id)
    assert "A CNAME must be the only record at its name" in conflict["reason"]

    db_session.expire_all()
    assert (await _all(db_session, zone.id))[cname_id].deleted_at is not None


@pytest.mark.asyncio
async def test_an_a_record_is_not_restored_beside_a_cname_created_meanwhile(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    a = _rec(zone, "cn", "A", "192.0.2.31")
    a_id = a.id
    db_session.add(a)
    await db_session.commit()
    await _delete(client, headers, zone, a_id)
    db_session.add(_rec(zone, "CN", "CNAME", "target.example.test."))
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_record/{a_id}/restore", headers=headers)
    assert resp.status_code == 409, resp.text
    assert "is a CNAME to" in resp.json()["detail"]["conflicts"][0]["reason"]


@pytest.mark.asyncio
async def test_a_second_cname_is_not_restored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    old = _rec(zone, "cn", "CNAME", "old.example.test.")
    old_id = old.id
    db_session.add(old)
    await db_session.commit()
    await _delete(client, headers, zone, old_id)
    db_session.add(_rec(zone, "cn", "CNAME", "new.example.test."))
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_record/{old_id}/restore", headers=headers)
    assert resp.status_code == 409, resp.text


@pytest.mark.asyncio
async def test_a_cname_in_another_view_is_not_a_clash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    v1 = DNSView(group_id=zone.group_id, name="internal")
    v2 = DNSView(group_id=zone.group_id, name="external")
    db_session.add_all([v1, v2])
    await db_session.flush()
    cname = _rec(zone, "cn", "CNAME", "t.example.test.", view_id=v1.id)
    cname_id = cname.id
    db_session.add(cname)
    await db_session.commit()
    await _delete(client, headers, zone, cname_id)
    db_session.add(_rec(zone, "cn", "A", "192.0.2.31", view_id=v2.id))
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_record/{cname_id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_a_record_that_does_not_clash_still_restores(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    cname = _rec(zone, "cn", "CNAME", "t.example.test.")
    cname_id = cname.id
    db_session.add(cname)
    await db_session.commit()
    await _delete(client, headers, zone, cname_id)
    db_session.add(_rec(zone, "other", "A", "192.0.2.9"))
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_record/{cname_id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["restored"] == 1


@pytest.mark.asyncio
async def test_a_zone_restore_is_refused_when_a_record_in_it_would_clash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    db_session.add_all(
        [_rec(zone, "cn", "CNAME", "t.example.test."), _rec(zone, "www", "A", "192.0.2.1")]
    )
    await db_session.commit()
    resp = await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}", headers=headers
    )
    assert resp.status_code == 204, resp.text
    # A record added since lands on the CNAME's name.
    db_session.add(_rec(zone, "cn", "TXT", "hello"))
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=headers)
    assert resp.status_code == 409, resp.text
    [conflict] = resp.json()["detail"]["conflicts"]
    assert conflict["display"] == f"cn.{zone.name} CNAME"

    db_session.expire_all()
    rows = await _all(db_session, zone.id)
    assert sum(1 for r in rows.values() if r.deleted_at is not None) == 2  # nothing restored


@pytest.mark.asyncio
async def test_a_bulk_batch_restores_the_rest_and_holds_the_clash_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    zone = await _zone(db_session)
    cname = _rec(zone, "cn", "CNAME", "t.example.test.")
    cname_id = cname.id
    ok = _rec(zone, "ok", "A", "192.0.2.5")
    ok_id = ok.id
    # What a bulk record delete leaves: independent siblings under one batch.
    batch_id = uuid.uuid4()
    for r in (cname, ok):
        r.deleted_at = datetime.now(UTC)
        r.deletion_batch_id = batch_id
    db_session.add_all([cname, ok])
    await db_session.commit()
    db_session.add(_rec(zone, "cn", "A", "192.0.2.31"))
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/admin/trash/dns_record/{ok_id}/restore?skip_conflicts=true", headers=headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["restored"] == 1
    assert [s["id"] for s in body["skipped"]] == [str(cname_id)]
    assert "CNAME" in body["skipped"][0]["reason"]

    db_session.expire_all()
    rows = await _all(db_session, zone.id)
    assert rows[ok_id].deleted_at is None
    assert rows[cname_id].deleted_at is not None
