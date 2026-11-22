"""spatiumddi#4755 — a trashed IPAM host record is not restored into the zone its
address left.

#4361 refused a restore when the address was renamed, comparing name and value
only. An address moved to another DNS zone keeps both, so the trashed copy in the
old zone passed the guard and came back beside the live one in the new zone.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from tests.test_record_restore_renamed_address_4361 import _record, _renamed, _rows
from tests.test_subnet_trash_retracts_dns_1906 import _address


async def _second_zone(db: AsyncSession, grp_id: uuid.UUID) -> DNSZone:
    z = DNSZone(
        group_id=grp_id,
        name=f"moved-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.commit()
    await db.refresh(z)
    return z


async def _trash_then_move(client, db, cidr, base, extra=None):  # type: ignore[no-untyped-def]
    headers, grp, zone, ip_id = await _renamed(client, db, cidr, base, "m1")
    rec_id = (await _record(db, ip_id, "A")).id
    d = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/{rec_id}", headers=headers
    )
    assert d.status_code == 204, d.text
    new = await _second_zone(db, grp.id)
    u = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"dns_zone_id": str(new.id), **(extra or {})},
    )
    assert u.status_code == 200, u.text
    return headers, grp, zone, new, ip_id, rec_id


@pytest.mark.asyncio
async def test_restore_of_a_record_whose_address_moved_zone_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _grp, zone, new, ip_id, rec_id = await _trash_then_move(
        client, db_session, "10.165.1.0/24", "10.165.0.0/16"
    )
    new_id = new.id
    await db_session.rollback()
    live = (
        (
            await db_session.execute(
                select(DNSRecord.zone_id).where(
                    DNSRecord.ip_address_id == uuid.UUID(ip_id), DNSRecord.record_type == "A"
                )
            )
        )
        .scalars()
        .all()
    )
    assert live == [new_id], "the move did not publish into the new zone"

    r = await client.post(f"/api/v1/admin/trash/dns_record/{rec_id}/restore", headers=headers)
    assert r.status_code == 409, r.text
    assert "no longer holds this name" in r.json()["detail"]

    await db_session.rollback()
    a_rows = [x for x in await _rows(db_session, ip_id) if x[0] == "A"]
    assert len([x for x in a_rows if x[2]]) == 1, a_rows


@pytest.mark.asyncio
async def test_bulk_restore_reports_the_record_in_the_zone_the_address_left(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from tests.test_record_restore_renamed_address_4361 import _sid

    headers, grp, zone, ip_id = await _renamed(
        client, db_session, "10.166.1.0/24", "10.166.0.0/16", "m1"
    )
    other = await _address(client, headers, str(await _sid(db_session, ip_id)), "10.166.1.11", "m2")
    rec_id = (await _record(db_session, ip_id, "A")).id
    other_id = (await _record(db_session, other, "A")).id
    d = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/bulk-delete",
        headers=headers,
        json={"record_ids": [str(rec_id), str(other_id)]},
    )
    assert d.status_code == 200, d.text
    new = await _second_zone(db_session, grp.id)
    u = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"dns_zone_id": str(new.id)}
    )
    assert u.status_code == 200, u.text

    r = await client.post(
        f"/api/v1/admin/trash/dns_record/{other_id}/restore?skip_conflicts=true", headers=headers
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["restored"] == 1
    assert [s["id"] for s in body["skipped"]] == [str(rec_id)]
    assert "no longer holds this name" in body["skipped"][0]["reason"]


@pytest.mark.asyncio
async def test_restore_of_a_record_in_an_extra_zone_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, ip_id = await _renamed(
        client, db_session, "10.167.1.0/24", "10.167.0.0/16", "x1"
    )
    extra = await _second_zone(db_session, grp.id)
    u = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"extra_zone_ids": [str(extra.id)]}
    )
    assert u.status_code == 200, u.text
    rows = (
        (
            await db_session.execute(
                select(DNSRecord.id).where(
                    DNSRecord.ip_address_id == uuid.UUID(ip_id),
                    DNSRecord.record_type == "A",
                    DNSRecord.zone_id == extra.id,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1, "the extra zone did not get its A record"
    d = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{extra.id}/records/{rows[0]}", headers=headers
    )
    assert d.status_code == 204, d.text
    r = await client.post(f"/api/v1/admin/trash/dns_record/{rows[0]}/restore", headers=headers)
    assert r.status_code == 200, r.text
