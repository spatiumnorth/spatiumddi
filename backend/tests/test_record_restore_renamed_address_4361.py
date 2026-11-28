"""spatiumddi#4361 — an IPAM record trashed through the record API is not
restored under a name its address gave up.

The record API's delete moves an IPAM-generated record to the Trash on its
own; a rename of the address meanwhile publishes a new record and never sees
the trashed copy, so its Restore brought the old name back beside the new one
and pushed it to the zone's servers. Restore is refused (single) or reported as
a conflict (bulk), as for an orphaned address (#3189).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp
from tests.test_subnet_trash_retracts_dns_1906 import _address, _admin_headers, _setup


async def _rows(db: AsyncSession, ip_id: str) -> list[tuple[str, str, bool]]:
    rows = (
        await db.execute(
            select(DNSRecord.record_type, DNSRecord.fqdn, DNSRecord.deleted_at.is_(None))
            .where(DNSRecord.ip_address_id == uuid.UUID(ip_id))
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).all()
    return sorted((str(t), str(f), bool(live)) for t, f, live in rows)


async def _ops_named(db: AsyncSession, label: str) -> int:
    rows = (await db.execute(select(DNSRecordOp.record))).scalars().all()
    return sum(1 for r in rows if str(r.get("name", "")).lower() == label)


async def _record(db: AsyncSession, ip_id: str, rtype: str) -> DNSRecord:
    return (
        await db.execute(
            select(DNSRecord).where(
                DNSRecord.ip_address_id == uuid.UUID(ip_id), DNSRecord.record_type == rtype
            )
        )
    ).scalar_one()


async def _renamed(client, db, cidr, base, host):  # type: ignore[no-untyped-def]
    headers = await _admin_headers(db)
    grp, _srv, zone, sid, _ = await _setup(client, db, headers, cidr, None, base)
    net = cidr.rsplit(".", 1)[0]
    ip_id = await _address(client, headers, sid, f"{net}.10", host)
    return headers, grp, zone, ip_id


@pytest.mark.asyncio
async def test_restore_of_a_record_whose_address_was_renamed_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, ip_id = await _renamed(
        client, db_session, "10.161.1.0/24", "10.161.0.0/16", "r1"
    )
    rec = await _record(db_session, ip_id, "A")
    rec_id = rec.id
    d = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/{rec_id}", headers=headers
    )
    assert d.status_code == 204, d.text
    u = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "r1z"}
    )
    assert u.status_code == 200, u.text
    ops_before = await _ops_named(db_session, "r1")

    r = await client.post(f"/api/v1/admin/trash/dns_record/{rec_id}/restore", headers=headers)
    assert r.status_code == 409, r.text
    assert "no longer holds this name" in r.json()["detail"]

    await db_session.rollback()
    a_rows = [x for x in await _rows(db_session, ip_id) if x[0] == "A"]
    live = [x[1] for x in a_rows if x[2]]
    assert len(live) == 1 and live[0].startswith("r1z."), a_rows
    assert any(not x[2] and x[1].startswith("r1.") for x in a_rows)  # still in the Trash
    assert await _ops_named(db_session, "r1") == ops_before  # nothing pushed for the old name


@pytest.mark.asyncio
async def test_bulk_restore_reports_the_renamed_address_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, ip_id = await _renamed(
        client, db_session, "10.162.1.0/24", "10.162.0.0/16", "q1"
    )
    other = await _address(client, headers, str(await _sid(db_session, ip_id)), "10.162.1.11", "q2")
    rec_id = (await _record(db_session, ip_id, "A")).id
    other_id = (await _record(db_session, other, "A")).id
    d = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/bulk-delete",
        headers=headers,
        json={"record_ids": [str(rec_id), str(other_id)]},
    )
    assert d.status_code == 200, d.text
    u = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "q1z"}
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

    await db_session.rollback()
    names = {x[1] for x in await _rows(db_session, ip_id) if x[0] == "A" and x[2]}
    assert all(n.startswith("q1z.") for n in names), names
    assert [x for x in await _rows(db_session, other) if x[0] == "A" and x[2]]


async def _sid(db: AsyncSession, ip_id: str) -> uuid.UUID:
    from app.models.ipam import IPAddress

    return (
        await db.execute(select(IPAddress.subnet_id).where(IPAddress.id == uuid.UUID(ip_id)))
    ).scalar_one()


@pytest.mark.asyncio
async def test_restore_of_an_unchanged_record_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, ip_id = await _renamed(
        client, db_session, "10.163.1.0/24", "10.163.0.0/16", "k1"
    )
    rec_id = (await _record(db_session, ip_id, "A")).id
    d = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/{rec_id}", headers=headers
    )
    assert d.status_code == 204, d.text
    r = await client.post(f"/api/v1/admin/trash/dns_record/{rec_id}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["restored"] == 1


@pytest.mark.asyncio
async def test_restore_of_a_ptr_whose_address_was_renamed_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, ip_id = await _renamed(
        client, db_session, "10.164.1.0/24", "10.164.0.0/16", "p1"
    )
    ptr = await _record(db_session, ip_id, "PTR")
    ptr_id, ptr_zone = ptr.id, ptr.zone_id
    d = await client.delete(
        f"/api/v1/dns/groups/{grp.id}/zones/{ptr_zone}/records/{ptr_id}", headers=headers
    )
    assert d.status_code == 204, d.text
    u = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": "p1z"}
    )
    assert u.status_code == 200, u.text
    r = await client.post(f"/api/v1/admin/trash/dns_record/{ptr_id}/restore", headers=headers)
    assert r.status_code == 409, r.text
    await db_session.rollback()
    live = [x for x in await _rows(db_session, ip_id) if x[0] == "PTR" and x[2]]
    assert len(live) == 1
