"""Mark as Orphan is reversible for an address's DNS aliases too (#2604).

The Delete IP Address dialog calls Mark as Orphan reversible, and the row's
Restore puts the address back. Orphaning used to delete every alias record of
the address with its host record, and Restore re-created the host record
only, so the aliases were gone for good. They are now withdrawn (soft-deleted
under one batch per address) and come back with the row.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSZone
from app.tasks.trash_purge import _purge_dns_records
from tests.test_ipam_alias_cname_exclusive_2080 import _alloc, _setup


async def _all_alias_rows(db: AsyncSession, ip_id: str) -> list[DNSRecord]:
    """Every alias row of the address, trashed ones included."""
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(
                    DNSRecord.ip_address_id == uuid.UUID(ip_id),
                    DNSRecord.ip_alias.is_(True),
                )
                .execution_options(include_deleted=True, populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


async def _live_zone(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type, DNSRecord.value)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted((str(n), str(t), str(v)) for n, t, v in rows)


async def _last_op(db: AsyncSession, zone: DNSZone, name: str) -> str | None:
    rows = (
        (
            await db.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.zone_id == zone.id)
                .order_by(DNSRecordOp.created_at)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    ops = [r.op for r in rows if (r.record or {}).get("name") == name]
    return ops[-1] if ops else None


async def _aliased(client: AsyncClient, headers: dict[str, str], sid: str, addr: str) -> str:
    r = await _alloc(
        client,
        headers,
        sid,
        addr,
        "h1",
        aliases=[{"name": "www", "record_type": "CNAME"}, {"name": "ftp", "record_type": "A"}],
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def _alias_names(client: AsyncClient, headers: dict[str, str], ip_id: str) -> list[str]:
    r = await client.get(f"/api/v1/ipam/addresses/{ip_id}/aliases", headers=headers)
    assert r.status_code == 200, r.text
    return sorted(a["name"] for a in r.json())


@pytest.mark.asyncio
async def test_orphan_then_restore_brings_the_aliases_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    ip_id = await _aliased(client, headers, sid, "10.98.5.21")
    before = {r.name: r.id for r in await _all_alias_rows(db_session, ip_id)}
    assert sorted(before) == ["ftp", "www"]

    d = await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    assert d.status_code == 204, d.text
    # Out of DNS: the API lists none, the served zone holds none, and the
    # agent was told to delete them.
    assert await _alias_names(client, headers, ip_id) == []
    assert await _live_zone(db_session, zone.id) == []
    assert await _last_op(db_session, zone, "www") == "delete"
    assert await _last_op(db_session, zone, "ftp") == "delete"
    # ...but not lost.
    assert {r.name for r in await _all_alias_rows(db_session, ip_id)} == {"ftp", "www"}

    p = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"status": "allocated"}
    )
    assert p.status_code == 200, p.text
    assert await _alias_names(client, headers, ip_id) == ["ftp", "www"]
    zone_name = zone.name.rstrip(".")
    assert await _live_zone(db_session, zone.id) == [
        ("ftp", "A", "10.98.5.21"),
        ("h1", "A", "10.98.5.21"),
        ("www", "CNAME", f"h1.{zone_name}."),
    ]
    assert await _last_op(db_session, zone, "www") == "create"
    assert await _last_op(db_session, zone, "ftp") == "create"
    # The same rows, not copies.
    after = {r.name: r.id for r in await _all_alias_rows(db_session, ip_id)}
    assert after == before


@pytest.mark.asyncio
async def test_restore_that_renames_repoints_the_cname(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    ip_id = await _aliased(client, headers, sid, "10.98.5.22")
    assert (
        await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    ).status_code == 204
    p = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"status": "allocated", "hostname": "h2"},
    )
    assert p.status_code == 200, p.text
    zone_name = zone.name.rstrip(".")
    assert ("www", "CNAME", f"h2.{zone_name}.") in await _live_zone(db_session, zone.id)


@pytest.mark.asyncio
async def test_a_name_taken_meanwhile_refuses_the_restore(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    zone_id = zone.id
    ip_id = await _aliased(client, headers, sid, "10.98.5.23")
    assert (
        await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    ).status_code == 204
    # Another address now holds the CNAME alias's name.
    r = await _alloc(client, headers, sid, "10.98.5.24", "www")
    assert r.status_code == 201, r.text

    p = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"status": "allocated"}
    )
    assert p.status_code == 409, p.text
    assert "www" in p.text
    # The test client shares one session with the app; production's get_db
    # rolls a failed request back, so do the same here.
    await db_session.rollback()
    got = await client.get(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    assert got.json()["status"] == "orphan"
    # Nothing half-restored: still withdrawn, and the host record not back.
    assert await _alias_names(client, headers, ip_id) == []
    assert ("h1", "A", "10.98.5.23") not in await _live_zone(db_session, zone_id)


@pytest.mark.asyncio
async def test_purging_the_orphan_deletes_its_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _aliased(client, headers, sid, "10.98.5.25")
    assert (
        await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    ).status_code == 204
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/orphans/purge", headers=headers, json={"ip_ids": [ip_id]}
    )
    assert r.status_code == 200, r.text
    assert r.json()["purged"] == 1
    assert await _all_alias_rows(db_session, ip_id) == []


@pytest.mark.asyncio
async def test_permanent_delete_of_an_orphan_deletes_its_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _aliased(client, headers, sid, "10.98.5.26")
    assert (
        await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    ).status_code == 204
    d = await client.delete(f"/api/v1/ipam/addresses/{ip_id}?permanent=true", headers=headers)
    assert d.status_code == 204, d.text
    assert await _all_alias_rows(db_session, ip_id) == []


@pytest.mark.asyncio
async def test_bulk_orphan_then_restore_brings_the_aliases_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _aliased(client, headers, sid, "10.98.5.27")
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        headers=headers,
        json={"ip_ids": [ip_id], "permanent": False},
    )
    assert r.status_code == 200, r.text
    assert r.json()["deleted_count"] == 1
    assert await _alias_names(client, headers, ip_id) == []
    p = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"status": "allocated"}
    )
    assert p.status_code == 200, p.text
    assert await _alias_names(client, headers, ip_id) == ["ftp", "www"]


@pytest.mark.asyncio
async def test_retention_purge_keeps_an_orphans_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _aliased(client, headers, sid, "10.98.5.28")
    assert (
        await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    ).status_code == 204
    # A cutoff past every stamp: anything not held back would go.
    await _purge_dns_records(db_session, datetime.now(UTC) + timedelta(days=1), set())
    await db_session.commit()
    assert {r.name for r in await _all_alias_rows(db_session, ip_id)} == {"ftp", "www"}
    p = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"status": "allocated"}
    )
    assert p.status_code == 200, p.text
    assert await _alias_names(client, headers, ip_id) == ["ftp", "www"]
