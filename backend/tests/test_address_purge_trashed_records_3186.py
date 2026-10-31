"""spatiumddi#3186 — deleting an address for good takes its trashed auto records.

Zone deleted first (its batch holds IPAM's record for the host), then the
address deleted permanently: the record's ``ip_address_id`` used to go NULL and
the zone's restore brought back a record owned by nothing. The same holds for
the DHCP lease and reservation mirrors, which are addresses deleted for good by
their own teardown paths.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPServer
from app.models.ipam import IPAddress
from app.services.dhcp.lease_cleanup import purge_lease, sweep_orphaned_lease_mirrors
from app.services.dhcp.static_ipam import _delete_mirror_row
from tests.test_subnet_trash_retracts_dns_1906 import (
    _address,
    _admin_headers,
    _live_records,
    _setup,
)
from tests.test_zone_restore_trashed_subnet_records_2732 import _forward_a


async def _zone_trashed_with_address(client, db, headers, cidr, base, host):  # type: ignore[no-untyped-def]
    grp, _server, zone, sid, _ = await _setup(client, db, headers, cidr, None, base)
    ip_id = await _address(client, headers, sid, host, "h3")
    assert ("h3", "A", host) in await _live_records(db, zone.id)
    r = await client.delete(f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}", headers=headers)
    assert r.status_code == 204, r.text
    assert await _forward_a(db, zone.id) == [("h3", host, False)]
    return zone, sid, ip_id


async def _restore_and_assert_clean(client, db, headers, zone):  # type: ignore[no-untyped-def]
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _forward_a(db, zone.id) == []


@pytest.mark.asyncio
async def test_single_permanent_delete(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_headers(db_session)
    zone, _sid, ip_id = await _zone_trashed_with_address(
        client, db_session, headers, "10.145.1.0/24", "10.145.0.0/16", "10.145.1.10"
    )
    r = await client.delete(f"/api/v1/ipam/addresses/{ip_id}?permanent=true", headers=headers)
    assert r.status_code == 204, r.text
    await _restore_and_assert_clean(client, db_session, headers, zone)


@pytest.mark.asyncio
async def test_bulk_permanent_delete(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_headers(db_session)
    zone, _sid, ip_id = await _zone_trashed_with_address(
        client, db_session, headers, "10.145.2.0/24", "10.145.0.0/16", "10.145.2.10"
    )
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-delete",
        headers=headers,
        json={"ip_ids": [ip_id], "permanent": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["deleted_count"] == 1
    await _restore_and_assert_clean(client, db_session, headers, zone)


@pytest.mark.asyncio
async def test_orphan_purge(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_headers(db_session)
    zone, sid, ip_id = await _zone_trashed_with_address(
        client, db_session, headers, "10.145.3.0/24", "10.145.0.0/16", "10.145.3.10"
    )
    r = await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{sid}/orphans/purge", headers=headers, json={"ip_ids": [ip_id]}
    )
    assert r.status_code == 200, r.text
    assert r.json()["purged"] == 1
    await _restore_and_assert_clean(client, db_session, headers, zone)


# ── The DHCP mirrors: lease and reservation rows are addresses deleted for good too ──


async def _as_lease_mirror(db: AsyncSession, ip_id: str) -> IPAddress:
    row = await db.get(IPAddress, uuid.UUID(ip_id))
    assert row is not None
    row.auto_from_lease = True
    row.status = "dhcp"
    row.last_seen_at = None
    await db.flush()
    return row


@pytest.mark.asyncio
async def test_lease_purge(client: AsyncClient, db_session: AsyncSession) -> None:
    """The pull's absence-delete and the delete-lease endpoint (``purge_lease``)."""
    headers = await _admin_headers(db_session)
    zone, sid, ip_id = await _zone_trashed_with_address(
        client, db_session, headers, "10.145.4.0/24", "10.145.0.0/16", "10.145.4.10"
    )
    await _as_lease_mirror(db_session, ip_id)
    server = DHCPServer(name=f"k-{uuid.uuid4().hex[:6]}", driver="kea", host="10.0.0.1", port=67)
    db_session.add(server)
    await db_session.flush()
    lease = DHCPLease(
        server_id=server.id,
        ip_address="10.145.4.10",
        mac_address="aa:bb:cc:dd:ee:10",
        state="active",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(lease)
    await db_session.flush()
    assert await purge_lease(db_session, lease, subnet_id=uuid.UUID(sid)) is True
    await db_session.commit()
    await _restore_and_assert_clean(client, db_session, headers, zone)


@pytest.mark.asyncio
async def test_orphaned_lease_mirror_sweep(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _admin_headers(db_session)
    zone, _sid, ip_id = await _zone_trashed_with_address(
        client, db_session, headers, "10.145.5.0/24", "10.145.0.0/16", "10.145.5.10"
    )
    await _as_lease_mirror(db_session, ip_id)
    assert await sweep_orphaned_lease_mirrors(db_session) == 1
    await db_session.commit()
    await _restore_and_assert_clean(client, db_session, headers, zone)


@pytest.mark.asyncio
async def test_static_mirror_removal(client: AsyncClient, db_session: AsyncSession) -> None:
    """A reservation's IPAM mirror deleted with its reservation (``_delete_mirror_row``)."""
    headers = await _admin_headers(db_session)
    zone, _sid, ip_id = await _zone_trashed_with_address(
        client, db_session, headers, "10.145.6.0/24", "10.145.0.0/16", "10.145.6.10"
    )
    row = await db_session.get(IPAddress, uuid.UUID(ip_id))
    assert row is not None
    await _delete_mirror_row(db_session, row, None)
    await db_session.commit()
    await _restore_and_assert_clean(client, db_session, headers, zone)


@pytest.mark.asyncio
async def test_trash_batch_size_follows_the_purge(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The zone's Trash row counts what its batch still holds once the record is gone."""
    headers = await _admin_headers(db_session)
    zone, _sid, ip_id = await _zone_trashed_with_address(
        client, db_session, headers, "10.145.7.0/24", "10.145.0.0/16", "10.145.7.10"
    )

    async def _batch_size() -> int:
        r = await client.get("/api/v1/admin/trash?type=dns_zone", headers=headers)
        assert r.status_code == 200, r.text
        (item,) = [i for i in r.json()["items"] if i["id"] == str(zone.id)]
        return int(item["batch_size"])

    before = await _batch_size()
    r = await client.delete(f"/api/v1/ipam/addresses/{ip_id}?permanent=true", headers=headers)
    assert r.status_code == 204, r.text
    assert await _batch_size() == before - 1
