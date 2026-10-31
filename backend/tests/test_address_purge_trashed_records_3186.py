"""spatiumddi#3186 — deleting an address for good takes its trashed auto records.

Zone deleted first (its batch holds IPAM's record for the host), then the
address deleted permanently: the record's ``ip_address_id`` used to go NULL and
the zone's restore brought back a record owned by nothing.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

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
