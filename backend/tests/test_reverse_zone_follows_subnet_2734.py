"""spatiumddi#2734 / #2735 — a subnet's auto reverse zone follows the subnet,
and a subnet that opted out of one stays out.

#2734: only the lone-subnet delete retired the zone. A block or space delete
left it live and served, linked to the trashed subnet; every purge left it
behind (live and unlinked, or in the Trash and restorable for a subnet that no
longer exists). #2735: ``skip_reverse_zone`` was consumed at create, so the
first named address's record sync created the zone it opted out of.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_subnet_delete_reverse_zone_1066 import (
    _admin_headers,
    _bound_subnet,
    _fixture,
    _subnet_row,
    _zone_row,
)

ZONE = "1.67.10.in-addr.arpa."


@pytest.mark.asyncio
async def test_block_delete_trashes_the_reverse_zone_and_restore_brings_it_back(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    space_id, block_id, gid, _zid = ids
    sid = await _bound_subnet(client, headers, ids, "10.67.1.0/24")
    zone_before = await _zone_row(db_session, gid, ZONE)
    assert zone_before is not None

    resp = await client.delete(f"/api/v1/ipam/blocks/{block_id}", headers=headers)
    assert resp.status_code == 204, resp.text

    zone = await _zone_row(db_session, gid, ZONE)
    subnet = await _subnet_row(db_session, sid)
    assert zone is not None and zone.deleted_at is not None
    assert subnet is not None and zone.deletion_batch_id == subnet.deletion_batch_id
    listed = await client.get(f"/api/v1/dns/groups/{gid}/zones", headers=headers)
    assert str(zone.id) not in {z["id"] for z in listed.json()}

    restored = await client.post(
        f"/api/v1/admin/trash/ip_block/{block_id}/restore", headers=headers
    )
    assert restored.status_code == 200, restored.text
    zone = await _zone_row(db_session, gid, ZONE)
    assert zone is not None and zone.deleted_at is None
    assert str(zone.linked_subnet_id) == sid


@pytest.mark.asyncio
async def test_block_purge_removes_the_reverse_zone_for_good(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    _space_id, block_id, gid, _zid = ids
    await _bound_subnet(client, headers, ids, "10.67.1.0/24")

    deleted = await client.delete(f"/api/v1/ipam/blocks/{block_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    resp = await client.delete(f"/api/v1/admin/trash/ip_block/{block_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_row(db_session, gid, ZONE) is None


@pytest.mark.asyncio
async def test_space_delete_then_purge_leaves_no_reverse_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    space_id, _block_id, gid, _zid = ids
    await _bound_subnet(client, headers, ids, "10.67.1.0/24")

    deleted = await client.delete(f"/api/v1/ipam/spaces/{space_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    zone = await _zone_row(db_session, gid, ZONE)
    assert zone is not None and zone.deleted_at is not None
    resp = await client.delete(f"/api/v1/admin/trash/ip_space/{space_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_row(db_session, gid, ZONE) is None


@pytest.mark.asyncio
async def test_lone_subnet_purge_takes_the_trashed_reverse_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    gid = ids[2]
    sid = await _bound_subnet(client, headers, ids, "10.67.1.0/24")

    deleted = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    zone = await _zone_row(db_session, gid, ZONE)
    assert zone is not None and zone.deleted_at is not None
    resp = await client.delete(f"/api/v1/admin/trash/subnet/{sid}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _subnet_row(db_session, sid) is None
    assert await _zone_row(db_session, gid, ZONE) is None


@pytest.mark.asyncio
async def test_purge_retires_a_live_zone_left_by_an_earlier_block_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Data written before the fix: the zone is LIVE, linked to a trashed
    subnet. Purging the block must still take it."""
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    _space_id, block_id, gid, _zid = ids
    await _bound_subnet(client, headers, ids, "10.67.1.0/24")
    deleted = await client.delete(f"/api/v1/ipam/blocks/{block_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    zone = await _zone_row(db_session, gid, ZONE)
    assert zone is not None
    zone.deleted_at = None
    zone.deletion_batch_id = None
    await db_session.commit()

    resp = await client.delete(f"/api/v1/admin/trash/ip_block/{block_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _zone_row(db_session, gid, ZONE) is None


@pytest.mark.asyncio
async def test_block_delete_keeps_a_zone_shared_with_a_subnet_outside_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Two /25s share one /24 zone; only the first sits in the deleted child
    block. The zone is re-linked to the survivor, not trashed."""
    from app.models.ipam import IPBlock

    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    space_id, block_id, gid, zid = ids
    child = IPBlock(
        space_id=uuid.UUID(space_id),
        parent_block_id=uuid.UUID(block_id),
        network="10.67.2.0/25",
        name="child",
    )
    db_session.add(child)
    await db_session.commit()
    first = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": space_id,
            "block_id": str(child.id),
            "network": "10.67.2.0/25",
            "dns_group_id": gid,
            "dns_zone_id": zid,
        },
    )
    assert first.status_code == 201, first.text
    second = await _bound_subnet(client, headers, ids, "10.67.2.128/25")

    deleted = await client.delete(f"/api/v1/ipam/blocks/{child.id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    zone = await _zone_row(db_session, gid, "2.67.10.in-addr.arpa.")
    assert zone is not None and zone.deleted_at is None
    assert str(zone.linked_subnet_id) == second


@pytest.mark.asyncio
async def test_skip_reverse_zone_survives_the_first_named_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    space_id, block_id, gid, zid = ids
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": space_id,
            "block_id": block_id,
            "network": "10.67.1.0/24",
            "dns_group_id": gid,
            "dns_zone_id": zid,
            "skip_reverse_zone": True,
        },
    )
    assert resp.status_code == 201, resp.text
    sid = resp.json()["id"]
    assert resp.json()["skip_reverse_zone"] is True
    assert await _zone_row(db_session, gid, ZONE) is None

    addr = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": "10.67.1.10", "hostname": "host1"},
    )
    assert addr.status_code == 201, addr.text
    assert await _zone_row(db_session, gid, ZONE) is None

    # An operator asking for THIS subnet's zone by name overrides the opt-out.
    made = await client.post(f"/api/v1/ipam/subnets/{sid}/reverse-zones/backfill", headers=headers)
    assert made.status_code == 200, made.text
    assert await _zone_row(db_session, gid, ZONE) is not None


@pytest.mark.asyncio
async def test_a_subnet_without_the_opt_out_still_gets_its_zone_from_the_catch_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    gid = ids[2]
    sid = await _bound_subnet(client, headers, ids, "10.67.1.0/24")
    zone_before = await _zone_row(db_session, gid, ZONE)
    assert zone_before is not None
    got = await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert got.json()["skip_reverse_zone"] is False
