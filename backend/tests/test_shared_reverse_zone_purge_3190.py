"""spatiumddi#3190 — purging one subnet from the Trash must not take another
trashed subnet's PTRs with the shared auto reverse zone.

Two /25s of one /24 share ``7.199.10.in-addr.arpa.``. A is deleted first (the
zone is re-linked to B), then B (the zone retires into B's batch). B's purge
used to purge that zone, and its FK cascade deleted A's trashed PTRs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone
from tests.test_subnet_delete_reverse_zone_1066 import (
    _admin_headers,
    _fixture,
    _subnet_row,
    _zone_row,
)
from tests.test_subnet_trash_retracts_dns_1906 import _address


async def _setup(client, db, headers):  # type: ignore[no-untyped-def]
    ids = await _fixture(db)
    space_id, block_id, gid, zid = ids
    from app.models.ipam import IPBlock

    child = IPBlock(
        space_id=uuid.UUID(space_id),
        parent_block_id=uuid.UUID(block_id),
        network="10.67.7.0/24",
        name="c",
    )
    db.add(child)
    await db.commit()
    sids = []
    for net in ("10.67.7.0/25", "10.67.7.128/25"):
        r = await client.post(
            "/api/v1/ipam/subnets",
            headers=headers,
            json={
                "space_id": space_id,
                "block_id": str(child.id),
                "network": net,
                "dns_group_id": gid,
                "dns_zone_id": zid,
            },
        )
        assert r.status_code == 201, r.text
        sids.append(r.json()["id"])
    a, b = sids
    await _address(client, headers, a, "10.67.7.10", "ha")
    await _address(client, headers, b, "10.67.7.130", "hb")
    zone = await _zone_row(db, gid, "7.67.10.in-addr.arpa.")
    assert zone is not None
    return a, b, gid, zone.id


async def _both_trashed(client, db, headers):  # type: ignore[no-untyped-def]
    a, b, gid, zid = await _setup(client, db, headers)
    for sid in (a, b):
        r = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
        assert r.status_code == 204, r.text
    return a, b, gid, zid


async def _ptrs(db: AsyncSession, zid: uuid.UUID) -> list[tuple[str, bool]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.deleted_at.is_(None))
            .where(DNSRecord.zone_id == zid, DNSRecord.record_type == "PTR")
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).all()
    return sorted((n, live) for n, live in rows)


async def _zone(db: AsyncSession, zid: uuid.UUID) -> DNSZone | None:
    return (
        await db.execute(
            select(DNSZone)
            .where(DNSZone.id == zid)
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_purging_b_keeps_a_batch_whole_and_a_restore_brings_back_zone_and_ptrs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    assert [n for n, _ in await _ptrs(db_session, zid)] == ["1", "10", "129", "130"]

    r = await client.delete(f"/api/v1/admin/trash/subnet/{b}", headers=headers)
    assert r.status_code == 204, r.text

    assert await _subnet_row(db_session, b) is None
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is not None
    a_row = await _subnet_row(db_session, a)
    assert a_row is not None and zone.deletion_batch_id == a_row.deletion_batch_id
    assert str(zone.linked_subnet_id) == a
    assert await _ptrs(db_session, zid) == [("1", False), ("10", False)]  # B's gone, A's kept

    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is None
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True)]
    # DNS sync reports no missing PTR for A's address.
    chk = await client.get(f"/api/v1/ipam/subnets/{a}/dns-sync/preview", headers=headers)
    assert chk.status_code == 200, chk.text
    assert chk.json()["missing"] == [] and chk.json()["reverse_zone_id"] == str(zid)


@pytest.mark.asyncio
async def test_restoring_b_first_then_a_keeps_everything(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    r = await client.post(f"/api/v1/admin/trash/subnet/{b}/restore", headers=headers)
    assert r.status_code == 200, r.text
    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is None
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True), ("129", True), ("130", True)]


@pytest.mark.asyncio
async def test_a_restored_before_b_is_purged_then_b_purge_leaves_the_zone_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    # A cannot come back while its zone sits in B's batch (#1957): the refusal
    # names the zone, and nothing is lost by it.
    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 409, r.text
    r = await client.delete(f"/api/v1/admin/trash/subnet/{b}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True)]


@pytest.mark.asyncio
async def test_purging_both_removes_zone_and_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    for sid in (b, a):
        r = await client.delete(f"/api/v1/admin/trash/subnet/{sid}", headers=headers)
        assert r.status_code == 204, r.text
    assert await _zone(db_session, zid) is None
    assert await _ptrs(db_session, zid) == []


@pytest.mark.asyncio
async def test_the_expiry_sweep_of_b_does_not_take_a_unexpired_ptrs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.ipam import Subnet
    from app.tasks.trash_purge import _purge_dns_zones

    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    old = datetime.now(UTC) - timedelta(days=60)
    # Only B's batch is old: its subnet row, and the zone riding it.
    await db_session.execute(
        update(Subnet)
        .where(Subnet.id == uuid.UUID(b))
        .values(deleted_at=old)
        .execution_options(include_deleted=True)
    )
    await db_session.execute(
        update(DNSZone)
        .where(DNSZone.id == zid)
        .values(deleted_at=old)
        .execution_options(include_deleted=True)
    )
    await db_session.commit()

    purged, _skipped = await _purge_dns_zones(db_session, datetime.now(UTC) - timedelta(days=30))
    await db_session.commit()
    assert purged == 0
    zone = await _zone(db_session, zid)
    assert zone is not None
    assert (await _subnet_row(db_session, a)) is not None
    assert [("1", False), ("10", False)] == [
        x for x in await _ptrs(db_session, zid) if x[0] in ("1", "10")
    ]
    assert str(zone.linked_subnet_id) == a


async def _batch_of(db: AsyncSession, zid: uuid.UUID) -> dict[str, uuid.UUID | None]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.deletion_batch_id)
            .where(DNSRecord.zone_id == zid, DNSRecord.record_type == "PTR")
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).all()
    return dict(rows)


@pytest.mark.asyncio
async def test_the_handover_leaves_b_own_auto_ptrs_in_b_batch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Called while B's own PTRs are still there (B held back, or any caller that
    did not retract them first), the handover must not move them into A's batch:
    A's restore would publish PTRs for B's trashed addresses."""
    from app.tasks.trash_purge import _purge_dns_zones

    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    old = datetime.now(UTC) - timedelta(days=60)
    await db_session.execute(
        update(DNSZone)
        .where(DNSZone.id == zid)
        .values(deleted_at=old)
        .execution_options(include_deleted=True)
    )
    await db_session.commit()
    b_row = await _subnet_row(db_session, b)
    assert b_row is not None
    b_batch = b_row.deletion_batch_id

    await _purge_dns_zones(db_session, datetime.now(UTC) - timedelta(days=30))
    await db_session.commit()
    a_row = await _subnet_row(db_session, a)
    assert a_row is not None
    batches = await _batch_of(db_session, zid)
    assert batches["1"] == batches["10"] == a_row.deletion_batch_id
    assert batches["129"] == batches["130"] == b_batch


@pytest.mark.asyncio
async def test_the_full_expiry_sweep_hands_the_zone_to_a(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Through ``_sweep``: B's whole batch is past retention, A's is not."""
    from app.models.settings import PlatformSettings
    from app.services.soft_delete import TYPE_TO_MODEL
    from app.tasks.trash_purge import _sweep

    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    if (await db_session.execute(select(PlatformSettings).limit(1))).scalar_one_or_none() is None:
        db_session.add(PlatformSettings())
    b_row = await _subnet_row(db_session, b)
    assert b_row is not None
    b_batch = b_row.deletion_batch_id
    old = datetime.now(UTC) - timedelta(days=90)
    for model in TYPE_TO_MODEL.values():
        await db_session.execute(
            update(model)
            .where(model.deletion_batch_id == b_batch)
            .values(deleted_at=old)
            .execution_options(include_deleted=True, synchronize_session=False)
        )
    await db_session.commit()

    result = await _sweep()
    assert result["per_type"]["subnet"] == 1, result
    assert result["per_type"]["dns_zone"] == 0, result

    db_session.expire_all()
    assert await _subnet_row(db_session, b) is None
    a_row = await _subnet_row(db_session, a)
    assert a_row is not None
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deletion_batch_id == a_row.deletion_batch_id
    assert str(zone.linked_subnet_id) == a
    assert await _ptrs(db_session, zid) == [("1", False), ("10", False)]

    from app.models.audit import AuditLog

    handover = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dns_zone", AuditLog.resource_id == str(zid)
                )
            )
        )
        .scalars()
        .all()
    )
    assert any((r.new_value or {}).get("handed_over_to_subnet") == a for r in handover)

    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True)]


@pytest.mark.asyncio
async def test_the_trash_purge_audits_the_handover(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.audit import AuditLog

    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    r = await client.delete(f"/api/v1/admin/trash/subnet/{b}", headers=headers)
    assert r.status_code == 204, r.text
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dns_zone", AuditLog.resource_id == str(zid)
                )
            )
        )
        .scalars()
        .all()
    )
    assert [
        (x.new_value or {}).get("handed_over_to_subnet") for x in rows if x.action == "update"
    ] == [a]
    assert not [x for x in rows if x.action == "permanent_delete"]


@pytest.mark.asyncio
async def test_a_permanent_delete_of_b_keeps_trashed_a_ptrs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The permanent subnet delete (``?permanent=true``) of B while A sits in the
    Trash used to delete the shared zone with every record in it, A's included."""
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _setup(client, db_session, headers)
    r = await client.delete(f"/api/v1/ipam/subnets/{a}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/ipam/subnets/{b}?permanent=true&force=true", headers=headers)
    assert r.status_code == 204, r.text

    assert await _subnet_row(db_session, b) is None
    a_row = await _subnet_row(db_session, a)
    assert a_row is not None
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is not None
    assert zone.deletion_batch_id == a_row.deletion_batch_id
    assert await _ptrs(db_session, zid) == [("1", False), ("10", False)]

    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is None
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True)]


@pytest.mark.asyncio
async def test_a_pre_2741_live_zone_left_on_b_keeps_trashed_a_ptrs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A zone still LIVE on trashed B (what the block / space deletes left before
    #2741) is retired by B's purge; it must not take A's trashed PTRs with it."""
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    zone = await _zone(db_session, zid)
    assert zone is not None
    zone.deleted_at = None
    zone.deleted_by_user_id = None
    zone.deletion_batch_id = None
    await db_session.commit()

    r = await client.delete(f"/api/v1/admin/trash/subnet/{b}", headers=headers)
    assert r.status_code == 204, r.text
    a_row = await _subnet_row(db_session, a)
    assert a_row is not None
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deletion_batch_id == a_row.deletion_batch_id
    assert await _ptrs(db_session, zid) == [("1", False), ("10", False)]
    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True)]


@pytest.mark.asyncio
async def test_three_sharers_hand_the_zone_down_the_line(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    space_id, block_id, gid, zid_fwd = ids
    from app.models.ipam import IPBlock

    child = IPBlock(
        space_id=uuid.UUID(space_id),
        parent_block_id=uuid.UUID(block_id),
        network="10.67.7.0/24",
        name="c",
    )
    db_session.add(child)
    await db_session.commit()
    sids = []
    for net in ("10.67.7.0/26", "10.67.7.64/26", "10.67.7.128/25"):
        r = await client.post(
            "/api/v1/ipam/subnets",
            headers=headers,
            json={
                "space_id": space_id,
                "block_id": str(child.id),
                "network": net,
                "dns_group_id": gid,
                "dns_zone_id": zid_fwd,
            },
        )
        assert r.status_code == 201, r.text
        sids.append(r.json()["id"])
    a, c, b = sids
    await _address(client, headers, a, "10.67.7.10", "ha")
    await _address(client, headers, c, "10.67.7.70", "hc")
    await _address(client, headers, b, "10.67.7.130", "hb")
    zone = await _zone_row(db_session, gid, "7.67.10.in-addr.arpa.")
    assert zone is not None
    zid = zone.id
    for sid in (a, c, b):
        r = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
        assert r.status_code == 204, r.text

    r = await client.delete(f"/api/v1/admin/trash/subnet/{b}", headers=headers)
    assert r.status_code == 204, r.text
    zone_now = await _zone(db_session, zid)
    assert zone_now is not None and str(zone_now.linked_subnet_id) == c
    r = await client.delete(f"/api/v1/admin/trash/subnet/{c}", headers=headers)
    assert r.status_code == 204, r.text
    zone_now = await _zone(db_session, zid)
    assert zone_now is not None and str(zone_now.linked_subnet_id) == a
    assert await _ptrs(db_session, zid) == [("1", False), ("10", False)]

    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True)]
