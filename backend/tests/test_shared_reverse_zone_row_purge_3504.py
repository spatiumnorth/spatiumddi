"""spatiumddi#3504 — Delete permanently on a shared auto reverse zone's OWN Trash
row must not take another trashed subnet's PTRs through the zone's FK cascade.

Two /25s of one /24 share ``7.67.10.in-addr.arpa.``. A is deleted first (the zone
is re-linked to B, A's PTRs stay in it under A's batch), then B (the zone retires
into B's batch and gets a Trash row). Purging that row used to delete the zone and,
by cascade, A's trashed PTRs; A's restore then came back with no reverse zone.
The purge is now refused while A's records are there.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSZone
from tests.test_shared_reverse_zone_purge_3190 import _both_trashed, _ptrs, _setup, _zone
from tests.test_subnet_delete_reverse_zone_1066 import _admin_headers, _subnet_row


@pytest.mark.asyncio
async def test_zone_row_purge_is_refused_while_another_batch_holds_ptrs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    assert [n for n, _ in await _ptrs(db_session, zid)] == ["1", "10", "129", "130"]

    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zid}", headers=headers)
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "7.67.10.in-addr.arpa" in detail
    assert "10.67.7.0/25" in detail  # A, whose records the purge would take
    assert "10.67.7.128/25" in detail  # B, the zone's own subnet: the way out

    # Nothing was touched: zone, A's and B's PTRs all still in the Trash.
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is not None
    assert await _ptrs(db_session, zid) == [
        ("1", False),
        ("10", False),
        ("129", False),
        ("130", False),
    ]

    # The way out the refusal names: purge B (hands the zone to A, #3190), and
    # A's restore brings zone and PTRs back.
    r = await client.delete(f"/api/v1/admin/trash/subnet/{b}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is None
    assert await _ptrs(db_session, zid) == [("1", True), ("10", True)]


@pytest.mark.asyncio
async def test_zone_row_purge_goes_through_once_the_other_subnet_is_purged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.audit import AuditLog

    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    r = await client.delete(f"/api/v1/admin/trash/subnet/{a}", headers=headers)
    assert r.status_code == 204, r.text
    # A's own PTRs went with A; only B's (in the zone's own batch) are left.
    assert [n for n, _ in await _ptrs(db_session, zid)] == ["129", "130"]

    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zid}", headers=headers)
    assert r.status_code == 204, r.text
    assert await _zone(db_session, zid) is None
    assert await _ptrs(db_session, zid) == []
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "dns_zone",
                    AuditLog.resource_id == str(zid),
                    AuditLog.action == "permanent_delete",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert (await _subnet_row(db_session, b)) is not None


@pytest.mark.asyncio
async def test_a_single_owner_reverse_zone_row_still_purges(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _setup(client, db_session, headers)
    # B first: the zone stays live, re-linked to A.
    r = await client.delete(f"/api/v1/ipam/subnets/{b}", headers=headers)
    assert r.status_code == 204, r.text
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is None  # A still lives in it
    r = await client.delete(f"/api/v1/ipam/subnets/{a}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/admin/trash/subnet/{b}", headers=headers)
    assert r.status_code == 204, r.text
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is not None
    # B is purged: only the zone's own batch (A's) holds records in it now.
    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zid}", headers=headers)
    assert r.status_code == 204, r.text
    assert await _zone(db_session, zid) is None


@pytest.mark.asyncio
async def test_the_sweep_of_a_older_batch_leaves_the_zone_purgeable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A's batch (the one whose PTRs sit in B's zone) expires first: the sweep
    takes A and its PTRs, keeps the zone with B, and the zone row then purges."""
    from app.models.settings import PlatformSettings
    from app.services.soft_delete import TYPE_TO_MODEL
    from app.tasks.trash_purge import _sweep

    headers = await _admin_headers(db_session)
    a, b, _gid, zid = await _both_trashed(client, db_session, headers)
    if (await db_session.execute(select(PlatformSettings).limit(1))).scalar_one_or_none() is None:
        db_session.add(PlatformSettings())
    a_row = await _subnet_row(db_session, a)
    assert a_row is not None
    a_batch = a_row.deletion_batch_id
    old = datetime.now(UTC) - timedelta(days=90)
    for model in TYPE_TO_MODEL.values():
        await db_session.execute(
            update(model)
            .where(model.deletion_batch_id == a_batch)
            .values(deleted_at=old)
            .execution_options(include_deleted=True, synchronize_session=False)
        )
    await db_session.commit()

    result = await _sweep()
    assert result["per_type"]["subnet"] == 1, result
    assert result["per_type"]["dns_zone"] == 0, result

    db_session.expire_all()
    assert await _subnet_row(db_session, a) is None
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is not None
    assert str(zone.linked_subnet_id) == b
    assert await _ptrs(db_session, zid) == [("129", False), ("130", False)]

    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zid}", headers=headers)
    assert r.status_code == 204, r.text
    assert (
        await db_session.execute(
            select(DNSZone.id)
            .where(DNSZone.id == uuid.UUID(str(zid)))
            .execution_options(include_deleted=True)
        )
    ).first() is None


@pytest.mark.asyncio
async def test_permanent_delete_of_a_live_shared_zone_is_refused_3826(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The zone route's ``?permanent=true`` (and the copilot's delete_dns_zone)
    on the LIVE zone shared with a trashed subnet is refused, as the Trash row's
    purge is (#3504): A's trashed PTRs are not ours to cascade away."""
    headers = await _admin_headers(db_session)
    a, b, gid, zid = await _setup(client, db_session, headers)
    r = await client.delete(f"/api/v1/ipam/subnets/{a}", headers=headers)
    assert r.status_code == 204, r.text
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is None  # live, kept by B
    before = await _ptrs(db_session, zid)
    assert any(not live for _, live in before)  # A's PTRs sit in the Trash

    r = await client.delete(f"/api/v1/dns/groups/{gid}/zones/{zid}?permanent=true", headers=headers)
    assert r.status_code == 409, r.text
    assert "10.67.7.0/25" in r.json()["detail"]
    zone = await _zone(db_session, zid)
    assert zone is not None and zone.deleted_at is None
    assert await _ptrs(db_session, zid) == before

    # A's restore still brings its PTRs back into the live zone. (The test client
    # shares one session across requests; production closes it after the 409.)
    await db_session.rollback()
    r = await client.post(f"/api/v1/admin/trash/subnet/{a}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert all(live for _, live in await _ptrs(db_session, zid))


@pytest.mark.asyncio
async def test_copilot_preview_refuses_the_same_delete_3826(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.auth import User
    from app.services.ai.operations_risky import DeleteZoneArgs, _preview_delete_zone

    headers = await _admin_headers(db_session)
    a, _b, gid, zid = await _setup(client, db_session, headers)
    r = await client.delete(f"/api/v1/ipam/subnets/{a}", headers=headers)
    assert r.status_code == 204, r.text
    user = (
        (await db_session.execute(select(User).where(User.is_superadmin.is_(True))))
        .scalars()
        .first()
    )
    res = await _preview_delete_zone(
        db_session, user, DeleteZoneArgs(group_id=gid, zone_id=zid, permanent=True)
    )
    assert res.ok is False
    assert "10.67.7.0/25" in res.detail


@pytest.mark.asyncio
async def test_permanent_delete_of_a_live_zone_with_no_trashed_sharer_still_works_3826(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    a, b, gid, zid = await _setup(client, db_session, headers)
    r = await client.delete(f"/api/v1/ipam/subnets/{a}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/admin/trash/subnet/{a}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/dns/groups/{gid}/zones/{zid}?permanent=true", headers=headers)
    assert r.status_code == 204, r.text
    assert await _zone(db_session, zid) is None


@pytest.mark.asyncio
async def test_permanent_delete_of_an_operator_made_zone_is_refused_3889(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An operator-made forward zone holding a trashed subnet's A record: the
    permanent delete is refused too (#3889), and that subnet's restore keeps it."""
    from app.models.dns import DNSRecord
    from tests.test_subnet_delete_reverse_zone_1066 import _bound_subnet, _fixture
    from tests.test_subnet_trash_retracts_dns_1906 import _address

    headers = await _admin_headers(db_session)
    ids = await _fixture(db_session)
    _space, _block, gid, zid = ids
    sid = await _bound_subnet(client, headers, ids, "10.67.9.0/25")
    await _address(client, headers, sid, "10.67.9.10", "hz")
    r = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert r.status_code == 204, r.text
    zone_id = uuid.UUID(zid)

    async def _fwd() -> list[tuple[str, bool]]:
        rows = (
            await db_session.execute(
                select(DNSRecord.name, DNSRecord.deleted_at)
                .where(DNSRecord.zone_id == zone_id, DNSRecord.record_type == "A")
                .execution_options(include_deleted=True, populate_existing=True)
            )
        ).all()
        return sorted((n, d is None) for n, d in rows)

    before = await _fwd()
    assert before == [("hz", False)]

    r = await client.delete(f"/api/v1/dns/groups/{gid}/zones/{zid}?permanent=true", headers=headers)
    assert r.status_code == 409, r.text
    assert "10.67.9.0/25" in r.json()["detail"]
    zone = await _zone(db_session, zone_id)
    assert zone is not None and zone.deleted_at is None
    assert await _fwd() == before

    await db_session.rollback()
    r = await client.post(f"/api/v1/admin/trash/subnet/{sid}/restore", headers=headers)
    assert r.status_code == 200, r.text
    assert await _fwd() == [("hz", True)]


async def _trashed_subnet_in_trashed_operator_zone(client, db_session, headers):  # type: ignore[no-untyped-def]
    from tests.test_subnet_delete_reverse_zone_1066 import _bound_subnet, _fixture
    from tests.test_subnet_trash_retracts_dns_1906 import _address

    ids = await _fixture(db_session)
    _space, _block, gid, zid = ids
    sid = await _bound_subnet(client, headers, ids, "10.67.9.0/25")
    await _address(client, headers, sid, "10.67.9.10", "hz")
    r = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert r.status_code == 204, r.text
    r = await client.delete(f"/api/v1/dns/groups/{gid}/zones/{zid}", headers=headers)
    assert r.status_code == 204, r.text
    zone = await _zone(db_session, uuid.UUID(zid))
    assert zone is not None and zone.deleted_at is not None and not zone.is_auto_generated
    return sid, uuid.UUID(zid)


@pytest.mark.asyncio
async def test_trash_purge_of_a_trashed_operator_zone_is_refused_3889(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    sid, zid = await _trashed_subnet_in_trashed_operator_zone(client, db_session, headers)
    r = await client.delete(f"/api/v1/admin/trash/dns_zone/{zid}", headers=headers)
    assert r.status_code == 409, r.text
    assert "10.67.9.0/25" in r.json()["detail"]
    assert await _zone(db_session, zid) is not None


@pytest.mark.asyncio
async def test_expiry_sweep_keeps_an_operator_zone_a_trashed_subnet_needs_3889(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.tasks.trash_purge import _purge_dns_zones

    headers = await _admin_headers(db_session)
    sid, zid = await _trashed_subnet_in_trashed_operator_zone(client, db_session, headers)
    old = datetime.now(UTC) - timedelta(days=60)
    await db_session.execute(
        update(DNSZone)
        .where(DNSZone.id == zid)
        .values(deleted_at=old)
        .execution_options(include_deleted=True)
    )
    await db_session.commit()
    cutoff = datetime.now(UTC) - timedelta(days=30)
    purged, skipped = await _purge_dns_zones(db_session, cutoff)
    await db_session.commit()
    assert (purged, skipped) == (0, 0)
    assert await _zone(db_session, zid) is not None

    # Once the subnet leaves the Trash, the next sweep takes the zone.
    r = await client.delete(f"/api/v1/admin/trash/subnet/{sid}", headers=headers)
    assert r.status_code == 204, r.text
    purged, _ = await _purge_dns_zones(db_session, cutoff)
    await db_session.commit()
    assert purged == 1
    assert await _zone(db_session, zid) is None
