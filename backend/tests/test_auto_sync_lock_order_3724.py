"""The IPAM -> DNS auto-sync takes its address rows before any zone (#3724).

``_sync_dns_record`` locks a row's zone and then writes the row. Run row by row
the auto-sync's DDNS re-apply held a zone from its first row while writing the
address of its second, and a permanent zone delete (address rows, then the
zone, #3691) holding that address while it waited for the zone made a cycle
(40P01). The re-apply now locks every address it will write, ascending, first.

The test parks the re-apply right after its first row's sync (which holds the
zone), then has a "delete" take the SECOND row's address and ask for the zone.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.v1.ipam.router as router_mod
from app.models.ipam import IPAddress, Subnet
from app.tasks.ipam_dns_sync import _reapply_ddns_for_active_leases
from tests.conftest import _TestSessionLocal
from tests.test_ddns_lease_rename_1618 import _setup


@pytest.mark.asyncio
async def test_reapply_locks_addresses_before_the_first_zone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _server, subnet, zone, _ip = await _setup(db_session, 71)
    subnet_id, zone_id = subnet.id, zone.id
    for n in (61, 62):
        db_session.add(
            IPAddress(
                subnet_id=subnet_id,
                address=f"10.93.71.{n}",
                status="dhcp",
                auto_from_lease=True,
                hostname=f"h{n}",
            )
        )
    await db_session.commit()
    ids = sorted(
        (
            await db_session.execute(
                select(IPAddress.id).where(
                    IPAddress.subnet_id == subnet_id, IPAddress.auto_from_lease.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )
    first_synced: list[Any] = []

    parked, release = asyncio.Event(), asyncio.Event()
    real = router_mod._sync_dns_record
    calls = 0

    async def parking_sync(*a: Any, **k: Any) -> Any:
        nonlocal calls
        result = await real(*a, **k)
        calls += 1
        if calls == 1:
            first_synced.append(a[1].id)
        if calls == 1:
            parked.set()
            await release.wait()
        return result

    monkeypatch.setattr(router_mod, "_sync_dns_record", parking_sync)

    async def run_sync() -> None:
        async with _TestSessionLocal() as db:
            sn = await db.get(Subnet, subnet_id)
            assert sn is not None
            await _reapply_ddns_for_active_leases(db, sn)
            await db.commit()

    async def delete_like() -> None:
        async with _TestSessionLocal() as db:
            await db.execute(
                text("SELECT id FROM ip_address WHERE id = :i FOR NO KEY UPDATE"),
                {"i": next(i for i in ids if i != first_synced[0])},
            )
            await db.execute(
                text("SELECT id FROM dns_zone WHERE id = :z FOR NO KEY UPDATE"), {"z": zone_id}
            )
            await db.commit()

    sync_task = asyncio.create_task(run_sync())
    other: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(parked.wait(), 30)
        other = asyncio.create_task(delete_like())
        await asyncio.sleep(1)
        release.set()
        results = await asyncio.wait_for(
            asyncio.gather(sync_task, other, return_exceptions=True), 30
        )
    finally:
        release.set()
        for t in (sync_task, other):
            if t is not None and not t.done():
                t.cancel()
                with contextlib.suppress(BaseException):
                    await t
    assert results == [None, None], results
    assert calls >= 2


@pytest.mark.asyncio
async def test_sync_dns_commit_locks_addresses_before_the_first_zone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator's Sync DNS commit (subnet, block and space all go through
    ``_apply_dns_sync``) syncs its addresses row by row in one transaction
    too: it took the first address's zone and then wrote the second address,
    which a permanent zone delete could hold while it waited for that zone."""
    from app.api.v1.ipam.router import DnsSyncCommitRequest, _apply_dns_sync

    _server, subnet, zone, _ip = await _setup(db_session, 72, ddns=False)
    subnet_id, zone_id = subnet.id, zone.id
    for n in (61, 62):
        db_session.add(
            IPAddress(
                subnet_id=subnet_id,
                address=f"10.93.72.{n}",
                status="allocated",
                hostname=f"m{n}",
            )
        )
    await db_session.commit()
    ids = sorted(
        (
            await db_session.execute(
                select(IPAddress.id).where(
                    IPAddress.subnet_id == subnet_id, IPAddress.hostname.in_(["m61", "m62"])
                )
            )
        )
        .scalars()
        .all()
    )
    first_synced: list[Any] = []
    parked, release = asyncio.Event(), asyncio.Event()
    real = router_mod._sync_dns_record
    calls = 0

    async def parking_sync(*a: Any, **k: Any) -> Any:
        nonlocal calls
        result = await real(*a, **k)
        calls += 1
        if calls == 1:
            first_synced.append(a[1].id)
            parked.set()
            await release.wait()
        return result

    monkeypatch.setattr(router_mod, "_sync_dns_record", parking_sync)

    async def run_sync() -> None:
        async with _TestSessionLocal() as db:
            await _apply_dns_sync(
                db, DnsSyncCommitRequest(create_for_ip_ids=ids), restrict_subnet_id=subnet_id
            )
            await db.commit()

    async def delete_like() -> None:
        async with _TestSessionLocal() as db:
            await db.execute(
                text("SELECT id FROM ip_address WHERE id = :i FOR NO KEY UPDATE"),
                {"i": next(i for i in ids if i != first_synced[0])},
            )
            await db.execute(
                text("SELECT id FROM dns_zone WHERE id = :z FOR NO KEY UPDATE"), {"z": zone_id}
            )
            await db.commit()

    sync_task = asyncio.create_task(run_sync())
    other: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(parked.wait(), 30)
        other = asyncio.create_task(delete_like())
        await asyncio.sleep(1)
        release.set()
        results = await asyncio.wait_for(
            asyncio.gather(sync_task, other, return_exceptions=True), 30
        )
    finally:
        release.set()
        for t in (sync_task, other):
            if t is not None and not t.done():
                t.cancel()
                with contextlib.suppress(BaseException):
                    await t
    assert results == [None, None], results
    assert calls == 2


@pytest.mark.asyncio
async def test_lock_targets_include_each_record_owner_and_zone(db_session: AsyncSession) -> None:
    """A ticked or deleted record's own address is locked even when the
    address's ``dns_record_id`` names another record (a PTR, an extra-zone
    A): the update re-syncs that address and the stale delete clears its DNS
    cache, both writes to the row. The deleted record's zone is locked too."""
    from app.api.v1.ipam.router import DnsSyncCommitRequest, _dns_sync_lock_targets
    from app.models.dns import DNSRecord

    _server, subnet, zone, _ip = await _setup(db_session, 73, ddns=False)
    ip = IPAddress(subnet_id=subnet.id, address="10.93.73.9", status="allocated", hostname="p9")
    db_session.add(ip)
    await db_session.flush()
    ptr = DNSRecord(
        zone_id=zone.id,
        name="9",
        record_type="PTR",
        value="wrong.example.",
        ip_address_id=ip.id,
        auto_generated=True,
    )
    db_session.add(ptr)
    await db_session.commit()
    assert ip.dns_record_id is None

    upd_addrs, upd_zones = await _dns_sync_lock_targets(
        db_session, DnsSyncCommitRequest(update_record_ids=[ptr.id])
    )
    assert ip.id in upd_addrs
    del_addrs, del_zones = await _dns_sync_lock_targets(
        db_session,
        DnsSyncCommitRequest(delete_stale_record_ids=[ptr.id]),
        allowed_stale_ids=[ptr.id],
    )
    assert ip.id in del_addrs and zone.id in del_zones
    # A stale id the scope does not list is not deleted, so not locked.
    none_addrs, none_zones = await _dns_sync_lock_targets(
        db_session, DnsSyncCommitRequest(delete_stale_record_ids=[ptr.id])
    )
    assert none_addrs == set() and none_zones == set()
