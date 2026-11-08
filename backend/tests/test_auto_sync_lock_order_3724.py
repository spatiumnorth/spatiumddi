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


async def _auto_sync_subnet_with(db_session: AsyncSession, n: int, octet: int) -> None:
    """A DNS-bound subnet with ``n`` named, unsynced addresses, auto-sync on."""
    from app.models.settings import PlatformSettings

    _server, subnet, _zone, _ip = await _setup(db_session, octet, ddns=False)
    for k in range(n):
        db_session.add(
            IPAddress(
                subnet_id=subnet.id,
                address=f"10.93.{octet}.{100 + k}",
                status="allocated",
                hostname=f"b{k}",
            )
        )
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dns_auto_sync_enabled = True
    ps.dns_auto_sync_last_run_at = None
    await db_session.commit()


@pytest.mark.asyncio
async def test_auto_sync_commits_a_big_subnet_in_bounded_batches(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A subnet is committed in batches of ``SYNC_BATCH_SIZE`` addresses, each
    locking only its own rows, so a zone delete waits for one batch and not
    for the whole subnet (it waited ~2 min for 1,000 renames)."""
    import app.tasks.ipam_dns_sync as sync_mod

    # ``raising=False`` so this runs (and fails on its assertions) against a
    # build that commits a whole subnet at once and has no batch size.
    monkeypatch.setattr(sync_mod, "SYNC_BATCH_SIZE", 3, raising=False)
    await _auto_sync_subnet_with(db_session, 7, 74)

    locked_per_call: list[int] = []
    real_lock = router_mod._lock_dns_sync_rows

    async def counting_lock(db: Any, address_ids: Any, **k: Any) -> Any:
        ids = set(address_ids)
        locked_per_call.append(len(ids))
        return await real_lock(db, ids, **k)

    monkeypatch.setattr(router_mod, "_lock_dns_sync_rows", counting_lock)
    commits = 0
    real_commit = AsyncSession.commit

    async def counting_commit(self: AsyncSession) -> None:
        nonlocal commits
        commits += 1
        await real_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", counting_commit)

    result = await sync_mod._run_auto_sync()
    assert result["errors"] == 0, result
    assert result["created"] == 7, result
    assert result["subnets_touched"] == 1
    # 7 addresses (plus the fixture's own) -> every batch within the bound.
    assert len(locked_per_call) >= 3
    assert max(locked_per_call) <= 3, locked_per_call
    assert sum(locked_per_call) >= 7


@pytest.mark.asyncio
async def test_auto_sync_failed_batch_rolls_back_alone_and_names_itself(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.ipam_dns_sync as sync_mod
    from app.models.audit import AuditLog

    monkeypatch.setattr(sync_mod, "SYNC_BATCH_SIZE", 2)
    await _auto_sync_subnet_with(db_session, 6, 75)

    real_batch = sync_mod._sync_batch
    seen = 0

    async def flaky(db: Any, subnet_id: Any, batch: Any, **k: Any) -> Any:
        nonlocal seen
        seen += 1
        counts = await real_batch(db, subnet_id, batch, **k)
        if seen == 2:
            raise RuntimeError("boom")
        return counts

    monkeypatch.setattr(sync_mod, "_sync_batch", flaky)
    result = await sync_mod._run_auto_sync()
    assert seen >= 3
    # The failed batch's rows are rolled back, the others committed and counted.
    assert result["errors"] == 1, result
    assert 0 < result["created"] < 6 + 1, result
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "dns-sync")))
        .scalars()
        .all()
    )
    msgs = [e for a in audit for e in (a.new_value or {}).get("errors", [])]
    assert any("batch 2/" in m and "addresses" in m and "boom" in m for m in msgs), msgs


async def _between_batches(monkeypatch: pytest.MonkeyPatch, before_second: Any) -> None:
    """Run ``before_second`` (committed, on its own session) after the first
    batch of the run has committed and before the second one starts."""
    import app.tasks.ipam_dns_sync as sync_mod

    real_batch = sync_mod._sync_batch
    seen = 0

    async def hooked(db: Any, subnet_id: Any, batch: Any, **k: Any) -> Any:
        nonlocal seen
        seen += 1
        if seen == 2:
            await before_second()
        return await real_batch(db, subnet_id, batch, **k)

    monkeypatch.setattr(sync_mod, "_sync_batch", hooked)


async def _forward_records(db: AsyncSession, subnet_id: Any) -> dict[str, list[Any]]:
    from app.models.dns import DNSRecord

    rows = (
        await db.execute(
            select(IPAddress.hostname, DNSRecord.name, DNSRecord.zone_id)
            .join(DNSRecord, DNSRecord.ip_address_id == IPAddress.id)
            .where(
                IPAddress.subnet_id == subnet_id,
                DNSRecord.record_type == "A",
                DNSRecord.auto_generated.is_(True),
            )
        )
    ).all()
    out: dict[str, list[Any]] = {}
    for host, name, zone_id in rows:
        out.setdefault(host, []).append((name, zone_id))
    return out


@pytest.mark.asyncio
async def test_auto_sync_zone_purged_between_batches_writes_nothing_into_it(
    client: Any, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A permanent zone delete that lands between two batches of one subnet:
    the later batches publish nothing into the deleted zone, report no error,
    and the run does not fail. The plan named the zone; the batch must not
    trust it (nor a subnet object cached from an earlier batch)."""
    import app.tasks.ipam_dns_sync as sync_mod
    from app.models.dns import DNSZone
    from tests.test_ipam_alias_cname_exclusive_2080 import _headers

    monkeypatch.setattr(sync_mod, "SYNC_BATCH_SIZE", 1, raising=False)
    await _auto_sync_subnet_with(db_session, 4, 76)
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "10.93.76.0/24"))
    ).scalar_one()
    zone = await db_session.get(DNSZone, subnet.dns_zone_id)
    assert zone is not None
    subnet_id, zone_id, group_id = subnet.id, zone.id, zone.group_id
    h = await _headers(db_session)
    await db_session.commit()

    async def purge() -> None:
        resp = await client.delete(
            f"/api/v1/dns/groups/{group_id}/zones/{zone_id}?permanent=true", headers=h
        )
        assert resp.status_code == 204, resp.text

    await _between_batches(monkeypatch, purge)
    result = await sync_mod._run_auto_sync()
    assert result["errors"] == 0, result
    db_session.expire_all()
    assert await db_session.get(DNSZone, zone_id) is None
    # Nothing published into the purged zone, and the addresses left after the
    # delete got no forward record at all (the subnet names no zone now).
    fwd = await _forward_records(db_session, subnet_id)
    assert all(z != zone_id for recs in fwd.values() for _n, z in recs), fwd
    assert len(fwd) <= 1, fwd


@pytest.mark.asyncio
async def test_auto_sync_later_batch_publishes_the_live_name(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An address renamed after the plan but before its batch is published
    under its new name, not the one the plan read."""
    import app.tasks.ipam_dns_sync as sync_mod

    monkeypatch.setattr(sync_mod, "SYNC_BATCH_SIZE", 1, raising=False)
    await _auto_sync_subnet_with(db_session, 4, 77)
    subnet_id = (
        await db_session.execute(select(Subnet.id).where(Subnet.network == "10.93.77.0/24"))
    ).scalar_one()
    await db_session.commit()
    renamed: list[str] = []

    async def rename() -> None:
        # Every address the first batch did not publish gets a new name.
        from app.models.dns import DNSRecord

        async with _TestSessionLocal() as db:
            published = select(DNSRecord.ip_address_id).where(
                DNSRecord.record_type == "A", DNSRecord.ip_address_id.is_not(None)
            )
            rows = (
                (
                    await db.execute(
                        select(IPAddress).where(
                            IPAddress.subnet_id == subnet_id,
                            IPAddress.hostname.like("b%"),
                            IPAddress.id.not_in(published),
                        )
                    )
                )
                .scalars()
                .all()
            )
            for ip in rows:
                ip.hostname = f"re{ip.hostname}"
                renamed.append(ip.hostname)
            await db.commit()

    await _between_batches(monkeypatch, rename)
    result = await sync_mod._run_auto_sync()
    assert result["errors"] == 0, result
    db_session.expire_all()
    fwd = await _forward_records(db_session, subnet_id)
    assert renamed, "the hook renamed nothing"
    for host in renamed:
        assert host in fwd, (host, fwd)
    for host, recs in fwd.items():
        assert [n for n, _z in recs] == [host], fwd


@contextlib.contextmanager
def _capture_locks(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The order of zone-gate and address-row lock calls, as
    ``(kind, exclusive)`` tuples; ``kind`` is ``"gate"`` or ``"rows"``."""
    import app.services.lock_order as lo

    seen: list[tuple[str, bool]] = []
    real_gate, real_rows = lo.lock_zone_gate, lo._lock_address_ids

    async def gate(db: Any, zone_ids: Any, *, exclusive: bool) -> None:
        zone_ids = list(zone_ids)
        if zone_ids:
            seen.append(("gate", exclusive))
        await real_gate(db, zone_ids, exclusive=exclusive)

    async def rows(db: Any, ids: Any, **k: Any) -> None:
        ids = list(ids)
        if ids:
            seen.append(("rows", False))
        await real_rows(db, ids, **k)

    monkeypatch.setattr(lo, "lock_zone_gate", gate)
    monkeypatch.setattr(lo, "_lock_address_ids", rows)
    yield seen


@pytest.mark.asyncio
async def test_each_batch_takes_the_shared_zone_gate_before_its_address_rows(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A permanent zone delete takes the zone's gate exclusive, and Postgres
    queues a new shared request behind it: the batch after the one the delete
    waits on waits for the delete, not the other way round. So every batch
    takes the gate shared, before its first address row."""
    import app.tasks.ipam_dns_sync as sync_mod

    monkeypatch.setattr(sync_mod, "SYNC_BATCH_SIZE", 2)
    await _auto_sync_subnet_with(db_session, 4, 78)
    with _capture_locks(monkeypatch) as seen:
        result = await sync_mod._run_auto_sync()
    assert result["errors"] == 0, result
    # Each batch: a shared gate first, then its address rows, never rows first.
    assert seen[0] == ("gate", False), seen
    gate_at = [i for i, e in enumerate(seen) if e[0] == "gate"]
    assert len(gate_at) >= 2 and all(not seen[i][1] for i in gate_at), seen
    for i, e in enumerate(seen):
        if e[0] == "rows":
            assert any(g < i for g in gate_at), seen
    # The gate of every batch precedes that batch's rows: between two gates
    # there is at least one row lock and never a row lock before the first.
    for g, nxt in zip(gate_at, [*gate_at[1:], len(seen)], strict=True):
        assert all(e[0] == "rows" for e in seen[g + 1 : nxt]), seen


@pytest.mark.asyncio
async def test_permanent_zone_delete_takes_the_exclusive_gate_before_address_rows(
    client: Any, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.ipam_dns_sync as sync_mod
    from app.models.dns import DNSZone
    from tests.test_ipam_alias_cname_exclusive_2080 import _headers

    await _auto_sync_subnet_with(db_session, 2, 79)
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "10.93.79.0/24"))
    ).scalar_one()
    zone = await db_session.get(DNSZone, subnet.dns_zone_id)
    assert zone is not None
    zone_id, group_id = zone.id, zone.group_id
    h = await _headers(db_session)
    await db_session.commit()
    # Publish first, so the addresses link to the zone and the delete has rows.
    assert (await sync_mod._run_auto_sync())["created"] == 2
    with _capture_locks(monkeypatch) as seen:
        resp = await client.delete(
            f"/api/v1/dns/groups/{group_id}/zones/{zone_id}?permanent=true", headers=h
        )
    assert resp.status_code == 204, resp.text
    assert seen and seen[0] == ("gate", True), seen
    assert ("rows", False) in seen, seen


@pytest.mark.asyncio
async def test_reapply_in_a_batch_whose_zone_was_deleted_counts_nothing(
    client: Any, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch that waited on a zone delete and then writes nothing adds
    nothing to the run's totals."""
    import app.tasks.ipam_dns_sync as sync_mod
    from app.models.dns import DNSZone
    from app.models.settings import PlatformSettings
    from tests.test_ipam_alias_cname_exclusive_2080 import _headers

    monkeypatch.setattr(sync_mod, "SYNC_BATCH_SIZE", 2)
    _server, subnet, zone, _ip = await _setup(db_session, 80)
    for n in range(4):
        db_session.add(
            IPAddress(
                subnet_id=subnet.id,
                address=f"10.93.80.{100 + n}",
                status="dhcp",
                auto_from_lease=True,
                hostname=f"m{n}",
            )
        )
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dns_auto_sync_enabled = True
    ps.dns_auto_sync_last_run_at = None
    zone_id, group_id = zone.id, zone.group_id
    h = await _headers(db_session)
    await db_session.commit()

    written_before: list[int] = []

    async def purge() -> None:
        from app.models.dns import DNSRecord

        written_before.append(
            len(
                (
                    await db_session.execute(
                        select(DNSRecord.id).where(
                            DNSRecord.record_type == "A", DNSRecord.auto_generated.is_(True)
                        )
                    )
                ).all()
            )
        )
        resp = await client.delete(
            f"/api/v1/dns/groups/{group_id}/zones/{zone_id}?permanent=true", headers=h
        )
        assert resp.status_code == 204, resp.text

    # The delete lands while the second batch waits for its locks: after the
    # batch has read its subnet and DDNS state, before it writes anything.
    real_lock = router_mod._lock_dns_sync_rows
    calls = 0

    async def purge_then_lock(db: Any, ids: Any, **k: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            await purge()
        return await real_lock(db, ids, **k)

    monkeypatch.setattr(router_mod, "_lock_dns_sync_rows", purge_then_lock)
    result = await sync_mod._run_auto_sync()
    assert result["errors"] == 0, result
    db_session.expire_all()
    assert await db_session.get(DNSZone, zone_id) is None
    # The run reports what it wrote: the first batch's records, none from the
    # batch that found its zone gone.
    assert written_before and written_before[0] > 0, written_before
    assert result["ddns_reapplied"] == written_before[0], (result, written_before)
    assert result["created"] == written_before[0], (result, written_before)


@pytest.mark.asyncio
async def test_batch_error_keeps_the_first_line_and_the_type() -> None:
    from app.tasks.ipam_dns_sync import _first_line

    exc = RuntimeError("canceling statement due to statement timeout\n[SQL: SELECT 1 ...]\n" * 50)
    out = _first_line(exc)
    assert out == "RuntimeError: canceling statement due to statement timeout"
    assert _first_line(ValueError()) == "ValueError"


async def _pid(db: AsyncSession) -> int:
    return int((await db.execute(text("SELECT pg_backend_pid()"))).scalar_one())


async def _wait_blocked_by(probe: AsyncSession, pid: int, by: int, deadline: float = 20.0) -> bool:
    """Poll until ``pid`` is waiting with ``by`` among its blockers (a hard
    block, or ``by`` ahead of it in a lock's wait queue)."""
    loop = asyncio.get_running_loop()
    end = loop.time() + deadline
    while loop.time() < end:
        blockers = (
            await probe.execute(text("SELECT pg_blocking_pids(:p)"), {"p": pid})
        ).scalar_one()
        if by in (blockers or []):
            return True
        await asyncio.sleep(0.05)
    return False


@pytest.mark.asyncio
async def test_next_batch_queues_behind_a_zone_delete_waiting_on_this_batch(
    db_session: AsyncSession,
) -> None:
    """The ddi-pg boundary, on three real connections: batch N holds the
    zone's gate (shared) and its address row; a permanent zone delete waits
    for it; batch N+1, on a DIFFERENT address of the zone, then asks for its
    locks. Ungated, batch N+1 took its row at once and the delete, reaching
    that row after batch N committed, waited a second whole batch. Gated,
    batch N+1 queues behind the delete, which finishes first."""
    import app.tasks.ipam_dns_sync as sync_mod
    from app.core.security import hash_password
    from app.models.auth import User
    from app.models.dns import DNSZone
    from app.services.ai.operations_risky import DeleteZoneArgs, _apply_delete_zone

    await _auto_sync_subnet_with(db_session, 2, 81)
    assert (await sync_mod._run_auto_sync())["created"] == 2
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "10.93.81.0/24"))
    ).scalar_one()
    subnet_id = subnet.id
    zone = await db_session.get(DNSZone, subnet.dns_zone_id)
    assert zone is not None
    zone_id, group_id = zone.id, zone.group_id
    ids = sorted(
        (
            await db_session.execute(
                select(IPAddress.id).where(
                    IPAddress.subnet_id == subnet_id, IPAddress.forward_zone_id == zone_id
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(ids) == 2, ids
    user = User(
        username="u3724-gate",
        email="u3724-gate@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.commit()
    user_id = user.id

    order: list[str] = []
    async with (
        _TestSessionLocal() as a,
        _TestSessionLocal() as b,
        _TestSessionLocal() as d,
        _TestSessionLocal() as probe,
    ):
        a_pid, b_pid, d_pid = await _pid(a), await _pid(b), await _pid(d)
        await router_mod._lock_dns_sync_rows(
            a, [ids[0]], restrict_subnet_id=subnet_id, gate_zones=True
        )

        async def delete() -> None:
            u = await d.get(User, user_id)
            assert u is not None
            await _apply_delete_zone(
                d, u, DeleteZoneArgs(group_id=group_id, zone_id=zone_id, permanent=True)
            )
            order.append("delete")

        async def next_batch() -> None:
            await router_mod._lock_dns_sync_rows(
                b, [ids[1]], restrict_subnet_id=subnet_id, gate_zones=True
            )
            order.append("batch")
            await b.commit()

        dt = asyncio.create_task(delete())
        try:
            assert await _wait_blocked_by(probe, d_pid, a_pid), "the delete never waited on batch N"
            bt = asyncio.create_task(next_batch())
            try:
                assert await _wait_blocked_by(
                    probe, b_pid, d_pid
                ), f"batch N+1 did not queue behind the delete: {order}"
                assert order == [], order
            finally:
                await a.commit()
                await asyncio.wait_for(asyncio.gather(dt, bt), timeout=60)
        finally:
            if not dt.done():
                dt.cancel()
    assert order == ["delete", "batch"], order
    db_session.expire_all()
    assert await db_session.get(DNSZone, zone_id) is None


@pytest.mark.asyncio
async def test_trash_sweep_takes_no_zone_gate(db_session: AsyncSession) -> None:
    """The sweep purges many zones in one transaction, each after the last
    one's rows; a gate taken per zone there would come after a row lock and
    out of key order (a batch gating two of them deadlocks with it). So a
    held shared gate does not stop the sweep."""
    from datetime import UTC, datetime, timedelta

    from app.models.dns import DNSServerGroup, DNSZone
    from app.services.lock_order import lock_zone_gate
    from app.tasks.trash_purge import _purge_dns_zones

    group = DNSServerGroup(name="g3724-sweep")
    db_session.add(group)
    await db_session.flush()
    zones = [
        DNSZone(
            group_id=group.id,
            name=f"z{i}-3724.test.",
            kind="forward",
            deleted_at=datetime.now(UTC) - timedelta(days=40),
        )
        for i in range(2)
    ]
    db_session.add_all(zones)
    await db_session.commit()
    zone_ids = [z.id for z in zones]

    async with _TestSessionLocal() as holder, _TestSessionLocal() as sweep:
        await lock_zone_gate(holder, zone_ids, exclusive=False)
        await sweep.execute(text("SET LOCAL lock_timeout = '3s'"))
        purged, skipped = await _purge_dns_zones(sweep, datetime.now(UTC) - timedelta(days=30))
        await sweep.commit()
        await holder.rollback()
    assert (purged, skipped) == (2, 0)
