"""The Trash sweep and the reverse-zone purge lock every zone's address rows in
ONE ascending pass before any zone is purged (#3751).

An auto-sync batch locks its rows in one ascending pass across zones (#3726); a
pass per zone interleaves with it into a 40P01. The spies record the order of
``lock_addresses_of_zones`` calls against ``purge_trashed_zone`` calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.dns.zone_purge as zone_purge_mod
import app.services.lock_order as lock_order_mod
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from tests.conftest import _TestSessionLocal


def _spy(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, list[Any]]]:
    events: list[tuple[str, list[Any]]] = []
    real_lock = lock_order_mod.lock_addresses_of_zones
    real_purge = zone_purge_mod.purge_trashed_zone

    async def lock(db: Any, zone_ids: Any) -> Any:
        ids = list(zone_ids)
        events.append(("lock", ids))
        return await real_lock(db, ids)

    async def purge(db: Any, zone: Any) -> None:
        events.append(("purge", [zone.id]))
        await real_purge(db, zone)

    monkeypatch.setattr(lock_order_mod, "lock_addresses_of_zones", lock)
    monkeypatch.setattr(zone_purge_mod, "purge_trashed_zone", purge)
    return events


def _assert_one_pass_first(events: list[tuple[str, list[Any]]], zone_ids: set[Any]) -> None:
    first_purge = next(i for i, (kind, _) in enumerate(events) if kind == "purge")
    before = [ids for kind, ids in events[:first_purge] if kind == "lock"]
    assert any(set(ids) == zone_ids for ids in before), events


@pytest.mark.asyncio
async def test_trash_sweep_locks_all_zones_before_the_first_purge(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks.trash_purge import _purge_dns_zones

    group = DNSServerGroup(name="g3751-sweep")
    db_session.add(group)
    await db_session.flush()
    zones = [
        DNSZone(
            group_id=group.id,
            name=f"z{i}-3751.test.",
            kind="forward",
            deleted_at=datetime.now(UTC) - timedelta(days=40),
        )
        for i in range(3)
    ]
    db_session.add_all(zones)
    await db_session.commit()
    zone_ids = {z.id for z in zones}
    events = _spy(monkeypatch)

    purged, skipped = await _purge_dns_zones(db_session, datetime.now(UTC) - timedelta(days=30))
    assert (purged, skipped) == (3, 0)
    _assert_one_pass_first(events, zone_ids)


@pytest.mark.asyncio
async def test_reverse_zone_purge_locks_all_zones_before_the_first_purge(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.dns.reverse_zone import purge_auto_reverse_zones

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.75.0.0/16", name="b")
    group = DNSServerGroup(name="g3751-rev")
    db_session.add_all([block, group])
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.75.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    zones = [
        DNSZone(
            group_id=group.id,
            name=f"{n}.75.10.in-addr.arpa.",
            kind="reverse",
            is_auto_generated=True,
            linked_subnet_id=subnet.id,
            deleted_at=datetime.now(UTC),
        )
        for n in (1, 2)
    ]
    db_session.add_all(zones)
    await db_session.commit()
    zone_ids = {z.id for z in zones}
    events = _spy(monkeypatch)

    await purge_auto_reverse_zones(db_session, [subnet])
    assert any(kind == "purge" for kind, _ in events), events
    _assert_one_pass_first(events, zone_ids)


async def _pid(db: AsyncSession) -> int:
    return int((await db.execute(text("SELECT pg_backend_pid()"))).scalar_one())


async def _wait_blocked_by(probe: AsyncSession, pid: int, by: int, deadline: float = 20.0) -> bool:
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
async def test_trash_sweep_and_an_ascending_batch_do_not_deadlock(
    db_session: AsyncSession,
) -> None:
    """On two real connections: a batch holds the LOWER-id address row (in
    zone B) and then asks for the higher one (in zone A). The sweep purges
    zone A before zone B. Locked one zone at a time, the sweep held A's row
    while waiting for B's, and the batch's second request closed the cycle
    (40P01). In one ascending pass the sweep waits on B's row holding nothing,
    so the batch takes A's row, commits, and both finish."""
    from app.tasks.trash_purge import _purge_dns_zones

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:8]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.76.0.0/16", name="b")
    group = DNSServerGroup(name="g3751-2conn")
    db_session.add_all([block, group])
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.76.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    trashed = datetime.now(UTC) - timedelta(days=40)
    # Zone A is inserted (and so, unordered, swept) first.
    zone_a = DNSZone(group_id=group.id, name="a-3751.test.", kind="forward", deleted_at=trashed)
    db_session.add(zone_a)
    await db_session.flush()
    zone_b = DNSZone(group_id=group.id, name="b-3751.test.", kind="forward", deleted_at=trashed)
    db_session.add(zone_b)
    await db_session.flush()
    # Zone B's row sorts first: the batch's ascending pass takes it first.
    low, high = sorted([uuid.uuid4(), uuid.uuid4()])
    db_session.add_all(
        [
            IPAddress(
                id=high, subnet_id=subnet.id, address="10.76.1.10", forward_zone_id=zone_a.id
            ),
            IPAddress(id=low, subnet_id=subnet.id, address="10.76.1.11", forward_zone_id=zone_b.id),
        ]
    )
    await db_session.commit()
    zone_ids = {zone_a.id, zone_b.id}

    lock_row = text("SELECT id FROM ip_address WHERE id = :i FOR NO KEY UPDATE")
    async with (
        _TestSessionLocal() as batch,
        _TestSessionLocal() as sweep,
        _TestSessionLocal() as probe,
    ):
        batch_pid, sweep_pid = await _pid(batch), await _pid(sweep)
        await batch.execute(lock_row, {"i": low})

        async def run_sweep() -> tuple[int, int]:
            result = await _purge_dns_zones(sweep, datetime.now(UTC) - timedelta(days=30))
            await sweep.commit()
            return result

        st = asyncio.create_task(run_sweep())
        try:
            assert await _wait_blocked_by(probe, sweep_pid, batch_pid), "sweep never waited"
            # Unfixed, the sweep now holds zone A's row: this closes the cycle.
            await batch.execute(lock_row, {"i": high})
            await batch.commit()
            purged, skipped = await asyncio.wait_for(st, timeout=60)
        finally:
            if not st.done():
                st.cancel()
                with contextlib.suppress(BaseException):
                    await st
    assert (purged, skipped) == (2, 0)
    db_session.expire_all()
    left = (
        (await db_session.execute(select(DNSZone.id).where(DNSZone.id.in_(zone_ids))))
        .scalars()
        .all()
    )
    assert left == []


@pytest.mark.asyncio
async def test_a_database_error_in_one_zone_does_not_undo_the_others(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep skips a zone whose purge raises and goes on. A DATABASE
    error there (a 40P01, a lock or statement timeout) aborts the transaction,
    and Postgres turns the sweep's closing COMMIT into a ROLLBACK without an
    error: the zones counted as purged, and the sweep's audit row, were all
    silently undone. Each zone now runs in a savepoint, which the error rolls
    back alone (the up-front address locks, taken outside it, stay held)."""
    from app.tasks.trash_purge import _purge_dns_zones

    group = DNSServerGroup(name="g3751-dberr")
    db_session.add(group)
    await db_session.flush()
    trashed = datetime.now(UTC) - timedelta(days=40)
    good = DNSZone(group_id=group.id, name="good-3751.test.", kind="forward", deleted_at=trashed)
    bad = DNSZone(group_id=group.id, name="bad-3751.test.", kind="forward", deleted_at=trashed)
    db_session.add_all([good, bad])
    await db_session.commit()
    good_id, bad_id = good.id, bad.id
    real_purge = zone_purge_mod.purge_trashed_zone

    async def purge(db: Any, zone: Any) -> None:
        if zone.id == bad_id:
            await db.execute(text("SELECT 1/0"))
        await real_purge(db, zone)

    monkeypatch.setattr(zone_purge_mod, "purge_trashed_zone", purge)

    async with _TestSessionLocal() as sweep:
        result = await _purge_dns_zones(sweep, datetime.now(UTC) - timedelta(days=30))
        await sweep.commit()
    assert result == (1, 1)
    db_session.expire_all()
    left = (
        (
            await db_session.execute(
                select(DNSZone.id)
                .where(DNSZone.id.in_([good_id, bad_id]))
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    assert left == [bad_id]
