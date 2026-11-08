"""The Trash sweep and the reverse-zone purge lock every zone's address rows in
ONE ascending pass before any zone is purged (#3751).

An auto-sync batch locks its rows in one ascending pass across zones (#3726); a
pass per zone interleaves with it into a 40P01. The spies record the order of
``lock_addresses_of_zones`` calls against ``purge_trashed_zone`` calls.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.dns.zone_purge as zone_purge_mod
import app.services.lock_order as lock_order_mod
from app.models.dns import DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet


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
