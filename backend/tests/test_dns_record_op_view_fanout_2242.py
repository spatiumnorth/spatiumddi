"""Record ops carry the view they are for (#2242, slice 3).

A group with views queues one op per view that renders the zone, each naming
its view; a flat group queues one op with ``view_name`` NULL, as before.
Nothing ships differently: ops queued under views are still retired by the
bundle build, and ``ships_ops`` stays false there. The sweep narrows to the
view for a pinned zone.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.record_ops import (
    enqueue_agent_record_ops,
    enqueue_record_op,
    enqueue_record_ops_batch,
    sweep_zone_ops,
)


async def _group(
    db: AsyncSession, view_names: list[str], n_servers: int = 2
) -> tuple[DNSServerGroup, list[DNSServer], dict[str, DNSView]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    servers = [
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host=f"10.0.0.{i + 1}",
            name=f"srv{i}-{uuid.uuid4().hex[:4]}",
            is_primary=i == 0,
            is_enabled=True,
        )
        for i in range(n_servers)
    ]
    views = {
        n: DNSView(group_id=grp.id, name=n, order=i, match_clients=["10.0.0.0/8"])
        for i, n in enumerate(view_names)
    }
    db.add_all([*servers, *views.values()])
    await db.flush()
    return grp, servers, views


async def _zone(
    db: AsyncSession, grp: DNSServerGroup, name: str, view: DNSView | None = None
) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        view_id=view.id if view else None,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{name}",
        admin_email=f"admin.{name}",
    )
    db.add(zone)
    await db.flush()
    return zone


async def _record(
    db: AsyncSession, zone: DNSZone, view: DNSView | None = None, name: str = "www"
) -> DNSRecord:
    rec = DNSRecord(
        zone_id=zone.id,
        view_id=view.id if view else None,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value="10.0.0.9",
    )
    db.add(rec)
    await db.flush()
    return rec


def _payload(rec: DNSRecord) -> dict:
    return {
        "record_id": str(rec.id),
        "name": rec.name,
        "type": rec.record_type,
        "value": rec.value,
        "ttl": None,
    }


async def _ops(db: AsyncSession, server: DNSServer) -> list[DNSRecordOp]:
    return list(
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == server.id)))
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_flat_group_queues_one_op_with_no_view(db_session: AsyncSession) -> None:
    grp, servers, _ = await _group(db_session, [])
    zone = await _zone(db_session, grp, f"flat{uuid.uuid4().hex[:6]}.example.")
    rec = await _record(db_session, zone)
    await enqueue_record_op(db_session, zone, "create", _payload(rec))
    for s in servers:
        ops = await _ops(db_session, s)
        assert len(ops) == 1 and ops[0].view_name is None


@pytest.mark.asyncio
async def test_global_zone_fans_out_one_op_per_view(db_session: AsyncSession) -> None:
    grp, servers, _ = await _group(db_session, ["internal", "external", "dmz"])
    zone = await _zone(db_session, grp, f"glob{uuid.uuid4().hex[:6]}.example.")
    rec = await _record(db_session, zone)  # shared record: every view carries it
    await enqueue_record_op(db_session, zone, "create", _payload(rec))
    for s in servers:
        assert sorted(o.view_name or "" for o in await _ops(db_session, s)) == [
            "dmz",
            "external",
            "internal",
        ]


@pytest.mark.asyncio
async def test_view_scoped_record_reaches_only_its_view(db_session: AsyncSession) -> None:
    grp, servers, views = await _group(db_session, ["internal", "external"])
    zone = await _zone(db_session, grp, f"scoped{uuid.uuid4().hex[:6]}.example.")
    rec = await _record(db_session, zone, views["external"])
    await enqueue_record_op(db_session, zone, "create", _payload(rec))
    for s in servers:
        assert [o.view_name for o in await _ops(db_session, s)] == ["external"]


@pytest.mark.asyncio
async def test_pinned_zone_queues_into_its_pin_only(db_session: AsyncSession) -> None:
    grp, servers, views = await _group(db_session, ["internal", "external"])
    zone = await _zone(db_session, grp, f"pin{uuid.uuid4().hex[:6]}.example.", views["internal"])
    rec = await _record(db_session, zone)
    await enqueue_record_op(db_session, zone, "create", _payload(rec))
    assert [o.view_name for o in await _ops(db_session, servers[0])] == ["internal"]


@pytest.mark.asyncio
async def test_batch_and_agent_paths_fan_out_too(db_session: AsyncSession) -> None:
    grp, servers, _ = await _group(db_session, ["internal", "external"])
    zone = await _zone(db_session, grp, f"batch{uuid.uuid4().hex[:6]}.example.")
    recs = [await _record(db_session, zone, name=f"h{i}") for i in range(3)]
    returned = await enqueue_record_ops_batch(
        db_session, zone, [{"op": "create", "record": _payload(r)} for r in recs]
    )
    assert len(returned) == 3 and all(r is not None for r in returned)
    # 3 records x 2 views per server.
    for s in servers:
        assert len(await _ops(db_session, s)) == 6
    queued = await enqueue_agent_record_ops(
        db_session,
        zone,
        [{"op": "create", "record": _payload(recs[0])}],
        only_server_ids=[servers[1].id],
    )
    assert queued == 1
    assert len(await _ops(db_session, servers[1])) == 8
    assert len(await _ops(db_session, servers[0])) == 6


@pytest.mark.asyncio
async def test_hard_deleted_record_falls_back_to_every_view(db_session: AsyncSession) -> None:
    grp, servers, views = await _group(db_session, ["internal", "external"])
    zone = await _zone(db_session, grp, f"del{uuid.uuid4().hex[:6]}.example.")
    rec = await _record(db_session, zone, views["internal"])
    payload = _payload(rec)
    await db_session.delete(rec)  # hard-deleted: the row is gone by enqueue time
    await db_session.flush()
    await enqueue_record_op(db_session, zone, "delete", payload)
    # No row to read: falls back to every view rendering the zone, never none.
    assert sorted(o.view_name or "" for o in await _ops(db_session, servers[0])) == [
        "external",
        "internal",
    ]


@pytest.mark.asyncio
async def test_ops_queued_under_views_are_retired_as_before(db_session: AsyncSession) -> None:
    grp, servers, _ = await _group(db_session, ["internal", "external"], n_servers=1)
    zone = await _zone(db_session, grp, f"ret{uuid.uuid4().hex[:6]}.example.")
    rec = await _record(db_session, zone)
    await enqueue_record_op(db_session, zone, "create", _payload(rec))
    assert len(await _ops(db_session, servers[0])) == 2
    bundle = await build_config_bundle(db_session, servers[0])
    assert bundle["pending_record_ops"] == []
    assert [o.state for o in await _ops(db_session, servers[0])] == ["applied", "applied"]


@pytest.mark.asyncio
async def test_sweep_is_exact_for_a_pinned_zone_when_ops_name_their_view(
    db_session: AsyncSession,
) -> None:
    grp, (a, *_), views = await _group(db_session, ["internal", "external"], n_servers=1)
    name = f"split{uuid.uuid4().hex[:6]}.example."
    z_int = await _zone(db_session, grp, name, views["internal"])
    z_ext = await _zone(db_session, grp, name, views["external"])
    for view_name in ("internal", "external", None):  # None: queued before the column
        db_session.add(
            DNSRecordOp(
                server_id=a.id,
                zone_name=name,
                view_name=view_name,
                op="create",
                record={"name": "www", "type": "A", "value": "10.0.0.1"},
                state="pending",
            )
        )
    await db_session.flush()
    # internal's own op and the unattributable legacy one; external's stays.
    assert await sweep_zone_ops(db_session, z_int, grp.id) == 2
    assert [o.view_name for o in await _ops(db_session, a)] == ["external"]
    assert await sweep_zone_ops(db_session, z_ext, grp.id) == 1
