"""A split-horizon render retires its server's queued ops without loading
them (#2227).

On the scale lab (one view, 2M records, seven servers) each server's queue
held about 813k record ops when a render finally ran, and
``retire_queued_ops`` loaded every one as an ORM object to stamp it applied:
about 4 kB each, 3.7 GB in the worker process on top of the render. That,
not the render, was the bulk of the ~7.5 GB process the 8Gi worker lost.

It now locks and stamps a chunk of ids at a time with one UPDATE each. These
tests pin what must not change with it: every covered op is retired, in
several chunks, stamped exactly as ``_mark_applied`` stamps one; ops it must
leave (another server's, a non-record kind, already applied) are left; a row
already in the session reads applied without a reload; and no
``DNSRecordOp`` row is loaded into the session to do it, which is what a
build without the change fails on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns import agent_config
from app.services.dns.agent_config import retire_queued_ops
from app.services.dns.record_ops import _mark_applied


async def _setup(db: AsyncSession) -> tuple[DNSServer, DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    servers = []
    for i in range(2):
        s = DNSServer(
            group_id=grp.id,
            driver="bind9",
            host=f"10.0.0.{i + 1}",
            name=f"srv{i}-{uuid.uuid4().hex[:6]}",
            is_primary=i == 0,
            is_enabled=True,
            agent_id=uuid.uuid4(),
        )
        db.add(s)
        servers.append(s)
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    return servers[0], servers[1], zone


def _op(server: DNSServer, zone: DNSZone, name: str, **kw: object) -> DNSRecordOp:
    fields: dict[str, object] = {
        "server_id": server.id,
        "zone_name": zone.name,
        "zone_id": zone.id,
        "op": "create",
        "record": {"name": name, "type": "A", "value": "10.9.9.9"},
        "state": "pending",
    }
    fields.update(kw)
    return DNSRecordOp(**fields)


@pytest.mark.asyncio
async def test_retire_stamps_every_covered_op_in_chunks_without_loading_rows(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = db_session
    server, other, zone = await _setup(db)
    mine = [
        _op(server, zone, f"h{i}", attempts=i % 3, last_error="earlier", state=st)
        for i, st in enumerate(["pending", "in_flight"] * 6)
    ]
    others = [
        _op(other, zone, "o1"),
        _op(server, zone, "rollover", op="dnssec_rollover", record={}),
        _op(server, zone, "done", state="applied"),
    ]
    db.add_all([*mine, *others])
    await db.commit()
    mine_ids = {op.id: op.attempts for op in mine}
    other_ids = {op.id: (op.state, op.attempts) for op in others}
    db.expunge_all()

    # 12 ops in chunks of 5: two full chunks and a short last one.
    monkeypatch.setattr(agent_config, "RETIRE_CHUNK", 5, raising=False)
    statements: list[str] = []
    loads: list[object] = []

    def _on_load(target: object, _ctx: object) -> None:
        loads.append(target)

    event.listen(DNSRecordOp, "load", _on_load)
    sync_engine = db.get_bind()

    def _stmt(_c: object, _cur: object, statement: str, *_a: object) -> None:
        if statement.lstrip().upper().startswith("UPDATE DNS_RECORD_OP"):
            statements.append(statement)

    event.listen(sync_engine, "before_cursor_execute", _stmt)
    try:
        server = await db.get(DNSServer, server.id)
        assert server is not None
        retired = await retire_queued_ops(db, server)
    finally:
        event.remove(DNSRecordOp, "load", _on_load)
        event.remove(sync_engine, "before_cursor_execute", _stmt)
    await db.commit()

    assert loads == [], "retire loaded DNSRecordOp rows into the session"
    assert retired == len(mine)
    assert len(statements) == 3, statements

    rows = {r.id: r for r in (await db.execute(select(DNSRecordOp))).scalars().all()}
    # Stamped exactly as the one helper stamps an applied op.
    for op_id, attempts_before in mine_ids.items():
        row = rows[op_id]
        expected = DNSRecordOp(attempts=attempts_before, last_error="x", next_attempt_at=None)
        _mark_applied(expected, row.applied_at)  # type: ignore[arg-type]
        assert row.state == "applied"
        assert row.attempts == expected.attempts
        assert row.last_error is None and row.next_attempt_at is None
        assert row.applied_at is not None and row.updated_at == row.applied_at
    for op_id, (state, attempts) in other_ids.items():
        assert (rows[op_id].state, rows[op_id].attempts) == (state, attempts)


@pytest.mark.asyncio
async def test_a_row_already_in_the_session_reads_applied_and_is_not_rewritten(
    db_session: AsyncSession,
) -> None:
    db = db_session
    server, _other, zone = await _setup(db)
    op = _op(server, zone, "h1", attempts=2)
    db.add(op)
    await db.commit()

    await retire_queued_ops(db, server)
    # The loaded row carries the retire as committed state: no reload, and
    # nothing dirty for a flush to write a second time (attempts would be 4).
    assert op.state == "applied" and op.attempts == 3
    assert op.applied_at is not None and op.last_error is None
    assert op not in db.dirty
    await db.commit()
    await db.refresh(op)
    assert op.state == "applied" and op.attempts == 3


@pytest.mark.asyncio
async def test_the_snapshot_gate_still_bounds_what_is_retired(
    db_session: AsyncSession,
) -> None:
    """``up_to`` alone (no visible_xacts): an op created after it is left."""
    db = db_session
    server, _other, zone = await _setup(db)
    old = _op(server, zone, "old", created_at=datetime(2026, 1, 1, tzinfo=UTC))
    new = _op(server, zone, "new", created_at=datetime(2026, 6, 1, tzinfo=UTC))
    db.add_all([old, new])
    await db.commit()
    n = await retire_queued_ops(db, server, up_to=datetime(2026, 3, 1, tzinfo=UTC))
    await db.commit()
    await db.refresh(old)
    await db.refresh(new)
    assert n == 1
    assert (old.state, new.state) == ("applied", "pending")
