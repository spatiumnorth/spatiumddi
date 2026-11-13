"""#1254 — chunked log prune and age-out of terminal queue rows."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPConfigOp, DHCPServer
from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup
from app.models.event_subscription import EventOutbox, EventSubscription
from app.models.logs import DNSQueryLogEntry
from app.tasks import prune_logs
from app.tasks.prune_logs import (
    TERMINAL_FAILED_RETENTION_DAYS,
    TERMINAL_OK_RETENTION_DAYS,
    _prune_table,
    _sweep_with_session,
)

OLD_OK = timedelta(days=TERMINAL_OK_RETENTION_DAYS + 1)
OLD_FAILED = timedelta(days=TERMINAL_FAILED_RETENTION_DAYS + 1)


async def _count(db: AsyncSession, model: type) -> int:
    return (await db.scalar(select(func.count()).select_from(model))) or 0


async def _dns_server(db: AsyncSession) -> DNSServer:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    s = DNSServer(
        group_id=grp.id, name=f"d-{uuid.uuid4().hex[:6]}", host="127.0.0.1", driver="bind9"
    )
    db.add(s)
    await db.flush()
    return s


@pytest.mark.asyncio
async def test_log_prune_runs_in_chunks(db_session: AsyncSession) -> None:
    s = await _dns_server(db_session)
    old = datetime.now(UTC) - timedelta(days=5)
    for i in range(25):
        db_session.add(DNSQueryLogEntry(server_id=s.id, ts=old, qname=f"o{i}.example", raw="o"))
    await db_session.commit()

    calls = 0
    real = prune_logs._batched

    def small(model, where, *, batch_size):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return real(model, where, batch_size=10)

    removed = await _prune_table(
        db_session,
        "dns_query_log_entry",
        lambda: small(DNSQueryLogEntry, DNSQueryLogEntry.ts < datetime.now(UTC), batch_size=10),
        batch_size=10,
    )
    assert removed == 25
    assert calls == 3  # 10 + 10 + 5: bounded statements, not one big delete
    assert await _count(db_session, DNSQueryLogEntry) == 0


@pytest.mark.asyncio
async def test_time_budget_stops_the_loop_and_next_run_resumes(db_session: AsyncSession) -> None:
    s = await _dns_server(db_session)
    old = datetime.now(UTC) - timedelta(days=5)
    for i in range(25):
        db_session.add(DNSQueryLogEntry(server_id=s.id, ts=old, qname=f"o{i}.example", raw="o"))
    await db_session.commit()

    def stmt():  # type: ignore[no-untyped-def]
        return prune_logs._batched(
            DNSQueryLogEntry, DNSQueryLogEntry.ts < datetime.now(UTC), batch_size=10
        )

    first = await _prune_table(db_session, "t", stmt, batch_size=10, time_budget=0.0)
    assert first == 10
    assert await _count(db_session, DNSQueryLogEntry) == 15
    second = await _prune_table(db_session, "t", stmt, batch_size=10)
    assert second == 15


@pytest.mark.asyncio
async def test_sweep_ages_out_terminal_rows_only(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    dns = await _dns_server(db_session)
    dhcp = DHCPServer(name=f"h-{uuid.uuid4().hex[:6]}", host="127.0.0.1", driver="kea")
    sub = EventSubscription(
        name=f"s-{uuid.uuid4().hex[:6]}", url="https://r.invalid/h", enabled=True, event_types=None
    )
    db_session.add_all([dhcp, sub])
    await db_session.flush()

    def op(state: str, age: timedelta) -> DNSRecordOp:
        return DNSRecordOp(
            server_id=dns.id,
            zone_name="z.example.",
            op="create",
            record={"name": "w", "type": "A", "value": "10.0.0.1"},
            state=state,
            updated_at=now - age,
        )

    def ob(state: str, age: timedelta) -> EventOutbox:
        return EventOutbox(
            subscription_id=sub.id,
            event_type="x",
            payload={},
            state=state,
            modified_at=now - age,
        )

    def co(status: str, age: timedelta) -> DHCPConfigOp:
        return DHCPConfigOp(
            server_id=dhcp.id, op_type="reload", status=status, created_at=now - age
        )

    db_session.add_all(
        [
            op("applied", OLD_OK),  # gone
            op("superseded", OLD_OK),  # gone
            op("applied", timedelta(hours=1)),  # recent: kept
            op("failed", OLD_OK),  # failed kept 30 d
            op("failed", OLD_FAILED),  # gone
            op("pending", OLD_FAILED),  # never touched
            ob("delivered", OLD_OK),  # gone
            ob("delivered", timedelta(hours=1)),
            ob("dead", OLD_OK),  # kept
            ob("dead", OLD_FAILED),  # gone
            ob("pending", OLD_FAILED),
            co("acked", OLD_OK),  # gone
            co("acked", timedelta(hours=1)),
            co("failed", OLD_OK),
            co("failed", OLD_FAILED),  # gone
            co("pending", OLD_FAILED),
        ]
    )
    await db_session.commit()

    result = await _sweep_with_session(db_session)
    assert result["failed_tables"] == []
    assert result["dns_record_op_removed"] == 3
    assert result["event_outbox_removed"] == 2
    assert result["dhcp_config_op_removed"] == 2

    assert sorted(r[0] for r in (await db_session.execute(select(DNSRecordOp.state))).all()) == [
        "applied",
        "failed",
        "pending",
    ]
    assert sorted(r[0] for r in (await db_session.execute(select(EventOutbox.state))).all()) == [
        "dead",
        "delivered",
        "pending",
    ]
    assert sorted(r[0] for r in (await db_session.execute(select(DHCPConfigOp.status))).all()) == [
        "acked",
        "failed",
        "pending",
    ]

    # Idempotent (#9): a second run finds nothing.
    again = await _sweep_with_session(db_session)
    assert again["dns_record_op_removed"] == again["event_outbox_removed"] == 0
    assert again["dhcp_config_op_removed"] == 0
