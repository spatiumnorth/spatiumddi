"""DNS record ops reach every server in the order they were queued (#1489).

Reported by @stefanriegel on a 3-server Technitium group: a UniFi sync
queued a delete and a create of the same record in one transaction, and the
servers applied the pair in different orders, so the record went missing on
some of them while every op read ``applied``. Ops were ordered by
``(created_at, id)``; ``created_at`` is the transaction start, so the pair
tied, and ``id`` is a random UUID.

Each test here runs inside one transaction, so every op it queues shares
``created_at``, which is exactly the tie.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.agent_config import page_pending_ops
from app.services.dns.record_ops import (
    enqueue_record_op,
    enqueue_record_ops_batch,
    fail_attempts,
    queued_after,
)

PAIRS = 25  # with a random tie-break, 25 pairs all in order is ~3e-8


async def _group(db: AsyncSession, servers: int = 3) -> tuple[list[DNSServer], DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    rows = [
        DNSServer(
            group_id=grp.id,
            driver="technitium",
            host=f"10.0.0.{i + 1}",
            name=f"ddi0{i + 1}",
            is_primary=i == 0,
            is_enabled=True,
            agent_id=uuid.uuid4(),
        )
        for i in range(servers)
    ]
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add_all([*rows, zone])
    await db.flush()
    return rows, zone


def _record(i: int) -> dict:
    return {"name": f"host{i}", "type": "A", "value": f"192.0.2.{i + 1}", "ttl": 300}


def _pairs() -> list[dict]:
    ops: list[dict] = []
    for i in range(PAIRS):
        ops.append({"op": "delete", "record": _record(i)})
        ops.append({"op": "create", "record": _record(i)})
    return ops


def _shipped(page: list[dict]) -> list[tuple[str, str]]:
    return [(p["record"]["name"], p["op"]) for p in page]


EXPECTED = [(f"host{i}", op) for i in range(PAIRS) for op in ("delete", "create")]


async def test_a_batch_ships_to_every_server_in_queue_order(db_session: AsyncSession) -> None:
    servers, zone = await _group(db_session)
    await enqueue_record_ops_batch(db_session, zone, _pairs())

    for server in servers:
        page, _ = await page_pending_ops(db_session, server)
        assert _shipped(page) == EXPECTED, server.name


async def test_separate_enqueues_ship_in_queue_order_and_the_record_survives(
    db_session: AsyncSession,
) -> None:
    """The reported shape: a delete and a create queued by separate calls in
    one transaction. Each is stamped with the RRset as of its own call (the
    delete's empty, the create's holding the record), so the order decides
    whether the record exists. Last applied wins, as on the agent."""
    servers, zone = await _group(db_session)
    for o in _pairs():
        await enqueue_record_op(db_session, zone, o["op"], o["record"])

    for server in servers:
        page, _ = await page_pending_ops(db_session, server)
        assert _shipped(page) == EXPECTED, server.name
        served: dict[str, list] = {}
        for p in page:
            served[p["record"]["name"]] = p["record"]["rrset"]["members"]
        missing = [name for name, members in served.items() if not members]
        assert missing == [], f"{server.name} is missing {missing}"


async def test_every_new_op_gets_a_queue_position(db_session: AsyncSession) -> None:
    servers, zone = await _group(db_session, servers=1)
    rows = await enqueue_record_ops_batch(db_session, zone, _pairs())
    seqs = []
    for row in rows:
        assert row is not None
        await db_session.refresh(row, ["seq"])
        seqs.append(row.seq)
    assert None not in seqs
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)


async def _delete_then_create(db: AsyncSession) -> tuple[DNSRecordOp, DNSRecordOp]:
    _, zone = await _group(db, servers=1)
    delete = await enqueue_record_op(db, zone, "delete", _record(0))
    create = await enqueue_record_op(db, zone, "create", _record(0))
    assert delete is not None and create is not None
    assert delete.record["rrset"]["members"] == []
    assert create.record["rrset"]["members"] != []
    return delete, create


async def test_a_failed_delete_is_superseded_by_the_create_queued_after_it(
    db_session: AsyncSession,
) -> None:
    """Retrying the delete after the create applied would remove the record
    again. Before ``seq``, ops of one transaction were never each other's
    successor, so the delete retried."""
    delete, create = await _delete_then_create(db_session)
    create.state = "applied"
    delete.state = "in_flight"
    await db_session.flush()

    await fail_attempts(db_session, [(delete, "REFUSED")], now=datetime.now(UTC))
    assert delete.state == "superseded"
    assert delete.superseded_by == create.id


async def test_the_create_is_not_superseded_by_the_delete_before_it(
    db_session: AsyncSession,
) -> None:
    delete, create = await _delete_then_create(db_session)
    delete.state = "applied"
    create.state = "in_flight"
    await db_session.flush()

    await fail_attempts(db_session, [(create, "REFUSED")], now=datetime.now(UTC))
    assert create.state == "pending"


# ── queued_after ─────────────────────────────────────────────────────────────


def test_different_transactions_compare_by_start_time() -> None:
    t = datetime.now(UTC)
    later = t + timedelta(seconds=1)
    # The seq of a transaction that started later but inserted first does not
    # reorder it: across transactions the comparison is what it always was.
    assert queued_after(later, 1, t, 99) is True
    assert queued_after(t, 99, later, 1) is False


def test_one_transaction_compares_by_queue_order() -> None:
    t = datetime.now(UTC)
    assert queued_after(t, 6, t, 5) is True
    assert queued_after(t, 5, t, 6) is False
    assert queued_after(t, 5, t, 5) is False


def test_rows_from_before_the_column_tie() -> None:
    t = datetime.now(UTC)
    assert queued_after(t, None, t, None) is False
    assert queued_after(t, 5, t, None) is False
    assert queued_after(t, None, t, 5) is False


def test_the_model_carries_the_queue_column() -> None:
    assert DNSRecordOp.__table__.c.seq.server_default is not None
