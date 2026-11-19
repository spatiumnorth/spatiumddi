"""The RRset match the op page and the failed-ack path run (#2289).

``page_pending_ops`` looks up the ops still backing off for the RRsets in its
page, and ``fail_attempts`` the ops queued after a failed one. Both matched a
page's ``(zone, name, type)`` keys as a row ``IN`` list: up to 3,000 tuples,
9,000 bind parameters and a 9,000-comparison expression that Postgres 16
JIT-compiled in every process running it (1.3-1.5 GB each), which OOM-killed
the primary under seven polling agents. The keys now ride as three array
parameters, so the statement is the same size whatever the page holds — and
it must still match exactly the ops it matched before.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import event, select, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup
from app.services.dns.agent_config import page_pending_ops
from app.services.dns.record_ops import (
    RRSET_KEY_CHUNK,
    ack_op,
    backed_off_match_where,
    op_rrset_key,
    rrset_match_where,
)


async def _server(db: AsyncSession) -> DNSServer:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return server


def _op(
    server: DNSServer,
    zone: str,
    name: str,
    rtype: str,
    created_at: datetime,
    *,
    state: str = "pending",
    backing_off: bool = False,
    rrset: bool = True,
) -> DNSRecordOp:
    record: dict = {"name": name, "type": rtype, "value": "10.0.0.5"}
    if rrset:
        record["rrset"] = {"ttl": 3600, "members": [{"value": "10.0.0.5"}]}
    op = DNSRecordOp(
        server_id=server.id,
        zone_name=zone,
        op="create",
        record=record,
        state=state,
        created_at=created_at,
        updated_at=created_at,
    )
    if backing_off:
        op.attempts = 1
        op.next_attempt_at = datetime.now(UTC) + timedelta(minutes=10)
    return op


class _RRsetMatchStatements:
    """Parameter counts of the statements that run the RRset match."""

    def __init__(self) -> None:
        self.param_counts: list[int] = []
        self.statements: list[tuple[str, int]] = []

    def __call__(self, conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        if "dns_record_op.record ?" in statement and "upper(" in statement:
            self.param_counts.append(len(parameters or ()))
            self.statements.append((statement, len(parameters or ())))

    def __enter__(self) -> _RRsetMatchStatements:
        event.listen(Engine, "before_cursor_execute", self)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(Engine, "before_cursor_execute", self)


async def test_a_full_page_retires_exactly_its_backed_off_ops_in_a_fixed_size_statement(
    db_session: AsyncSession,
) -> None:
    server = await _server(db_session)
    other = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(hours=1)
    n = RRSET_KEY_CHUNK + 100  # a page past one chunk of keys

    shipping = [
        _op(server, f"z{i % 7}.example.", f"h{i}", "A", t0 + timedelta(milliseconds=10 * i))
        for i in range(n)
    ]
    older = t0 - timedelta(minutes=1)
    # Backing off for RRsets in the page: first, middle, past the first chunk,
    # and one spelled differently that normalises to the same key.
    retired = [
        _op(server, "z0.example.", "h0", "A", older, backing_off=True),
        _op(server, "z2.example.", "h1500", "A", older, backing_off=True),
        _op(server, f"z{(n - 1) % 7}.example.", f"h{n - 1}", "A", older, backing_off=True),
        _op(server, "z3.example.", "H10", "a", older, backing_off=True),
    ]
    kept = [
        # Same name, different type / zone: a different RRset.
        _op(server, "z1.example.", "h1", "AAAA", older, backing_off=True),
        _op(server, "z0.example.", "h1", "A", older, backing_off=True),
        # Same RRset, but another server's queue.
        _op(other, "z0.example.", "h0", "A", older, backing_off=True),
        # Same RRset, but carrying no whole-RRset state.
        _op(server, "z4.example.", "h4", "A", older, backing_off=True, rrset=False),
    ]
    db_session.add_all(shipping + retired + kept)
    await db_session.flush()

    with _RRsetMatchStatements() as seen:
        page, remaining = await page_pending_ops(db_session, server)

    assert len(page) == n and remaining == 0
    assert [p["op_id"] for p in page] == [str(op.id) for op in shipping], "page order"
    by_key = {op_rrset_key(op): op.id for op in shipping}
    for op in retired:
        assert op.state == "superseded", op.record
        assert op.superseded_by == by_key[op_rrset_key(op)]
    for op in kept:
        assert op.state == "pending", (op.zone_name, op.record)

    # The page's keys never become bind parameters: the statement is the same
    # size for 3,100 keys as for one.
    assert seen.param_counts, "the backed-off check did not run"
    assert max(seen.param_counts) < 20, seen.param_counts


async def test_a_failed_ack_finds_its_successor_in_a_fixed_size_statement(
    db_session: AsyncSession,
) -> None:
    server = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(minutes=5)
    failed = _op(server, "a.example.", "", "MX", t0, state="in_flight")
    newer = _op(server, "a.example.", "@", "mx", t0 + timedelta(seconds=30))
    db_session.add_all([failed, newer])
    await db_session.flush()

    with _RRsetMatchStatements() as seen:
        await ack_op(db_session, str(failed.id), "error", "timeout", server_id=server.id)

    assert (failed.state, failed.superseded_by) == ("superseded", newer.id)
    assert seen.param_counts and max(seen.param_counts) < 20, seen.param_counts


async def test_the_match_selects_exactly_the_ops_whose_key_is_listed(
    db_session: AsyncSession,
) -> None:
    server = await _server(db_session)
    t0 = datetime.now(UTC)
    ops = [
        _op(server, "a.example.", "", "A", t0),
        _op(server, "a.example.", "@", "A", t0),
        _op(server, "a.example.", "WWW", "cname", t0),
        _op(server, "a.example.", "www", "A", t0),
        _op(server, "b.example.", "www", "CNAME", t0),
        _op(server, "a.example.", "www", "CNAME", t0, rrset=False),
    ]
    db_session.add_all(ops)
    await db_session.flush()
    keys = [("a.example.", "@", "A"), ("a.example.", "www", "CNAME"), ("c.example.", "x", "A")]

    got = set(
        (
            await db_session.execute(
                select(DNSRecordOp.id).where(
                    DNSRecordOp.server_id == server.id, rrset_match_where(keys)
                )
            )
        )
        .scalars()
        .all()
    )

    assert got == {ops[0].id, ops[1].id, ops[2].id}
    assert got == {op.id for op in ops if op_rrset_key(op) in set(keys)}


def test_the_backed_off_lookup_names_the_partial_index_predicate_literally() -> None:
    """``ix_dns_record_op_server_backoff`` is partial on ``state = 'pending'``.
    The planner may use it only when it can prove the query's own predicate
    implies that, and a generic plan (which a prepared statement settles on)
    cannot prove it from ``state = $1``: it reads every op of the server
    instead. So the state must reach Postgres as a literal."""
    stmt = select(DNSRecordOp.id).where(
        backed_off_match_where(uuid.uuid4(), datetime.now(UTC), [("a.example.", "@", "A")])
    )
    sql = str(stmt.compile(dialect=postgresql.asyncpg.dialect()))
    assert "dns_record_op.state = 'pending'" in sql, sql


def _joins_over_the_keys(node: dict, inside_loop: bool = False) -> list[str]:
    """Every nested loop in ``node`` with the unnested key list under it: the
    shape that compares every candidate with every key."""
    found = []
    kind = node.get("Node Type")
    if kind == "Function Scan" and inside_loop:
        found.append(node.get("Function Name") or node.get("Alias", "?"))
    loop = inside_loop or kind == "Nested Loop"
    for child in node.get("Plans", ()):
        found.extend(_joins_over_the_keys(child, loop))
    return found


async def test_no_plan_of_the_rrset_match_rescans_the_keys_per_op(
    db_session: AsyncSession,
) -> None:
    """QA's case 4 on #2289. With statistics taken while the queue was idle
    (as autoanalyze takes them), the GENERIC plan a prepared statement
    switches to after five executions estimated one waiting op and ten keys,
    and joined them in a nested loop that rescanned the 3,000 keys once per
    waiting op: 7.5-10.9 s for 5,000 ops, against 35 ms for the custom
    plan. asyncpg prepares every statement, so the generic plan is the one
    that runs. Matched by grouping, the statements have no join over the
    keys for any plan to choose; checked on the plan Postgres builds, for the
    page's backed-off lookup and the failed ack's successor lookup."""
    server = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(hours=1)
    # An idle queue as the statistics see it: history, nothing waiting.
    db_session.add_all(
        [
            _op(
                server,
                f"z{i % 7}.example.",
                f"old{i}",
                "A",
                t0 - timedelta(days=1),
                state="applied",
            )
            for i in range(500)
        ]
    )
    await db_session.flush()
    await db_session.execute(text("ANALYZE dns_record_op"))

    failed = _op(server, "a.example.", "@", "MX", t0, state="in_flight")
    db_session.add_all(
        [_op(server, "z0.example.", f"h{i}", "A", t0 + timedelta(seconds=i)) for i in range(50)]
        + [_op(server, "z0.example.", "h1", "A", t0 - timedelta(minutes=1), backing_off=True)]
        + [failed, _op(server, "a.example.", "@", "MX", t0 + timedelta(minutes=1))]
    )
    await db_session.flush()

    with _RRsetMatchStatements() as seen:
        await page_pending_ops(db_session, server)
        await ack_op(db_session, str(failed.id), "error", "timeout", server_id=server.id)
    assert len(seen.statements) >= 2, "the backed-off and successor lookups did not both run"

    raw = (await (await db_session.connection()).get_raw_connection()).driver_connection
    await raw.execute("SET LOCAL plan_cache_mode = force_generic_plan")
    for n, (statement, params) in enumerate(seen.statements):
        await raw.execute(f"PREPARE rrset_match_{n} AS {statement}")
        args = ", ".join(["NULL"] * params)
        explained = await raw.fetchval(f"EXPLAIN (FORMAT JSON) EXECUTE rrset_match_{n}({args})")
        # The session's asyncpg json codec may already have decoded it.
        if isinstance(explained, str):
            explained = json.loads(explained)
        plan = explained[0]["Plan"]
        await raw.execute(f"DEALLOCATE rrset_match_{n}")
        assert not _joins_over_the_keys(plan), json.dumps(plan, indent=1)
