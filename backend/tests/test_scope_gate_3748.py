"""The scope delete is not starved by a Kea HA pair's lease batches (#3748).

A lease-events batch holds its scope ``FOR KEY SHARE`` to its commit. Postgres
lets a new KEY SHARE join while another is held, even with a ``FOR UPDATE``
queued, so two agents posting overlapping batches kept the delete's
``FOR UPDATE`` waiting until the 30 s command timeout (503). A per-scope
advisory gate (``lock_scope_gates``) queues new batches behind the waiting
delete, which then waits only for the batches already running.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.main import app
from tests.conftest import _TestSessionLocal
from tests.test_lease_events_trashed_scope_3733 import (
    _estate,
    _post,
    concurrent_client,  # noqa: F401 — the fixture, shared
)

_KEY_SHARE = "SELECT id FROM dhcp_scope WHERE id = :s FOR KEY SHARE"


async def _wait_until(predicate: Any, what: str, timeout: float = 15.0) -> None:
    """Poll an async predicate; a timeout is an infrastructure failure (the
    state never arose), not the behaviour under test."""
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not await predicate():
        assert loop.time() < end, f"never observed: {what}"
        await asyncio.sleep(0.02)


async def _lock_waiting(pid: int) -> bool:
    """True when backend ``pid`` is blocked on a heavyweight lock (tuple,
    transactionid or advisory), as ``pg_stat_activity`` reports it."""
    async with _TestSessionLocal() as obs:
        row = await obs.execute(
            text("SELECT wait_event_type FROM pg_stat_activity WHERE pid = :p"), {"p": pid}
        )
        return row.scalar_one_or_none() == "Lock"


async def _batch_standin(
    scope_id: Any,
    gated: bool,
    pid_out: list[int],
    acquired: asyncio.Event,
    release: asyncio.Event,
    order: list[str],
) -> None:
    """A lease batch: gate (shared) then the scope ``FOR KEY SHARE``, held
    until ``release`` is set."""
    from app.services.lock_order import lock_scope_gates  # noqa: PLC0415

    async with _TestSessionLocal() as db:
        pid_out.append((await db.execute(text("SELECT pg_backend_pid()"))).scalar_one())
        if gated:
            await lock_scope_gates(db, [scope_id], exclusive=False)
        await db.execute(text(_KEY_SHARE), {"s": scope_id})
        order.append("batch")
        acquired.set()
        await release.wait()
        await db.commit()


async def _delete_like(scope_id: Any, gated: bool, pid_out: list[int], order: list[str]) -> None:
    from app.services.lock_order import lock_scope_gates  # noqa: PLC0415

    async with _TestSessionLocal() as db:
        pid_out.append((await db.execute(text("SELECT pg_backend_pid()"))).scalar_one())
        if gated:
            await lock_scope_gates(db, [scope_id], exclusive=True)
        await db.execute(
            text("SELECT id FROM dhcp_scope WHERE id = :s FOR UPDATE"), {"s": scope_id}
        )
        order.append("delete")  # recorded while still holding the row
        await db.commit()


@pytest.mark.parametrize("gated", [False, True])
@pytest.mark.asyncio
async def test_overlapping_key_shares_starve_a_for_update_unless_gated(
    db_session: AsyncSession, gated: bool
) -> None:
    """Driven by lock-wait evidence, not timing. Batch A holds the scope; the
    delete queues behind it (observed waiting); then batch B arrives and A
    ends. Ungated, B joins A's KEY SHARE past the queued FOR UPDATE and the
    delete is still blocked after A is gone (the reported 503); gated, B
    queues behind the delete's exclusive gate, so the delete gets the row as
    soon as A ends and B only runs after it."""
    _server, scope_id, _subnet, _admin = await _estate(db_session)
    app.dependency_overrides.pop(_auth_agent, None)
    a_pid: list[int] = []
    b_pid: list[int] = []
    d_pid: list[int] = []
    order: list[str] = []
    a_in, b_in = asyncio.Event(), asyncio.Event()
    a_out, b_out = asyncio.Event(), asyncio.Event()
    tasks: list[asyncio.Task[Any]] = []
    try:
        task_a = asyncio.create_task(_batch_standin(scope_id, gated, a_pid, a_in, a_out, order))
        tasks.append(task_a)
        await asyncio.wait_for(a_in.wait(), 15)

        delete = asyncio.create_task(_delete_like(scope_id, gated, d_pid, order))
        tasks.append(delete)

        async def _d_waiting() -> bool:
            return bool(d_pid) and await _lock_waiting(d_pid[0])

        await _wait_until(_d_waiting, "the delete waiting behind batch A")

        task_b = asyncio.create_task(_batch_standin(scope_id, gated, b_pid, b_in, b_out, order))
        tasks.append(task_b)
        if gated:
            # B queues behind the delete's exclusive gate instead of joining.
            async def _b_waiting() -> bool:
                return bool(b_pid) and await _lock_waiting(b_pid[0])

            await _wait_until(_b_waiting, "batch B queued behind the delete's gate")
            assert not b_in.is_set()
            a_out.set()
            await asyncio.wait_for(delete, 15)  # only A was ahead of it
            await asyncio.wait_for(b_in.wait(), 15)  # and B runs after it
            assert order == ["batch", "delete", "batch"], order
        else:
            await asyncio.wait_for(b_in.wait(), 15)  # B joined past the queue
            a_out.set()
            await asyncio.wait_for(task_a, 15)
            # A is gone, yet the delete is still blocked: starved by B.
            await asyncio.sleep(0.3)
            assert not delete.done()
            assert await _lock_waiting(d_pid[0])
    finally:
        a_out.set()
        b_out.set()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 30)
    # B released: the ungated delete now completes (no deadlock, just starved).
    assert delete.done() and delete.exception() is None


@contextlib.contextmanager
def _statements() -> Iterator[list[str]]:
    seen: list[str] = []

    def _record(conn: Any, cursor: Any, statement: str, *a: Any) -> None:
        if "pg_advisory_xact_lock" in statement or " FOR " in statement:
            seen.append(statement)

    event.listen(Engine, "before_cursor_execute", _record)
    try:
        yield seen
    finally:
        event.remove(Engine, "before_cursor_execute", _record)


def _first(seen: list[str], needle: str) -> int:
    return next(i for i, s in enumerate(seen) if needle in s)


@pytest.mark.asyncio
async def test_lease_batch_takes_the_shared_gate_before_its_first_row_lock(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    server, _scope_id, _subnet, _admin = await _estate(db_session)
    with _statements() as seen:
        assert (await _post(concurrent_client, server, ["10.31.1.10"])).status_code == 200
    # The gate is the batch's first lock: no row lock before it.
    assert seen and "pg_advisory_xact_lock_shared" in seen[0], seen
    assert _first(seen, "pg_advisory_xact_lock_shared") < _first(seen, "FROM dhcp_lease")
    assert _first(seen, "pg_advisory_xact_lock_shared") < _first(seen, "FOR KEY SHARE")


@pytest.mark.asyncio
async def test_scope_delete_takes_the_exclusive_gate_before_the_scope_row(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
) -> None:
    _server, scope_id, _subnet, admin = await _estate(db_session)
    with _statements() as seen:
        r = await concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    assert r.status_code in (200, 204), r.text
    i_gate = next(
        i
        for i, s in enumerate(seen)
        if "pg_advisory_xact_lock(" in s and "pg_advisory_xact_lock_shared" not in s
    )
    assert i_gate < _first(seen, "FOR UPDATE")


# ── The real paths: two agents' lease-events batches and the scope delete ──

#: How long each batch holds its scope ``FOR KEY SHARE`` before it goes on:
#: the zone wait the issue measured, made deterministic.
_HOLD = 0.8
#: The delete's budget. Gated, it waits for the batch already running (one
#: ``_HOLD``) and then does its own work; ungated it never gets the row while
#: the two agents keep posting.
_BUDGET = 12.0
_IPS = ["10.31.1.10", "10.31.1.11", "10.31.1.12"]


async def _pair_estate(db: AsyncSession) -> tuple[list[Any], Any, Any, dict[str, str]]:
    """Two Kea servers of one group (an HA pair) serving one DDNS scope, both
    holding its leases, and an admin."""
    from sqlalchemy import select  # noqa: PLC0415

    from app.models.dhcp import DHCPScope  # noqa: PLC0415
    from tests.test_dhcp_scope_lease_teardown import _make_admin  # noqa: PLC0415
    from tests.test_lease_events_insert_order_3480 import (  # noqa: PLC0415
        _ddns_subnet,
        _two_agents,
    )

    _, token = await _make_admin(db)
    subnet, _block = await _ddns_subnet(db)
    servers = await _two_agents(db, [subnet])
    scope_id = (
        await db.execute(select(DHCPScope.id).where(DHCPScope.subnet_id == subnet.id))
    ).scalar_one()
    return servers, scope_id, subnet, {"Authorization": f"Bearer {token}"}


async def _batch(client: AsyncClient, server: Any) -> Any:
    from tests.test_lease_events_insert_order_3480 import _lease  # noqa: PLC0415

    return await client.post(
        "/api/v1/dhcp/agents/lease-events",
        headers={"x-test-server": str(server.id)},
        json={"leases": [_lease(ip, n) for n, ip in enumerate(_IPS)]},
    )


async def _under_load(
    client: AsyncClient,
    servers: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    request: Any,
) -> tuple[Any, float, list[tuple[float, int]], float]:
    """Run ``request`` (a coroutine factory) while both agents post the
    scope's leases back to back, each batch holding the scope for ``_HOLD``
    after taking it, offset so a batch is always open: the reported shape.
    Returns its response, how long it took, every batch's (end time, status),
    and when it was answered. Fails if it is not answered within ``_BUDGET``."""
    from app.api.v1.dhcp import agents  # noqa: PLC0415

    for server in servers:  # both agents hold the leases, as an HA pair does
        assert (await _batch(client, server)).status_code == 200

    real = agents.lock_zones_for_addresses

    async def _slow(db: AsyncSession, **kwargs: Any) -> Any:
        await asyncio.sleep(_HOLD)
        return await real(db, **kwargs)

    monkeypatch.setattr(agents, "lock_zones_for_addresses", _slow)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    answered: list[tuple[float, int]] = []

    async def _agent(server: Any, offset: float) -> None:
        await asyncio.sleep(offset)
        while not stop.is_set():
            r = await _batch(client, server)
            answered.append((loop.time(), r.status_code))

    running = [asyncio.create_task(_agent(s, off)) for s, off in zip(servers, (0.0, _HOLD / 2))]
    task: asyncio.Task[Any] | None = None
    try:
        await asyncio.sleep(_HOLD * 1.5)  # both agents are in a batch
        start = loop.time()
        task = asyncio.create_task(request())
        done, _ = await asyncio.wait({task}, timeout=_BUDGET)
        took = loop.time() - start
        assert task in done, f"the request was still waiting after {_BUDGET} s"
        answered_at = loop.time()
        # The batches that queued behind it run, and are answered.
        await asyncio.sleep(_HOLD * 3)
    finally:
        stop.set()
        await asyncio.wait_for(asyncio.gather(*running, return_exceptions=True), 60)
        if task is not None and not task.done():
            await asyncio.wait_for(task, 60)
    return task.result(), took, answered, answered_at


@pytest.mark.asyncio
async def test_a_scope_delete_goes_through_while_both_agents_of_a_pair_post_its_leases(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real delete, against two agents' real batches: it must answer 204
    well inside its budget (ungated it waits until the agents stop), and the
    batches that queued behind it must then be answered 200 without writing
    anything into the trashed scope (#3747)."""
    from tests.test_lease_events_trashed_scope_3733 import _NOTHING, _counts  # noqa: PLC0415

    servers, scope_id, subnet, admin = await _pair_estate(db_session)
    resp, took, answered, answered_at = await _under_load(
        concurrent_client,
        servers,
        monkeypatch,
        lambda: concurrent_client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin),
    )
    assert resp.status_code == 204, resp.text
    assert took < _BUDGET
    assert answered and all(code == 200 for _t, code in answered), answered
    assert any(t > answered_at for t, _c in answered), "no batch ran after the delete"
    for server in servers:
        assert await _counts(db_session, server, subnet) == _NOTHING


@pytest.mark.asyncio
async def test_a_scope_edit_needs_no_gate_under_the_same_load(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scope edit's UPDATE changes no key column, so it takes the row ``FOR
    NO KEY UPDATE``, which a ``FOR KEY SHARE`` does not block: under the load
    that starved the delete it answers at once, and the batches carry on."""
    servers, scope_id, _subnet, admin = await _pair_estate(db_session)
    resp, took, answered, _at = await _under_load(
        concurrent_client,
        servers,
        monkeypatch,
        lambda: concurrent_client.put(
            f"/api/v1/dhcp/scopes/{scope_id}", headers=admin, json={"description": "edited"}
        ),
    )
    assert resp.status_code == 200, resp.text
    assert took < _HOLD, took
    assert answered and all(code == 200 for _t, code in answered), answered


# ── The subnet, block and space deletes' cascades (#3744 locks their scopes) ──


@pytest.mark.asyncio
async def test_a_subnet_delete_goes_through_while_both_agents_of_a_pair_post_its_leases(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subnet soft-delete takes its scopes ``FOR UPDATE`` (#3744), so it was
    starved by the pair's batches exactly as the scope delete was: it must
    answer 204 inside its budget, and the batches behind it 200, writing
    nothing into the trashed scope."""
    servers, _scope_id, subnet, admin = await _pair_estate(db_session)
    resp, took, answered, answered_at = await _under_load(
        concurrent_client,
        servers,
        monkeypatch,
        lambda: concurrent_client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=admin),
    )
    assert resp.status_code == 204, resp.text
    assert took < _BUDGET
    assert answered and all(code == 200 for _t, code in answered), answered
    assert any(t > answered_at for t, _c in answered), "no batch ran after the delete"
    from sqlalchemy import func, select  # noqa: PLC0415

    from app.models.dhcp import DHCPLease  # noqa: PLC0415

    for server in servers:
        left = (
            await db_session.execute(
                select(func.count()).select_from(DHCPLease).where(DHCPLease.server_id == server.id)
            )
        ).scalar_one()
        assert left == 0, (server.name, left)


def _gate_first(seen: list[tuple[str, Any]]) -> None:
    """The scope gate (exclusive, its namespace) comes before every row lock."""
    from app.services.lock_order import SCOPE_GATE_NS  # noqa: PLC0415

    def _is_gate(stmt: str, params: Any) -> bool:
        values = params.values() if isinstance(params, dict) else (params or ())
        return (
            "pg_advisory_xact_lock(" in stmt
            and "pg_advisory_xact_lock_shared" not in stmt
            and SCOPE_GATE_NS in tuple(values)
        )

    i_gate = next((i for i, (s, p) in enumerate(seen) if _is_gate(s, p)), None)
    assert i_gate is not None, "no exclusive scope gate taken"
    i_row = next(
        (i for i, (s, _p) in enumerate(seen) if " FOR " in s and "pg_advisory" not in s), None
    )
    assert i_row is not None and i_gate < i_row, (i_gate, i_row)


@contextlib.contextmanager
def _statements_with_params() -> Iterator[list[tuple[str, Any]]]:
    seen: list[tuple[str, Any]] = []

    def _record(conn: Any, cursor: Any, statement: str, params: Any, *a: Any) -> None:
        if "pg_advisory_xact_lock" in statement or " FOR " in statement:
            seen.append((statement, params))

    event.listen(Engine, "before_cursor_execute", _record)
    try:
        yield seen
    finally:
        event.remove(Engine, "before_cursor_execute", _record)


@pytest.mark.parametrize("kind", ["subnet", "subnet-permanent", "block", "space"])
@pytest.mark.asyncio
async def test_a_cascading_delete_takes_the_scope_gate_before_its_first_row_lock(
    concurrent_client: AsyncClient,  # noqa: F811
    db_session: AsyncSession,
    kind: str,
) -> None:
    """Every delete that takes or deletes a live scope's row takes that scope's
    gate exclusive as its first lock (step 0), or it waits behind a pair's
    batches as the scope delete did."""
    _server, _scope_id, subnet, admin = await _estate(db_session)
    url = {
        "subnet": f"/api/v1/ipam/subnets/{subnet.id}",
        "subnet-permanent": f"/api/v1/ipam/subnets/{subnet.id}?permanent=true&force=true",
        "block": f"/api/v1/ipam/blocks/{subnet.block_id}",
        "space": f"/api/v1/ipam/spaces/{subnet.space_id}",
    }[kind]
    with _statements_with_params() as seen:
        r = await concurrent_client.delete(url, headers=admin)
    assert r.status_code == 204, r.text
    _gate_first(seen)
