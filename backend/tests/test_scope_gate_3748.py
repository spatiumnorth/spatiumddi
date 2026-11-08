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
from sqlalchemy.exc import DBAPIError
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


async def _holder(scope_id: Any, offset: float, stop: asyncio.Event, gated: bool) -> None:
    """A batch stand-in: gate (shared) then the scope ``FOR KEY SHARE``, held
    0.4 s, in a loop. Two of them, offset by half a hold, keep a share lock
    on the row at every instant."""
    from app.services.lock_order import lock_scope_gates  # noqa: PLC0415

    await asyncio.sleep(offset)
    while not stop.is_set():
        async with _TestSessionLocal() as db:
            if gated:
                await lock_scope_gates(db, [scope_id], exclusive=False)
            await db.execute(text(_KEY_SHARE), {"s": scope_id})
            await asyncio.sleep(0.4)
            await db.commit()


async def _delete_like(scope_id: Any, gated: bool) -> None:
    from app.services.lock_order import lock_scope_gates  # noqa: PLC0415

    async with _TestSessionLocal() as db:
        await db.execute(text("SET LOCAL statement_timeout = '4s'"))
        if gated:
            await lock_scope_gates(db, [scope_id], exclusive=True)
        await db.execute(
            text("SELECT id FROM dhcp_scope WHERE id = :s FOR UPDATE"), {"s": scope_id}
        )
        await db.commit()


@pytest.mark.parametrize("gated", [False, True])
@pytest.mark.asyncio
async def test_overlapping_key_shares_starve_a_for_update_unless_gated(
    db_session: AsyncSession, gated: bool
) -> None:
    """Ungated, the FOR UPDATE times out behind two alternating KEY SHAREs (the
    reported 503); gated, it gets the row as soon as the running batches end."""
    _server, scope_id, _subnet, _admin = await _estate(db_session)
    app.dependency_overrides.pop(_auth_agent, None)
    stop = asyncio.Event()
    holders = [asyncio.create_task(_holder(scope_id, off, stop, gated)) for off in (0.0, 0.2)]
    try:
        await asyncio.sleep(0.5)
        if gated:
            await asyncio.wait_for(_delete_like(scope_id, True), 3.5)
        else:
            with pytest.raises(DBAPIError):
                await _delete_like(scope_id, False)
    finally:
        stop.set()
        for h in holders:
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(h, 5)


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
