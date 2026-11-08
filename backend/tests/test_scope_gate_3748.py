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
    gate = [s for s in seen if "pg_advisory_xact_lock_shared" in s]
    assert gate, seen
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
