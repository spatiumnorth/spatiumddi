"""A server move and the worker's bundle render must not deadlock (#1703).

The render stores a bundle with two statements on the server's row:
``INSERT INTO dns_agent_bundle`` (its foreign key takes ``FOR KEY SHARE`` on
``dns_server``), then ``UPDATE dns_server SET bundle_render_count = …``
(``FOR NO KEY UPDATE``). The move used to write the row in two flushes: a
non-key column first (the primary demotion, a plain field on the same PUT,
the Fleet engine switch's driver — ``FOR NO KEY UPDATE``), then ``group_id``,
a column of ``uq_dns_server_group_name`` and so ``FOR UPDATE``, which waits
for the render's key share while the render waits for the first flush: 40P01,
the move rolled back whole, a bare 500.

Two real sessions on two connections, interleaved deterministically: each
step waits until Postgres reports the other backend actually blocked on a
lock (``pg_stat_activity``), never on a sleep. The render side issues the
render's own statements, so the foreign-key lock is the real one.

Every await is bounded, both backends run with a ``lock_timeout``, and
``finally`` closes and terminates them, so a failure can never leave a lock
behind that blocks the suite's TRUNCATE.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.appliance import Appliance
from app.models.auth import User
from app.models.dns import DNSAgentBundle, DNSServer, DNSServerGroup
from app.services.appliance.dns_group_move import move_appliance_dns_servers
from app.services.dns.server_move import move_server_to_group
from tests.conftest import _TestSessionLocal
from tests.test_dns_server_group_move import (
    _auth,
    _fleet_appliance,
    _group,
    _server,
    _superadmin,
    _url,
)

_STEP = 20.0  # bound on any single await; Postgres detects a deadlock in ~1 s


async def _prepare(session: AsyncSession) -> int:
    """Bound the backend's lock waits and return its pid."""
    await asyncio.wait_for(session.execute(text("SET lock_timeout = '30s'")), _STEP)
    result = await asyncio.wait_for(session.execute(text("SELECT pg_backend_pid()")), _STEP)
    return int(result.scalar_one())


async def _wait_blocked(pid: int, task: asyncio.Task[Any]) -> str:
    """Wait until backend ``pid`` waits on a lock; return the statement it waits in."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _STEP
    async with _TestSessionLocal() as probe:
        while loop.time() < deadline:
            if task.done():
                task.result()  # surface its exception
                raise AssertionError("expected it to block on a row lock; it finished")
            row = (
                await asyncio.wait_for(
                    probe.execute(
                        text("SELECT wait_event_type, query FROM pg_stat_activity WHERE pid = :p"),
                        {"p": pid},
                    ),
                    _STEP,
                )
            ).one_or_none()
            await probe.rollback()  # a fresh pg_stat_activity snapshot each poll
            if row is not None and row.wait_event_type == "Lock":
                return str(row.query)
            await asyncio.sleep(0.05)
    raise AssertionError(f"backend {pid} never blocked on a lock")


async def _render_insert(render: AsyncSession, server_id: uuid.UUID) -> None:
    """The render's bundle INSERT: its FK takes FOR KEY SHARE on the server."""
    await asyncio.wait_for(
        render.execute(
            pg_insert(DNSAgentBundle).values(
                id=uuid.uuid4(),
                server_id=server_id,
                dirty_watermark=1,
                snapshot_at=datetime.now(UTC),
                etag="e1703",
                structural_etag="s1703",
                ships_ops=True,
                body=b"",
                body_bytes=0,
                body_gzip_bytes=0,
                records=0,
                render_ms=1,
                rendered_by="worker",
            )
        ),
        _STEP,
    )


async def _render_finish(render: AsyncSession, server_id: uuid.UUID) -> None:
    """The render's mirror UPDATE (FOR NO KEY UPDATE), then its commit."""
    await asyncio.wait_for(
        render.execute(
            update(DNSServer)
            .where(DNSServer.id == server_id)
            .values(
                bundle_render_count=DNSServer.bundle_render_count + 1,
                bundle_render_at=func.now(),
            )
        ),
        _STEP,
    )
    await asyncio.wait_for(render.commit(), _STEP)


async def _cleanup(
    task: asyncio.Task[Any] | None, sessions: list[AsyncSession], pids: list[int]
) -> None:
    if task is not None and not task.done():
        task.cancel()
        with contextlib.suppress(BaseException):
            await asyncio.wait_for(task, 5)
    for s in sessions:
        with contextlib.suppress(BaseException):
            await asyncio.wait_for(s.close(), 5)
    if pids:
        async with _TestSessionLocal() as killer:
            await asyncio.wait_for(
                killer.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE pid = ANY(:p) AND pid <> pg_backend_pid()"
                    ),
                    {"p": pids},
                ),
                _STEP,
            )


async def _render_holds_key_share_then_move(
    server_id: uuid.UUID,
    mover: AsyncSession,
    move: Callable[[], Awaitable[None]],
    *,
    owns_mover: bool,
) -> str:
    """The reported interleave: the render has inserted its bundle when the
    move arrives. Returns the statement the move blocked in."""
    render = _TestSessionLocal()
    sessions = [render] + ([mover] if owns_mover else [])
    pids: list[int] = []
    task: asyncio.Task[None] | None = None
    try:
        pids.append(await _prepare(render))
        mover_pid = await _prepare(mover)
        if owns_mover:  # never terminate the fixture's own session
            pids.append(mover_pid)
        await _render_insert(render, server_id)

        task = asyncio.create_task(move())
        blocked_in = await _wait_blocked(mover_pid, task)

        # The move is queued for the row. The render's own UPDATE must still
        # go through (the only conflicting lock is its own), then the move.
        await _render_finish(render, server_id)
        await asyncio.wait_for(task, _STEP)  # DeadlockDetectedError on main
        return blocked_in
    finally:
        await _cleanup(task, sessions, pids)


async def _assert_moved(server_id: uuid.UUID, group_id: uuid.UUID) -> DNSServer:
    async with _TestSessionLocal() as check:
        row = (
            await asyncio.wait_for(
                check.execute(select(DNSServer).where(DNSServer.id == server_id)), _STEP
            )
        ).scalar_one()
        assert row.group_id == group_id
        # The render's write was neither lost nor rolled back.
        assert row.bundle_render_count == 1
        bundles = (
            await check.execute(
                select(func.count())
                .select_from(DNSAgentBundle)
                .where(DNSAgentBundle.server_id == server_id)
            )
        ).scalar_one()
        assert bundles == 1
        return row


@pytest.mark.asyncio
async def test_server_put_move_waits_for_an_in_flight_render(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reported request: the PUT moves a primary (so it demotes first)
    and carries a plain column too, while a render holds the FK lock."""
    token = await _superadmin(db_session, "root1703")
    src = await _group(db_session, "src1703")
    dst = await _group(db_session, "dst1703")
    srv = await _server(db_session, src, "ns1", is_primary=True)
    await db_session.commit()
    server_id, src_id, dst_id = srv.id, src.id, dst.id

    async def do_move() -> None:
        resp = await client.put(
            _url(src_id, server_id),
            json={"group_id": str(dst_id), "notes": "moved"},
            headers=_auth(token),
        )
        assert resp.status_code == 200, resp.text

    # The PUT runs on ``db_session`` (the client fixture's override).
    blocked_in = await _render_holds_key_share_then_move(
        server_id, db_session, do_move, owns_mover=False
    )
    # It waits for the row lock up front, not halfway through its writes.
    assert "FOR UPDATE" in blocked_in, blocked_in
    row = await _assert_moved(server_id, dst_id)
    assert row.is_primary is True  # elected in the empty target
    assert row.notes == "moved"


@pytest.mark.asyncio
async def test_service_move_waits_for_an_in_flight_render(db_session: AsyncSession) -> None:
    src = await _group(db_session, "src1703s")
    dst = await _group(db_session, "dst1703s")
    srv = await _server(db_session, src, "ns1", is_primary=True)
    await db_session.commit()
    server_id, dst_id = srv.id, dst.id

    mover = _TestSessionLocal()

    async def do_move() -> None:
        server = await mover.get(DNSServer, server_id)
        target = await mover.get(DNSServerGroup, dst_id)
        assert server is not None and target is not None
        assert await move_server_to_group(mover, server, target) is not None
        await mover.commit()

    await _render_holds_key_share_then_move(server_id, mover, do_move, owns_mover=True)
    await _assert_moved(server_id, dst_id)


@pytest.mark.asyncio
async def test_fleet_engine_and_group_save_waits_for_an_in_flight_render(
    db_session: AsyncSession,
) -> None:
    """The Fleet roles PUT on an engine switch (#1856): the adopted row's
    driver is written first, then its group — the same two-step write."""
    src = await _group(db_session, "src1703f")
    dst = await _group(db_session, "dst1703f")
    appliance = await _fleet_appliance(db_session, src)  # roles: dns-bind9
    srv = await _server(
        db_session,
        src,
        appliance.hostname,
        is_primary=True,
        driver="technitium",
        host=appliance.hostname,
        appliance_id=appliance.id,
        agent_id=uuid.uuid4(),
    )
    user = User(
        username="root1703f",
        email="root1703f@example.com",
        display_name="root1703f",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.commit()
    server_id, dst_id, appliance_id, user_id = srv.id, dst.id, appliance.id, user.id

    mover = _TestSessionLocal()

    async def do_move() -> None:
        row = await mover.get(Appliance, appliance_id)
        target = await mover.get(DNSServerGroup, dst_id)
        actor = await mover.get(User, user_id)
        assert row is not None and target is not None and actor is not None
        outcome = await move_appliance_dns_servers(mover, row, target, actor)
        assert [m["dns_server"] for m in outcome.moved] == [str(server_id)]
        await mover.commit()

    blocked_in = await _render_holds_key_share_then_move(server_id, mover, do_move, owns_mover=True)
    assert "FOR UPDATE" in blocked_in, blocked_in
    row = await _assert_moved(server_id, dst_id)
    assert row.driver == "bind9"


@pytest.mark.asyncio
async def test_render_arriving_after_the_move_waits_for_it(db_session: AsyncSession) -> None:
    """The other order: the move holds the row when the render inserts its
    bundle. The render waits for the move's commit and then finishes."""
    src = await _group(db_session, "src1703r")
    dst = await _group(db_session, "dst1703r")
    srv = await _server(db_session, src, "ns1", is_primary=True)
    await db_session.commit()
    server_id, dst_id = srv.id, dst.id

    render = _TestSessionLocal()
    mover = _TestSessionLocal()
    pids: list[int] = []
    task: asyncio.Task[None] | None = None
    try:
        pids.append(await _prepare(render))
        pids.append(await _prepare(mover))
        server = await mover.get(DNSServer, server_id)
        target = await mover.get(DNSServerGroup, dst_id)
        assert server is not None and target is not None
        assert await asyncio.wait_for(move_server_to_group(mover, server, target), _STEP)
        await asyncio.wait_for(mover.flush(), _STEP)

        async def do_render() -> None:
            await _render_insert(render, server_id)
            await _render_finish(render, server_id)

        task = asyncio.create_task(do_render())
        await _wait_blocked(pids[0], task)
        await asyncio.wait_for(mover.commit(), _STEP)
        await asyncio.wait_for(task, _STEP)
    finally:
        await _cleanup(task, [render, mover], pids)

    await _assert_moved(server_id, dst_id)
