"""#2580 — a reservation DELETE racing the lease report, and the re-mirror backstop.

#1274 made a reservation's DELETE hand its IPAM row to the client's live lease
instead of freeing it, deciding from the lease table. The lease-event ingest
decides the other half from the row: it takes over an ``available`` row and
leaves a ``static_dhcp`` one alone. On plain reads the two could miss each
other — the ingest read the row before the DELETE committed (``static_dhcp``),
the DELETE read the lease table before the ingest committed (no lease) — and
both committed, leaving the address ``available`` beside a live lease.

The race tests drive the real handlers (``agent_lease_events`` and
``delete_static``) on two real sessions over two connections, with the
interleaving forced: one side is held inside its own ``commit`` (every
decision made, every lock held), the other is started, and the test waits until
Postgres reports it blocked on a row lock before letting the first commit. Run
in both orders; the end state must be the lease's ``dhcp`` mirror either way.
Every await is bounded, both backends carry a ``lock_timeout``, and ``finally``
closes and terminates them so a failure never leaves a lock behind.

The backstop tests cover ``remirror_available_rows_with_live_leases`` and the
lease-cleanup task step that runs it, which also heals the route no lock can
close: a lease batch the agent dropped after a refused POST.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import LeaseEvent, LeaseEventBatch, agent_lease_events
from app.api.v1.dhcp.statics import delete_static
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import (
    DHCPLease,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import upsert_ipam_for_static
from tests.conftest import _TestSessionLocal

IP = "10.25.80.20"
MAC = "aa:bb:cc:25:80:20"
_STEP = 20.0  # bound on any single await


# ── fixtures ────────────────────────────────────────────────────────────────


async def _group(db: AsyncSession) -> tuple[DHCPServerGroup, DHCPServer]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        status="active",
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.flush()
    return grp, srv


async def _scope(db: AsyncSession, grp: DHCPServerGroup) -> tuple[Subnet, DHCPScope]:
    """A fresh IP space, so two calls give two networks with the same CIDR."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.25.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.25.80.0/24", name="s")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    return subnet, scope


async def _user(db: AsyncSession) -> User:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user


def _lease(
    srv: DHCPServer,
    scope: DHCPScope | None,
    *,
    state: str = "active",
    expires_in: timedelta = timedelta(hours=8),
    seen_ago: timedelta = timedelta(seconds=5),
    hostname: str | None = "phone-7",
) -> DHCPLease:
    now = datetime.now(UTC)
    return DHCPLease(
        server_id=srv.id,
        scope_id=scope.id if scope is not None else None,
        ip_address=IP,
        mac_address=MAC,
        hostname=hostname,
        state=state,
        starts_at=now - seen_ago,
        ends_at=now + expires_in,
        expires_at=now + expires_in,
        last_seen_at=now - seen_ago,
    )


async def _row(db: AsyncSession, subnet_id: uuid.UUID) -> IPAddress:
    return (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.subnet_id == subnet_id, IPAddress.address == IP)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


def _batch() -> LeaseEventBatch:
    now = datetime.now(UTC)
    end = now + timedelta(hours=8)
    return LeaseEventBatch(
        leases=[
            LeaseEvent(
                ip_address=IP,
                mac_address=MAC,
                hostname="phone-7",
                state="active",
                starts_at=now,
                ends_at=end,
                expires_at=end,
            )
        ],
        batch_id=uuid.uuid4().hex,
    )


# ── two-session plumbing ────────────────────────────────────────────────────


async def _prepare(session: AsyncSession) -> int:
    """Bound the backend's lock waits and return its pid."""
    await asyncio.wait_for(session.execute(text("SET lock_timeout = '30s'")), _STEP)
    result = await asyncio.wait_for(session.execute(text("SELECT pg_backend_pid()")), _STEP)
    return int(result.scalar_one())


def _hold_commit(session: AsyncSession) -> tuple[asyncio.Event, asyncio.Event]:
    """Make ``session.commit`` stop until released, every decision already made.

    Returns ``(reached, release)``: ``reached`` is set when the handler calls
    commit, which then waits for ``release`` before really committing.
    """
    reached, release = asyncio.Event(), asyncio.Event()
    real_commit = session.commit

    async def held_commit() -> None:
        reached.set()
        await release.wait()
        await real_commit()

    session.commit = held_commit  # type: ignore[method-assign]
    return reached, release


async def _wait_reached(reached: asyncio.Event, task: asyncio.Task[Any]) -> None:
    """Wait until the held side reaches its commit; fail fast if it died first."""
    waiter = asyncio.create_task(reached.wait())
    try:
        await asyncio.wait({waiter, task}, timeout=_STEP, return_when=asyncio.FIRST_COMPLETED)
    finally:
        waiter.cancel()
    if task.done():
        task.result()  # surface its exception
        raise AssertionError("the held side finished without reaching its commit")
    assert reached.is_set(), "the held side never reached its commit"


async def _blocked_or_done(pid: int, task: asyncio.Task[Any]) -> str | None:
    """Wait until backend ``pid`` waits on a lock (return its statement) or
    ``task`` finishes without ever blocking (return None).

    The fixed code blocks; the unfixed code ran straight through. Returning
    rather than asserting here lets the test end on the state the issue is
    about, so the unfixed code fails on ``available`` instead of on plumbing.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _STEP
    async with _TestSessionLocal() as probe:
        while loop.time() < deadline:
            if task.done():
                task.result()  # surface its exception
                return None
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
    raise AssertionError(f"backend {pid} neither blocked on a lock nor finished")


async def _cleanup(tasks: list[asyncio.Task[Any]], sessions: list[AsyncSession]) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(task, 5)
    pids: list[int] = []
    for s in sessions:
        with contextlib.suppress(BaseException):
            pids.append(
                int(
                    (await asyncio.wait_for(s.execute(text("SELECT pg_backend_pid()")), 2)).scalar()
                )
            )
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


async def _seed_reservation(db: AsyncSession) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    """Committed: a reservation at ``IP`` with its ``static_dhcp`` row, no lease yet."""
    grp, srv = await _group(db)
    subnet, scope = await _scope(db, grp)
    st = DHCPStaticAssignment(scope_id=scope.id, ip_address=IP, mac_address=MAC, hostname="phone-7")
    db.add(st)
    await db.flush()
    await upsert_ipam_for_static(db, scope, st)
    user = await _user(db)
    ids = (srv.id, subnet.id, st.id, user.id)
    await db.commit()
    assert (await _row(db, subnet.id)).status == "static_dhcp"
    return ids


async def _assert_lease_mirror(db: AsyncSession, subnet_id: uuid.UUID) -> None:
    row = await _row(db, subnet_id)
    lease = (await db.execute(select(DHCPLease).where(DHCPLease.ip_address == IP))).scalar_one()
    assert row.status == "dhcp", "the address reads free beside a live lease"
    assert row.auto_from_lease is True
    assert row.dhcp_lease_id == str(lease.id)
    assert str(row.mac_address) == MAC
    assert row.static_assignment_id is None
    assert (
        await db.execute(select(DHCPStaticAssignment).where(DHCPStaticAssignment.ip_address == IP))
    ).scalar_one_or_none() is None


def _ingest(session: AsyncSession, server_id: uuid.UUID) -> Callable[[], Awaitable[dict[str, Any]]]:
    async def run() -> dict[str, Any]:
        server = await session.get(DHCPServer, server_id)
        assert server is not None
        return await agent_lease_events(_batch(), session, auth=(server, {}))

    return run


def _delete(
    session: AsyncSession, static_id: uuid.UUID, user_id: uuid.UUID
) -> Callable[[], Awaitable[None]]:
    async def run() -> None:
        user = await session.get(User, user_id)
        assert user is not None
        await delete_static(static_id, session, user)

    return run


# ── the race, both orders ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ingest_decides_first_then_the_delete_waits_and_hands_over(
    db_session: AsyncSession,
) -> None:
    """The ingest has inserted its lease and read the row (``static_dhcp``)
    and holds its transaction open. The DELETE must wait for it, then find the
    lease and hand the row over instead of freeing it."""
    server_id, subnet_id, static_id, user_id = await _seed_reservation(db_session)
    ingest_s, delete_s = _TestSessionLocal(), _TestSessionLocal()
    tasks: list[asyncio.Task[Any]] = []
    try:
        await _prepare(ingest_s)
        delete_pid = await _prepare(delete_s)
        reached, release = _hold_commit(ingest_s)

        ingest = asyncio.create_task(_ingest(ingest_s, server_id)())
        tasks.append(ingest)
        await _wait_reached(reached, ingest)

        delete = asyncio.create_task(_delete(delete_s, static_id, user_id)())
        tasks.append(delete)
        blocked_in = await _blocked_or_done(delete_pid, delete)

        release.set()
        await asyncio.wait_for(ingest, _STEP)
        await asyncio.wait_for(delete, _STEP)
    finally:
        await _cleanup(tasks, [ingest_s, delete_s])

    await _assert_lease_mirror(db_session, subnet_id)
    assert blocked_in is not None and "ip_address" in blocked_in, blocked_in


@pytest.mark.asyncio
async def test_delete_decides_first_then_the_ingest_waits_and_takes_the_row(
    db_session: AsyncSession,
) -> None:
    """The DELETE found no lease and set ``available``, and holds its
    transaction open. The ingest must wait for it, then see ``available`` and
    take the row instead of leaving it alone as ``static_dhcp``."""
    server_id, subnet_id, static_id, user_id = await _seed_reservation(db_session)
    ingest_s, delete_s = _TestSessionLocal(), _TestSessionLocal()
    tasks: list[asyncio.Task[Any]] = []
    try:
        ingest_pid = await _prepare(ingest_s)
        await _prepare(delete_s)
        reached, release = _hold_commit(delete_s)

        delete = asyncio.create_task(_delete(delete_s, static_id, user_id)())
        tasks.append(delete)
        await _wait_reached(reached, delete)

        ingest = asyncio.create_task(_ingest(ingest_s, server_id)())
        tasks.append(ingest)
        blocked_in = await _blocked_or_done(ingest_pid, ingest)

        release.set()
        await asyncio.wait_for(delete, _STEP)
        await asyncio.wait_for(ingest, _STEP)
    finally:
        await _cleanup(tasks, [ingest_s, delete_s])

    await _assert_lease_mirror(db_session, subnet_id)
    assert blocked_in is not None and "ip_address" in blocked_in, blocked_in


# ── the backstop ────────────────────────────────────────────────────────────


async def remirror_available_rows_with_live_leases(db: AsyncSession) -> list[Any]:
    # Imported here, not at module top, so the race tests above still run
    # against a tree without the backstop (the negative control).
    from app.services.dhcp.static_ipam import (  # noqa: PLC0415
        remirror_available_rows_with_live_leases as remirror,
    )

    return await remirror(db)


async def _available_with_lease(
    db: AsyncSession, *, lease_in_other_space: bool = False, **lease_kw: Any
) -> tuple[IPAddress, DHCPLease]:
    grp, srv = await _group(db)
    subnet, scope = await _scope(db, grp)
    row = IPAddress(subnet_id=subnet.id, address=IP, status="available", hostname="old-name")
    db.add(row)
    lease_scope = scope
    if lease_in_other_space:
        _other_subnet, lease_scope = await _scope(db, grp)
    lease = _lease(srv, lease_scope, **lease_kw)
    db.add(lease)
    await db.flush()
    return row, lease


@pytest.mark.asyncio
async def test_backstop_hands_an_available_row_to_the_live_lease_once(
    db_session: AsyncSession,
) -> None:
    """The dropped-batch route: the row is ``available``, the lease landed
    later (or was re-sent). One pass mirrors it; the next finds nothing."""
    row, lease = await _available_with_lease(db_session)

    handovers = await remirror_available_rows_with_live_leases(db_session)
    await db_session.flush()

    assert [h.row.id for h in handovers] == [row.id]
    assert row.status == "dhcp"
    assert row.auto_from_lease is True
    assert row.dhcp_lease_id == str(lease.id)
    assert str(row.mac_address) == MAC
    assert row.hostname == "phone-7"
    assert row.last_seen_method == "dhcp"

    assert await remirror_available_rows_with_live_leases(db_session) == []
    assert row.status == "dhcp"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "lease_kw",
    [
        {"state": "expired", "expires_in": timedelta(hours=-1)},
        {"state": "released"},
        {"state": "active", "expires_in": timedelta(minutes=-5)},
        {"lease_in_other_space": True},
    ],
    ids=["expired", "released", "active-past-expiry", "other-ip-space"],
)
async def test_backstop_leaves_a_row_no_live_lease_in_its_subnet_holds(
    db_session: AsyncSession, lease_kw: dict[str, Any]
) -> None:
    row, _lease_row = await _available_with_lease(db_session, **lease_kw)

    assert await remirror_available_rows_with_live_leases(db_session) == []
    assert row.status == "available"
    assert row.auto_from_lease is False


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["static_dhcp", "allocated", "reserved", "dhcp"])
async def test_backstop_only_takes_available_rows(db_session: AsyncSession, status: str) -> None:
    row, _lease_row = await _available_with_lease(db_session)
    row.status = status
    await db_session.flush()

    assert await remirror_available_rows_with_live_leases(db_session) == []
    assert row.status == status


@pytest.mark.asyncio
async def test_backstop_leaves_a_row_the_operator_freed_after_the_lease_was_seen(
    db_session: AsyncSession,
) -> None:
    """An operator setting the row ``available`` after the lease's last report
    is their later word; the backstop does not overrule it."""
    row, lease = await _available_with_lease(db_session)
    row.user_modified_at = lease.last_seen_at + timedelta(seconds=1)
    await db_session.flush()

    assert await remirror_available_rows_with_live_leases(db_session) == []
    assert row.status == "available"


@pytest.mark.asyncio
async def test_backstop_keeps_the_operator_hostname_on_a_row_edited_before_the_lease(
    db_session: AsyncSession,
) -> None:
    row, lease = await _available_with_lease(db_session)
    row.user_modified_at = lease.last_seen_at - timedelta(hours=1)
    await db_session.flush()

    handovers = await remirror_available_rows_with_live_leases(db_session)

    assert [h.row.id for h in handovers] == [row.id]
    assert row.status == "dhcp"
    assert row.dhcp_lease_id == str(lease.id)
    assert row.hostname == "old-name"


@pytest.mark.asyncio
async def test_lease_cleanup_task_runs_the_backstop_and_audits_it(
    db_session: AsyncSession,
) -> None:
    import app.tasks.dhcp_lease_cleanup as cleanup

    row, lease = await _available_with_lease(db_session)
    row_id, lease_id = row.id, lease.id
    await db_session.commit()

    assert await cleanup._remirror_live_leases() == 1
    assert await cleanup._remirror_live_leases() == 0

    fresh = (
        await db_session.execute(
            select(IPAddress)
            .where(IPAddress.id == row_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert (fresh.status, fresh.dhcp_lease_id) == ("dhcp", str(lease_id))
    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "dhcp-lease-remirror")))
        .scalars()
        .all()
    )
    assert len(audits) == 1
    assert audits[0].new_value["rows_remirrored"] == 1
    assert audits[0].new_value["addresses"] == [IP]
