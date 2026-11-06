"""A record write in flight when its zone is deleted answers 404, never 500 (#3535).

A permanent zone delete (``_apply_delete_zone``) deleted the zone's records,
then the zone row, and held both until it committed. A record create, update or
delete that had read the zone just before went on, and its serial bump waited
on the zone row; once the delete committed the bump matched no row and
SQLAlchemy raised ``StaleDataError``: a bare 500. An update or delete caught
between the delete's two steps held the zone row from its bump and waited on
its record, which the delete held: a deadlock, and a 500 on one side. A request
sent after the delete has committed answers ``404 Zone not found``; one caught
waiting on it must answer the same.

Every record writer now takes the zone row first, as it reads it, and every
zone delete, soft or permanent, takes it before the zone's records: whichever
comes second waits for the first, and nothing waits for the zone row while it
holds a record.

A zone delete also sweeps the zone's queued record ops, and it sweeps once it
holds the zone row: a record write that held the row first queued its op before
it let go, and a sweep run before the wait could not see that op.

Each test runs the real zone delete and the real request, each on its own
session, and orders them with a third session holding a lock one of them
needs: the audit-chain lock, which both take last, one of the zone's records,
or a key-share lock on the zone row. Every wait is bounded.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncGenerator
from typing import Any, NamedTuple

import pytest
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.main import app
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSZone
from app.services.audit_chain import _AUDIT_CHAIN_LOCK_KEY
from app.services.dns.record_ops import QUEUED_OP_STATES
from tests.conftest import _TestSessionLocal
from tests.test_dns_dynamic_update_acl import _bind9_group_zone_key, _superadmin
from tests.test_dns_server_move_render_deadlock_1703 import _STEP, _cleanup, _prepare

# How long a request may take to reach the lock it queues on: far longer than
# it needs.
_QUEUE_S = 10.0

_PERMANENT = {"permanent": "true"}
# Writers of new records, and writers of a record that exists.
_CREATES = ["create", "bulk-create"]
_EDITS = ["update", "delete", "delete-permanent", "bulk-delete", "bulk-delete-permanent"]


def _request(case: str, record_id: str) -> tuple[str, str, dict[str, Any] | None, dict[str, str]]:
    """What ``case`` sends: method, path under the zone, JSON body, query."""
    bulk = {"record_ids": [record_id]}
    return {
        "create": (
            "POST",
            "records",
            {"name": "new", "record_type": "A", "value": "192.0.2.20"},
            {},
        ),
        "bulk-create": (
            "POST",
            "records/bulk-create",
            {
                "records": [
                    {"name": "a", "record_type": "A", "value": "192.0.2.21"},
                    {"name": "b", "record_type": "A", "value": "192.0.2.22"},
                ]
            },
            {},
        ),
        "update": ("PUT", f"records/{record_id}", {"ttl": 600}, {}),
        "delete": ("DELETE", f"records/{record_id}", None, {}),
        "delete-permanent": ("DELETE", f"records/{record_id}", None, _PERMANENT),
        "bulk-delete": ("POST", "records/bulk-delete", bulk, {}),
        "bulk-delete-permanent": ("POST", "records/bulk-delete", bulk, _PERMANENT),
    }[case]


@pytest.fixture
async def concurrent_client() -> AsyncGenerator[AsyncClient, None]:
    """A client whose every request runs on its own session, and which answers
    an unhandled error with the 500 a client sees instead of raising it."""

    async def own_session() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = own_session
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
    finally:
        app.dependency_overrides.pop(get_db, None)


class _Zone:
    """A superadmin, a BIND9 group with a server and one zone, and two A records
    in it: ``hold``, inserted first, and ``www``, the one the request edits."""

    headers: dict[str, str]
    group_id: uuid.UUID
    zone_id: uuid.UUID
    name: str
    hold_id: uuid.UUID
    www_id: uuid.UUID

    @property
    def url(self) -> str:
        return f"/api/v1/dns/groups/{self.group_id}/zones/{self.zone_id}"


async def _seed(db: AsyncSession) -> _Zone:
    z = _Zone()
    _, z.headers = await _superadmin(db)
    group, zone, _ = await _bind9_group_zone_key(db)
    z.group_id, z.zone_id, z.name = group.id, zone.id, zone.name
    for name, value in (("hold", "192.0.2.9"), ("www", "192.0.2.10")):
        record = DNSRecord(
            zone_id=zone.id, name=name, fqdn=f"{name}.{zone.name}", record_type="A", value=value
        )
        db.add(record)
        await db.flush()  # hold's row first, so a scan of the zone meets it first
        setattr(z, f"{name}_id", record.id)
    await db.commit()
    return z


def _send(client: AsyncClient, z: _Zone, case: str) -> asyncio.Task[Response]:
    method, suffix, body, params = _request(case, str(z.www_id))
    return asyncio.create_task(
        client.request(method, f"{z.url}/{suffix}", headers=z.headers, json=body, params=params)
    )


def _delete_zone(client: AsyncClient, z: _Zone, *, permanent: bool) -> asyncio.Task[Response]:
    params = _PERMANENT if permanent else {}
    return asyncio.create_task(client.delete(z.url, headers=z.headers, params=params))


class _Wait(NamedTuple):
    pid: int
    query: str
    # The table whose row it waits for: a backend waiting on a row lock holds
    # (or queues for) that row's tuple lock.
    row_of: str | None


async def _blocked_by(
    probe: AsyncSession, holder: int, task: asyncio.Task[Response]
) -> _Wait | None:
    """A backend waiting on a lock backend ``holder`` holds, once one does.
    None if ``task`` finished first, or nothing waited within ``_QUEUE_S``."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _QUEUE_S
    while not task.done() and loop.time() < deadline:
        row = (
            await asyncio.wait_for(
                probe.execute(
                    text(
                        "SELECT a.pid, a.query, (SELECT l.relation::regclass::text"
                        " FROM pg_locks l WHERE l.pid = a.pid AND l.locktype = 'tuple'"
                        " LIMIT 1) AS row_of FROM pg_stat_activity a"
                        " WHERE a.wait_event_type = 'Lock' AND :h = ANY(pg_blocking_pids(a.pid))"
                    ),
                    {"h": holder},
                ),
                _STEP,
            )
        ).first()
        await probe.rollback()  # a fresh pg_stat_activity snapshot each poll
        if row is not None:
            return _Wait(int(row.pid), str(row.query), row.row_of)
        await asyncio.sleep(0.05)
    return None


def _said(resp: Response) -> str:
    return f"{resp.status_code} {resp.text[:300]}"


async def _answer(task: asyncio.Task[Response]) -> str:
    """What a request that did not wait answered, for an assertion message."""
    if not task.done():
        return "still running"
    return _said(task.result())


class _Gate:
    """A session holding a lock until ``open``; ``close`` cleans up after the
    test whatever happened."""

    def __init__(self) -> None:
        self.session = _TestSessionLocal()
        self.probe = _TestSessionLocal()
        self.pid = 0
        self.tasks: list[asyncio.Task[Response]] = []

    async def hold(self, sql: str, **params: Any) -> None:
        self.pid = await _prepare(self.session)
        await asyncio.wait_for(self.session.execute(text(sql), params), _STEP)

    async def open(self) -> None:
        await asyncio.wait_for(self.session.rollback(), _STEP)

    async def close(self) -> None:
        for task in self.tasks:
            if not task.done():
                task.cancel()
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(task, 5)
        await _cleanup(None, [self.session, self.probe], [self.pid] if self.pid else [])


async def _zone_state(zone_id: uuid.UUID) -> tuple[DNSZone | None, int, int]:
    """The zone row (None once deleted), its records, and those still live."""
    async with _TestSessionLocal() as check:
        zone = await check.get(DNSZone, zone_id)
        count = select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone_id)
        every = (await check.execute(count.execution_options(include_deleted=True))).scalar_one()
        live = (
            await check.execute(
                select(func.count())
                .select_from(DNSRecord)
                .where(DNSRecord.zone_id == zone_id, DNSRecord.deleted_at.is_(None))
            )
        ).scalar_one()
    return zone, every, live


def _is_zone_row_lock(wait: _Wait) -> bool:
    """A wait in a locking read of the zone row, before any record is touched.
    (``pg_stat_activity`` cuts a long statement short, so the row comes from
    the tuple lock the waiter holds, not from the statement's text.)"""
    return wait.row_of == "dns_zone" and wait.query.lstrip().upper().startswith("SELECT")


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CREATES + _EDITS)
async def test_a_record_write_waiting_on_a_permanent_zone_delete_answers_404(
    concurrent_client: AsyncClient, db_session: AsyncSession, case: str
) -> None:
    """The delete has taken the zone's rows and deleted them, and waits for the
    audit-chain lock, when the request arrives: the request waits for the
    delete, then finds the zone gone."""
    z = await _seed(db_session)
    gate = _Gate()
    try:
        await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        delete = _delete_zone(concurrent_client, z, permanent=True)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert (
            deleter is not None
        ), f"the zone delete never reached its audit: {await _answer(delete)}"
        write = _send(concurrent_client, z, case)
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, deleter[0], write)
        assert (
            writer is not None
        ), f"the request never waited on the zone delete: {await _answer(write)}"
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        w = await asyncio.wait_for(write, _STEP)
    finally:
        await gate.close()
    assert d.status_code == 204, f"the zone delete answered {_said(d)}; the request {_said(w)}"
    assert w.status_code == 404, f"{_said(w)} (the request waited in {writer[1]!r})"
    assert w.json() == {"detail": "Zone not found"}
    zone, every, _ = await _zone_state(z.zone_id)
    assert zone is None and every == 0, (zone, every)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CREATES + _EDITS)
async def test_a_permanent_zone_delete_waits_at_the_zone_row_for_a_record_write_holding_it(
    concurrent_client: AsyncClient, db_session: AsyncSession, case: str
) -> None:
    """The request has taken the zone row and written, and waits for the
    audit-chain lock, when the delete arrives: the delete waits for it at the
    zone row, before it touches a record, and deletes the zone after it."""
    z = await _seed(db_session)
    gate = _Gate()
    try:
        await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        write = _send(concurrent_client, z, case)
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, gate.pid, write)
        assert writer is not None, f"the request never reached its audit: {await _answer(write)}"
        delete = _delete_zone(concurrent_client, z, permanent=True)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, writer[0], delete)
        assert (
            deleter is not None
        ), f"the zone delete never waited on the request: {await _answer(delete)}"
        await gate.open()
        w = await asyncio.wait_for(write, _STEP)
        d = await asyncio.wait_for(delete, _STEP)
    finally:
        await gate.close()
    assert 200 <= w.status_code < 300, f"{_said(w)}; the zone delete {_said(d)}"
    assert (
        d.status_code == 204
    ), f"the zone delete answered {_said(d)} (it waited in {deleter[1]!r})"
    assert _is_zone_row_lock(deleter), f"the zone delete waited in {deleter!r}, not at the zone row"
    zone, every, _ = await _zone_state(z.zone_id)
    assert zone is None and every == 0, (zone, every)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CREATES + _EDITS)
async def test_a_record_write_waiting_on_a_soft_zone_delete_answers_404_without_a_deadlock(
    concurrent_client: AsyncClient, db_session: AsyncSession, case: str
) -> None:
    """A soft delete (the default) stamps the zone row, then its records. It
    has stamped the zone row and waits on the ``hold`` record when the request
    arrives: the request waits for it, then finds the zone gone. A request that
    held ``www`` while it waited for the zone row would deadlock the delete
    when its stamp reached ``www``."""
    z = await _seed(db_session)
    gate = _Gate()
    try:
        await gate.hold("SELECT id FROM dns_record WHERE id = :r FOR NO KEY UPDATE", r=z.hold_id)
        delete = _delete_zone(concurrent_client, z, permanent=False)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert deleter is not None, f"the zone delete never waited on hold: {await _answer(delete)}"
        write = _send(concurrent_client, z, case)
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, deleter[0], write)
        assert (
            writer is not None
        ), f"the request never waited on the zone delete: {await _answer(write)}"
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        w = await asyncio.wait_for(write, _STEP)
    finally:
        await gate.close()
    assert d.status_code == 204, f"the zone delete answered {_said(d)}; the request {_said(w)}"
    assert w.status_code == 404, f"{_said(w)} (the request waited in {writer[1]!r})"
    assert w.json() == {"detail": "Zone not found"}
    zone, every, live = await _zone_state(z.zone_id)
    assert zone is None and live == 0 and every >= 2, (zone, every, live)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _EDITS)
async def test_a_record_edit_beside_a_permanent_zone_delete_held_at_the_zone_row_never_deadlocks(
    concurrent_client: AsyncClient, db_session: AsyncSession, case: str
) -> None:
    """A key-share lock on the zone row (a foreign key check's, say) holds the
    delete at the zone row's lock. Before the fix the delete had deleted the
    zone's records by then, and an edit that went on took the zone row at its
    serial bump and waited on its record: a deadlock. Now the delete waits
    before it touches a record, and the edit either goes first or waits for
    the delete and answers 404."""
    z = await _seed(db_session)
    gate = _Gate()
    try:
        await gate.hold("SELECT id FROM dns_zone WHERE id = :z FOR KEY SHARE", z=z.zone_id)
        delete = _delete_zone(concurrent_client, z, permanent=True)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert (
            deleter is not None
        ), f"the zone delete never waited at the zone row: {await _answer(delete)}"
        write = _send(concurrent_client, z, case)
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, deleter[0], write)
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        w = await asyncio.wait_for(write, _STEP)
    finally:
        await gate.close()
    waited = f"waited in {writer[1]!r}" if writer else "did not wait"
    assert (
        d.status_code == 204
    ), f"the zone delete answered {_said(d)}; the request {_said(w)} ({waited})"
    went_first = 200 <= w.status_code < 300
    assert went_first or (
        w.status_code == 404 and w.json() == {"detail": "Zone not found"}
    ), f"{_said(w)} (the request {waited})"
    zone, every, _ = await _zone_state(z.zone_id)
    assert zone is None and every == 0, (zone, every)


# A second zone in the same group, for the control request.
_SIBLING = "sibling.example.com."


async def _sibling(db: AsyncSession, z: _Zone) -> _Zone:
    """A second zone in ``z``'s group, with its own ``www``. The request sent
    there, with no zone delete beside it, shows the op it queues."""
    s = _Zone()
    s.headers, s.group_id, s.name = z.headers, z.group_id, _SIBLING
    zone = DNSZone(group_id=z.group_id, name=_SIBLING, zone_type="primary", kind="forward")
    db.add(zone)
    await db.flush()
    www = DNSRecord(
        zone_id=zone.id, name="www", fqdn=f"www.{_SIBLING}", record_type="A", value="192.0.2.10"
    )
    db.add(www)
    await db.flush()
    s.zone_id, s.hold_id, s.www_id = zone.id, www.id, www.id
    await db.commit()
    return s


def _group_servers(group_id: uuid.UUID) -> Any:
    return DNSRecordOp.server_id.in_(select(DNSServer.id).where(DNSServer.group_id == group_id))


async def _queued_ops(group_id: uuid.UUID, zone_name: str) -> list[tuple[str, str, Any]]:
    """The ops still queued (pending or in flight) for ``zone_name`` on the
    group's servers, as ``(op, state, zone_id)``."""
    async with _TestSessionLocal() as check:
        rows = await check.execute(
            select(DNSRecordOp.op, DNSRecordOp.state, DNSRecordOp.zone_id).where(
                _group_servers(group_id),
                DNSRecordOp.zone_name == zone_name,
                DNSRecordOp.state.in_(QUEUED_OP_STATES),
            )
        )
        return [(r.op, r.state, r.zone_id) for r in rows]


async def _ops_without_a_zone(group_id: uuid.UUID) -> int:
    """The group's servers' ops whose zone row is gone (``dns_record_op.zone_id``
    is ``ON DELETE SET NULL``)."""
    async with _TestSessionLocal() as check:
        return (
            await check.execute(
                select(func.count())
                .select_from(DNSRecordOp)
                .where(_group_servers(group_id), DNSRecordOp.zone_id.is_(None))
            )
        ).scalar_one()


@pytest.mark.asyncio
@pytest.mark.parametrize("permanent", [False, True], ids=["soft", "permanent"])
@pytest.mark.parametrize("case", _CREATES + _EDITS)
async def test_a_zone_delete_behind_a_record_write_sweeps_the_op_the_write_queued(
    concurrent_client: AsyncClient, db_session: AsyncSession, case: str, permanent: bool
) -> None:
    """The group's BIND9 server is agent-based, so a record write queues an op
    for it. The request has taken the zone row, queued its op and waits for the
    audit-chain lock when the delete arrives, so its op commits after the
    delete has started. A sweep run before the delete waits at the zone row
    cannot see that op. Left behind, it stays queued against a zone the agent
    no longer serves (soft delete), or lives on with no zone (permanent delete:
    its ``zone_id`` is set NULL). The delete must sweep once it holds the row."""
    z = await _seed(db_session)
    sibling = await _sibling(db_session, z)
    control = await _send(concurrent_client, sibling, case)
    assert 200 <= control.status_code < 300, f"the control request answered {_said(control)}"
    assert await _queued_ops(
        z.group_id, _SIBLING
    ), f"the {case} request queued no op, so this test could not see one left behind"
    gate = _Gate()
    try:
        await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        write = _send(concurrent_client, z, case)
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, gate.pid, write)
        assert writer is not None, f"the request never reached its audit: {await _answer(write)}"
        delete = _delete_zone(concurrent_client, z, permanent=permanent)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, writer[0], delete)
        assert (
            deleter is not None
        ), f"the zone delete never waited on the request: {await _answer(delete)}"
        await gate.open()
        w = await asyncio.wait_for(write, _STEP)
        d = await asyncio.wait_for(delete, _STEP)
    finally:
        await gate.close()
    assert 200 <= w.status_code < 300, f"{_said(w)}; the zone delete {_said(d)}"
    assert d.status_code == 204, f"the zone delete answered {_said(d)}; the request {_said(w)}"
    left = await _queued_ops(z.group_id, z.name)
    assert left == [], f"the zone delete left these ops queued (op, state, zone_id): {left}"
    assert await _ops_without_a_zone(z.group_id) == 0
