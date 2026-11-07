"""The zone writers #3652 left out take the zone row first too (#3688).

``apply_record``, ``update_zone`` and ``apply_delegation`` read the zone plainly
and wrote its serial later: against a permanent zone delete the serial UPDATE
matched no row (``StaleDataError``, a bare 500), against a soft delete it wrote
into the trashed zone. The zone move wrote the zone row only after sweeping its
queued ops, so an op a record write queued meanwhile stayed queued for the old
group. ``retire_auto_reverse_zones`` swept a reverse zone's ops before it took
the zone row, the reverse of a zone delete's order.

Each test runs the real handlers on their own sessions, ordered by a third
session holding a lock (the audit-chain lock, which both take last). The
helpers are those of ``test_dns_record_write_zone_gone_3535``.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.audit_chain import _AUDIT_CHAIN_LOCK_KEY
from tests.conftest import _TestSessionLocal
from tests.test_dns_record_write_zone_gone_3535 import (
    _STEP,
    _answer,
    _blocked_by,
    _delete_zone,
    _Gate,
    _queued_op,
    _queued_ops,
    _said,
    _seed,
    _send,
    _Zone,
    _zone_state,
)
from tests.test_dns_record_write_zone_gone_3535 import (  # noqa: E402
    concurrent_client as concurrent_client_fixture,
)

concurrent_client = concurrent_client_fixture

_PERMANENT_OR_SOFT = pytest.mark.parametrize("permanent", [False, True], ids=["soft", "permanent"])


def _writer_request(client: AsyncClient, z: _Zone, case: str) -> asyncio.Task[Any]:
    if case == "update-zone":
        return asyncio.create_task(client.put(z.url, headers=z.headers, json={"ttl": 600}))
    if case == "rename-zone":
        return asyncio.create_task(
            client.put(z.url, headers=z.headers, json={"name": "renamed.example.com."})
        )
    if case == "apply-record":
        return asyncio.create_task(
            client.post(
                f"/api/v1/dns/servers/{z.server_id}/apply-record",
                headers=z.headers,
                json={"zone_id": str(z.zone_id), "record_id": str(z.www_id), "op": "update"},
            )
        )
    raise AssertionError(case)


_CASES = ["update-zone", "rename-zone", "apply-record"]


async def _with_server(db: AsyncSession, z: _Zone) -> _Zone:
    z.server_id = (  # type: ignore[attr-defined]
        await db.execute(select(DNSServer.id).where(DNSServer.group_id == z.group_id))
    ).scalar_one()
    return z


def _is_404(resp: Any) -> bool:
    return resp.status_code == 404 and "not found" in resp.json()["detail"].lower()


@pytest.mark.asyncio
@_PERMANENT_OR_SOFT
@pytest.mark.parametrize("case", _CASES)
async def test_a_writer_waiting_on_a_zone_delete_answers_404(
    concurrent_client: AsyncClient, db_session: AsyncSession, case: str, permanent: bool
) -> None:
    z = await _with_server(db_session, await _seed(db_session))
    gate = _Gate()
    try:
        if permanent:
            await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        else:
            await gate.hold(
                "SELECT id FROM dns_record WHERE id = :r FOR NO KEY UPDATE", r=z.hold_id
            )
        delete = _delete_zone(concurrent_client, z, permanent=permanent)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert deleter is not None, f"the delete never waited: {await _answer(delete)}"
        write = _writer_request(concurrent_client, z, case)
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, deleter[0], write)
        assert writer is not None, f"the request never waited on the delete: {await _answer(write)}"
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        w = await asyncio.wait_for(write, _STEP)
    finally:
        await gate.close()
    assert d.status_code == 204, f"delete {_said(d)}; request {_said(w)}"
    assert _is_404(w), f"{_said(w)} (waited in {writer[1]!r})"
    zone, _, live = await _zone_state(z.zone_id)
    assert zone is None and live == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CASES)
async def test_a_permanent_delete_waits_for_a_writer_holding_the_zone_row(
    concurrent_client: AsyncClient, db_session: AsyncSession, case: str
) -> None:
    z = await _with_server(db_session, await _seed(db_session))
    if case == "rename-zone":  # a zone holding records cannot be renamed
        await db_session.execute(sa_delete(DNSRecord).where(DNSRecord.zone_id == z.zone_id))
        await db_session.commit()
    gate = _Gate()
    try:
        await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        write = _writer_request(concurrent_client, z, case)
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, gate.pid, write)
        assert writer is not None, f"the request never reached its audit: {await _answer(write)}"
        delete = _delete_zone(concurrent_client, z, permanent=True)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, writer[0], delete)
        assert deleter is not None, f"the delete never waited: {await _answer(delete)}"
        await gate.open()
        w = await asyncio.wait_for(write, _STEP)
        d = await asyncio.wait_for(delete, _STEP)
    finally:
        await gate.close()
    assert 200 <= w.status_code < 300, f"{_said(w)}; delete {_said(d)}"
    assert d.status_code == 204, f"delete {_said(d)}"


# --- apply_delegation ------------------------------------------------------


async def _parent_and_child(db: AsyncSession) -> tuple[_Zone, _Zone]:
    parent = await _seed(db)
    zone = (await db.execute(select(DNSZone).where(DNSZone.id == parent.zone_id))).scalar_one()
    child_name = f"sub.{zone.name}"
    child_zone = DNSZone(
        group_id=zone.group_id, name=child_name, zone_type="primary", kind="forward"
    )
    db.add(child_zone)
    await db.flush()
    ns = DNSRecord(
        zone_id=child_zone.id,
        name="@",
        fqdn=child_name,
        record_type="NS",
        value="ns1.sub.example.com.",
    )
    db.add(ns)
    await db.flush()
    child = _Zone()
    child.headers, child.group_id, child.name = parent.headers, parent.group_id, child_name
    child.zone_id, child.hold_id, child.www_id = child_zone.id, ns.id, ns.id
    await db.commit()
    return parent, child


@pytest.mark.asyncio
@_PERMANENT_OR_SOFT
@pytest.mark.parametrize("victim", ["parent", "child"])
async def test_a_delegation_waiting_on_a_zone_delete_answers_404(
    concurrent_client: AsyncClient, db_session: AsyncSession, permanent: bool, victim: str
) -> None:
    parent, child = await _parent_and_child(db_session)
    target = parent if victim == "parent" else child
    gate = _Gate()
    try:
        if permanent:
            await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        else:
            await gate.hold(
                "SELECT id FROM dns_record WHERE id = :r FOR NO KEY UPDATE", r=target.hold_id
            )
        delete = _delete_zone(concurrent_client, target, permanent=permanent)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert deleter is not None, f"the delete never waited: {await _answer(delete)}"
        deleg = asyncio.create_task(
            concurrent_client.post(f"{child.url}/delegate-from-parent", headers=child.headers)
        )
        gate.tasks.append(deleg)
        writer = await _blocked_by(gate.probe, deleter[0], deleg)
        assert writer is not None, f"the request never waited: {await _answer(deleg)}"
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        w = await asyncio.wait_for(deleg, _STEP)
    finally:
        await gate.close()
    assert d.status_code == 204, f"delete {_said(d)}; delegation {_said(w)}"
    assert w.status_code == 404, f"{_said(w)} (waited in {writer[1]!r})"


# --- the zone move ---------------------------------------------------------


@pytest.mark.asyncio
async def test_a_zone_move_behind_a_record_write_leaves_no_op_for_the_old_group(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    z = await _seed(db_session)
    target = DNSServerGroup(name=f"target-{uuid.uuid4().hex[:6]}")
    db_session.add(target)
    await db_session.flush()
    db_session.add(DNSServer(group_id=target.id, name="ns2", driver="bind9", host="10.0.0.54"))
    target_id = target.id
    await db_session.commit()
    gate = _Gate()
    try:
        await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        write = _send(concurrent_client, z, "create")
        gate.tasks.append(write)
        writer = await _blocked_by(gate.probe, gate.pid, write)
        assert writer is not None, f"the request never reached its audit: {await _answer(write)}"
        move = asyncio.create_task(
            concurrent_client.post(
                f"{z.url}/move/commit",
                headers=z.headers,
                json={"target_group_id": str(target_id), "confirmation_zone_name": z.name},
            )
        )
        gate.tasks.append(move)
        mover = await _blocked_by(gate.probe, writer[0], move)
        assert mover is not None, f"the move never waited on the request: {await _answer(move)}"
        await gate.open()
        w = await asyncio.wait_for(write, _STEP)
        m = await asyncio.wait_for(move, _STEP)
    finally:
        await gate.close()
    assert 200 <= w.status_code < 300, f"{_said(w)}; move {_said(m)}"
    assert m.status_code == 200, f"move {_said(m)} (waited in {mover[1]!r})"
    left = await _queued_ops(z.group_id, z.name)
    assert left == [], f"the move left these ops queued for the old group: {left}"


@pytest.mark.asyncio
async def test_a_zone_move_beside_a_permanent_delete_never_deadlocks(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    z = await _seed(db_session)
    op_id = await _queued_op(db_session, z)
    target = DNSServerGroup(name=f"target-{uuid.uuid4().hex[:6]}")
    db_session.add(target)
    await db_session.flush()
    db_session.add(DNSServer(group_id=target.id, name="ns2", driver="bind9", host="10.0.0.54"))
    target_id = target.id
    await db_session.commit()
    gate = _Gate()
    try:
        await gate.hold("SELECT id FROM dns_record_op WHERE id = :o FOR UPDATE", o=op_id)
        delete = _delete_zone(concurrent_client, z, permanent=True)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert deleter is not None, f"the delete never waited: {await _answer(delete)}"
        move = asyncio.create_task(
            concurrent_client.post(
                f"{z.url}/move/commit",
                headers=z.headers,
                json={"target_group_id": str(target_id), "confirmation_zone_name": z.name},
            )
        )
        gate.tasks.append(move)
        mover = await _blocked_by(gate.probe, deleter[0], move)
        assert mover is not None, f"the move never waited on the delete: {await _answer(move)}"
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        m = await asyncio.wait_for(move, _STEP)
    finally:
        await gate.close()
    assert d.status_code == 204, f"delete {_said(d)}; move {_said(m)}"
    assert m.status_code == 404, f"move {_said(m)} (waited in {mover[1]!r})"


# --- retire_auto_reverse_zones --------------------------------------------


@pytest.mark.asyncio
async def test_a_subnet_delete_behind_a_reverse_zone_delete_does_not_deadlock(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    z = await _seed(db_session)
    space = IPSpace(name=f"rz3688-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.68.0.0/16", name="B")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.68.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    zone = (await db_session.execute(select(DNSZone).where(DNSZone.id == z.zone_id))).scalar_one()
    z.subnet_id = subnet.id  # type: ignore[attr-defined]
    zone.is_auto_generated = True
    zone.linked_subnet_id = subnet.id
    zone.kind = "reverse"
    subnet_id = subnet.id
    await db_session.commit()
    await _queued_op(db_session, z)
    gate = _Gate()
    try:
        await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        delete = _delete_zone(concurrent_client, z, permanent=True)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert deleter is not None, f"the delete never reached its audit: {await _answer(delete)}"
        sub = asyncio.create_task(
            concurrent_client.delete(f"/api/v1/ipam/subnets/{subnet_id}", headers=z.headers)
        )
        gate.tasks.append(sub)
        retirer = await _blocked_by(gate.probe, deleter[0], sub)
        assert retirer is not None, f"the subnet delete never waited: {await _answer(sub)}"
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        s = await asyncio.wait_for(sub, _STEP)
    finally:
        await gate.close()
    assert d.status_code == 204, f"zone delete {_said(d)}; subnet delete {_said(s)}"
    assert s.status_code == 204, f"subnet delete {_said(s)} (waited in {retirer[1]!r})"


@pytest.mark.asyncio
async def test_retiring_a_reverse_zone_takes_the_zone_row_before_it_sweeps_its_ops(
    concurrent_client: AsyncClient, db_session: AsyncSession
) -> None:
    """The subnet and block deletes pre-lock their zones, so this calls
    ``retire_auto_reverse_zones`` itself, as a caller that does not would: it
    must wait for a zone delete at the zone row, not at the zone's ops, and
    find the zone gone once the delete has committed."""
    from app.services.dns.reverse_zone import retire_auto_reverse_zones  # noqa: PLC0415

    z = await _seed(db_session)
    space = IPSpace(name=f"rz3688b-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.69.0.0/16", name="B")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.69.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    zone = (await db_session.execute(select(DNSZone).where(DNSZone.id == z.zone_id))).scalar_one()
    zone.is_auto_generated, zone.linked_subnet_id, zone.kind = True, subnet.id, "reverse"
    subnet_id = subnet.id
    await db_session.commit()
    await _queued_op(db_session, z)

    async def retire() -> list[Any]:
        async with _TestSessionLocal() as db:
            sub = await db.get(Subnet, subnet_id)
            assert sub is not None
            retired, _, _ = await retire_auto_reverse_zones(db, sub)
            await db.commit()
            return retired

    gate = _Gate()
    try:
        await gate.hold("SELECT pg_advisory_xact_lock(:k)", k=_AUDIT_CHAIN_LOCK_KEY)
        delete = _delete_zone(concurrent_client, z, permanent=True)
        gate.tasks.append(delete)
        deleter = await _blocked_by(gate.probe, gate.pid, delete)
        assert deleter is not None, f"the delete never reached its audit: {await _answer(delete)}"
        retiring = asyncio.create_task(retire())
        gate.tasks.append(retiring)  # type: ignore[arg-type]
        waiter = await _blocked_by(gate.probe, deleter[0], retiring)  # type: ignore[arg-type]
        assert waiter is not None, "the retirement never waited on the zone delete"
        await gate.open()
        d = await asyncio.wait_for(delete, _STEP)
        retired = await asyncio.wait_for(retiring, _STEP)
    finally:
        await gate.close()
    assert d.status_code == 204, _said(d)
    assert retired == [], "the retirement took a zone the delete had removed"
    assert waiter.row_of == "dns_zone", f"it waited at {waiter!r}, not at the zone row"


# --- the Technitium retry re-assert ----------------------------------------


@pytest.mark.asyncio
async def test_an_ack_bumps_no_reverse_zone_until_its_transaction_is_committed(
    db_session: AsyncSession,
) -> None:
    """The ack holds the acked op rows. The PTR re-assert bumps the reverse zone,
    and a zone delete takes the zone row, then the zone's ops: so the re-assert
    is returned to the caller to run after its commit, in a transaction that
    holds no op row (#3688), and does the work then."""
    from app.models.dns import DNSRecordOp  # noqa: PLC0415
    from tests import test_technitium_ptr_reassert_1800 as t  # noqa: PLC0415

    servers, fwd, rev = await t._group(db_session, servers=1)
    await t._ptr(db_session, rev)
    await t.enqueue_record_op(db_session, fwd, "delete", t._a_delete())
    a_op = await t._retry_a_delete_after_the_ptr_create(db_session, servers[0], reassert=False)
    pending = (
        await db_session.execute(
            select(DNSRecordOp.id).where(
                DNSRecordOp.zone_name == t.REV,
                DNSRecordOp.op == "create",
                DNSRecordOp.state == "pending",
            )
        )
    ).all()
    assert pending == [], "the ack re-asserted the PTR inside its own transaction"
    assert a_op.state == "applied"


# --- a committed delegation answers from what it wrote ----------------------


@pytest.mark.asyncio
async def test_a_delegation_whose_records_are_deleted_right_after_commit_answers_201(
    concurrent_client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parent zone delete queued behind the delegation's zone lock runs the
    moment it commits and removes the records it just wrote. The route must
    answer its 201 from what it wrote, not refresh them after the commit."""
    parent, child = await _parent_and_child(db_session)
    real_commit = AsyncSession.commit
    armed = {"on": True}

    async def commit_then_delete(self: AsyncSession) -> None:
        await real_commit(self)
        if not armed["on"]:
            return
        armed["on"] = False
        async with _TestSessionLocal() as other:
            await other.execute(
                sa_delete(DNSRecord).where(
                    DNSRecord.zone_id == parent.zone_id, DNSRecord.name == "sub"
                )
            )
            await real_commit(other)

    monkeypatch.setattr(AsyncSession, "commit", commit_then_delete)
    resp = await concurrent_client.post(f"{child.url}/delegate-from-parent", headers=child.headers)
    assert resp.status_code == 201, _said(resp)
    assert armed["on"] is False, "the commit hook never fired"
    assert any(r["record_type"] == "NS" and r["name"] == "sub" for r in resp.json()), resp.text
