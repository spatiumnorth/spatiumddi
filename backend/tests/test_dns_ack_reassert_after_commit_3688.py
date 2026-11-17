"""The #1800 PTR re-assert, run after the agent's ack commits (#3688).

Moving it out of the ack's transaction left two things to get right:

* a failure in that second transaction must not turn a committed heartbeat or
  ack into a 500 — the acks, the unacknowledged-op reset and any rotated agent
  token are already committed, so a 500 keeps the new token from the agent and
  has it resend acks that already landed;
* the reverse zone is read before it is locked, so the re-read after the lock
  must see the row as the lock found it: a serial another writer committed in
  between is where the bump counts from, not the value read earlier.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.models.dns import DNSRecordOp, DNSZone
from tests import test_technitium_ptr_reassert_1800 as t
from tests.conftest import _TestSessionLocal
from tests.test_dns_agent_bundle_ops_gate import _agent, _op

_FAKE_RETRIED = [("z.example.", {"name": "web", "type": "A", "value": "192.0.2.10"})]


async def _boom(*_a: Any, **_k: Any) -> None:
    raise RuntimeError("deadlock detected")


async def _state(op_id: Any) -> str:
    async with _TestSessionLocal() as db:
        return (
            await db.execute(select(DNSRecordOp.state).where(DNSRecordOp.id == op_id))
        ).scalar_one()


@pytest.mark.asyncio
async def test_a_failed_reassert_leaves_the_ack_route_answering_ok(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, zone, headers = await _agent(db_session)
    op = _op(server.id, zone, "h1")
    op.state = "in_flight"
    db_session.add(op)
    await db_session.commit()
    op_id = op.id
    real_ack = agents_api.ack_op

    async def ack_with_a_retried_delete(*a: Any, **k: Any) -> list[Any]:
        await real_ack(*a, **k)
        return list(_FAKE_RETRIED)

    monkeypatch.setattr(agents_api, "ack_op", ack_with_a_retried_delete)
    monkeypatch.setattr(agents_api, "reassert_after_retried_deletes", _boom)
    resp = await client.post(
        f"/api/v1/dns/agents/ops/{op_id}/ack", headers=headers, json={"result": "ok"}
    )
    assert resp.status_code == 200, resp.text
    assert await _state(op_id) == "applied"


@pytest.mark.asyncio
async def test_a_failed_reassert_leaves_the_heartbeat_answering_ok(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, zone, headers = await _agent(db_session)
    op = _op(server.id, zone, "h1")
    op.state = "in_flight"
    db_session.add(op)
    await db_session.commit()
    op_id, server_id = op.id, server.id
    real_apply = agents_api.apply_acks

    async def acks_with_a_retried_delete(*a: Any, **k: Any) -> list[Any]:
        await real_apply(*a, **k)
        return list(_FAKE_RETRIED)

    monkeypatch.setattr(agents_api, "apply_acks", acks_with_a_retried_delete)
    monkeypatch.setattr(agents_api, "reassert_after_retried_deletes", _boom)
    resp = await client.post(
        "/api/v1/dns/agents/heartbeat",
        headers=headers,
        json={"ops_ack": [{"op_id": str(op_id), "result": "ok"}]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["server_id"] == str(server_id)
    assert await _state(op_id) == "applied"


@pytest.mark.asyncio
async def test_the_reassert_bumps_from_the_serial_its_lock_found(
    db_session: AsyncSession,
) -> None:
    servers, fwd, rev = await t._group(db_session, servers=1)
    await t._ptr(db_session, rev)
    await t.enqueue_record_op(db_session, fwd, "delete", t._a_delete())
    a_op = await t._retry_a_delete_after_the_ptr_create(db_session, servers[0], reassert=False)
    assert a_op.state == "applied"
    retried = [(a_op.zone_name, dict(a_op.record))]
    rev_id = rev.id
    await db_session.commit()
    # Another writer bumps the reverse zone after this session last read it.
    committed = 3_000_000_000
    async with _TestSessionLocal() as other:
        await other.execute(
            update(DNSZone).where(DNSZone.id == rev_id).values(last_serial=committed)
        )
        await other.commit()
    await record_reassert(db_session, servers[0].id, retried)
    await db_session.commit()
    serials = [
        op.target_serial
        for op in (
            await db_session.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.zone_name == t.REV,
                    DNSRecordOp.op == "create",
                    DNSRecordOp.state == "pending",
                )
            )
        )
        .scalars()
        .all()
    ]
    assert serials, "the re-assert queued no PTR create"
    assert all(s is not None and s > committed for s in serials), serials
    async with _TestSessionLocal() as other:
        stored = (
            await other.execute(select(DNSZone.last_serial).where(DNSZone.id == rev_id))
        ).scalar_one()
    assert stored > committed, f"the serial went back from {committed} to {stored}"


async def record_reassert(db: AsyncSession, server_id: Any, retried: list[Any]) -> None:
    from app.services.dns.record_ops import reassert_after_retried_deletes  # noqa: PLC0415

    await reassert_after_retried_deletes(db, server_id, retried)


@pytest.mark.asyncio
async def test_retiring_a_reverse_zone_sweeps_the_group_its_lock_found(
    db_session: AsyncSession,
) -> None:
    """``retire_auto_reverse_zones`` reads its plan, locks the zones, and reads
    the plan again. A zone a move re-homed in between must be swept in the
    group it is in now, not the one the first read saw."""
    import uuid  # noqa: PLC0415

    from app.models.dns import DNSServer, DNSServerGroup  # noqa: PLC0415
    from app.models.ipam import IPBlock, IPSpace, Subnet  # noqa: PLC0415
    from app.services.dns.reverse_zone import retire_auto_reverse_zones  # noqa: PLC0415

    old, new = DNSServerGroup(name="rz-old"), DNSServerGroup(name="rz-new")
    db_session.add_all([old, new])
    await db_session.flush()
    new_srv = DNSServer(group_id=new.id, name="ns-new", driver="bind9", host="10.0.0.9")
    space = IPSpace(name=f"rz-{uuid.uuid4().hex[:6]}", description="")
    db_session.add_all([new_srv, space])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.70.0.0/16", name="B")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.70.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    zone = DNSZone(
        group_id=old.id,
        name="1.70.10.in-addr.arpa.",
        zone_type="primary",
        kind="reverse",
        is_auto_generated=True,
        linked_subnet_id=subnet.id,
    )
    db_session.add(zone)
    await db_session.commit()
    zone_id, new_id, new_srv_id = zone.id, new.id, new_srv.id
    # A move re-homes the zone and a write queues an op for its new group's
    # server, after this session loaded the zone.
    async with _TestSessionLocal() as other:
        await other.execute(update(DNSZone).where(DNSZone.id == zone_id).values(group_id=new_id))
        other.add(
            DNSRecordOp(
                server_id=new_srv_id,
                zone_name=zone.name,
                op="create",
                record={"name": "5", "type": "PTR", "value": "h.example."},
                state="pending",
            )
        )
        await other.commit()
    retired, _, wake = await retire_auto_reverse_zones(db_session, subnet)
    await db_session.commit()
    assert [z.id for z in retired] == [zone_id]
    assert wake == {new_id}, wake
    async with _TestSessionLocal() as other:
        left = (
            await other.execute(select(DNSRecordOp.id).where(DNSRecordOp.server_id == new_srv_id))
        ).all()
    assert left == [], "the retirement left an op queued for the zone's current group"
