"""The agent's requests and a server group move lock in one order (#1929).

A group move deletes the server's queued ops and zone-state rows. The agent's
config poll marks its ops ``in_flight`` and writes ``last_config_etag`` at
commit; its heartbeat acks ops; its zone-state report upserts state rows.

- #1929: read before the move's delete and written after it, those writes
  matched no row and the request answered 500 (``StaleDataError``).
- #1923's walk: once the move took the server row first (#1703), a poll
  holding its ops and wanting the server row deadlocked the move holding the
  server row and wanting the ops (40P01).

Every one of them now locks zone-state rows, then ops, then the server row
(``app.services.dns.row_locks``). Two real sessions, interleaved on what
``pg_stat_activity`` reports, every await bounded, backends terminated in
``finally`` (the harness is shared with the #1703 tests).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSServerZoneState, DNSZone
from app.services.dns import agent_token as dns_tokens
from app.services.dns.agent_config import page_pending_ops
from app.services.dns.server_move import move_server_to_group
from tests.conftest import _TestSessionLocal
from tests.test_dns_server_move_render_deadlock_1703 import (
    _STEP,
    _cleanup,
    _prepare,
    _wait_blocked,
)


async def _rig(db: AsyncSession, tag: str, *, ops: int = 2, state: bool = False) -> dict[str, Any]:
    src = DNSServerGroup(name=f"src{tag}")
    dst = DNSServerGroup(name=f"dst{tag}")
    db.add_all([src, dst])
    await db.flush()
    server = DNSServer(
        group_id=src.id,
        name="ns1",
        driver="bind9",
        host="10.0.0.1",
        port=53,
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
        agent_fingerprint="fp",
    )
    zone = DNSZone(
        group_id=src.id,
        name=f"z{tag}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add_all([server, zone])
    await db.flush()
    token, _exp = dns_tokens.mint_agent_token(str(server.id), str(server.agent_id), "fp")
    server.agent_jwt_hash = dns_tokens.hash_token(token)
    op_ids = []
    for i in range(ops):
        op = DNSRecordOp(
            server_id=server.id,
            zone_name=zone.name,
            op="create",
            record={"name": f"h{i}", "type": "A", "value": f"10.0.0.{i + 10}"},
            state="pending",
        )
        db.add(op)
        await db.flush()
        op_ids.append(op.id)
    if state:
        db.add(DNSServerZoneState(server_id=server.id, zone_id=zone.id, current_serial=1))
    await db.commit()
    return {
        "server_id": server.id,
        "dst_id": dst.id,
        "zone_name": zone.name,
        "op_ids": op_ids,
        "auth": {"Authorization": f"Bearer {token}"},
    }


async def _start_move(mover: AsyncSession, rig: dict[str, Any]) -> None:
    """Run the whole move in ``mover`` and leave it uncommitted: its deletes
    and locks are held until the test commits it."""
    server = await asyncio.wait_for(mover.get(DNSServer, rig["server_id"]), _STEP)
    target = await asyncio.wait_for(mover.get(DNSServerGroup, rig["dst_id"]), _STEP)
    assert server is not None and target is not None
    assert await asyncio.wait_for(move_server_to_group(mover, server, target), _STEP)
    await asyncio.wait_for(mover.flush(), _STEP)


async def _count(model: Any, *conds: Any) -> int:
    async with _TestSessionLocal() as check:
        return int(
            (
                await asyncio.wait_for(
                    check.execute(select(func.count()).select_from(model).where(*conds)), _STEP
                )
            ).scalar_one()
        )


async def _agent_request_racing_a_move(
    rig: dict[str, Any], db_session: AsyncSession, request: Any
) -> Response:
    """The move has deleted the rows (uncommitted) when the agent's request
    reads them; the request blocks on the move's locks, the move commits, and
    the request must then answer normally."""
    mover = _TestSessionLocal()
    pids: list[int] = []
    task: asyncio.Task[Response] | None = None
    try:
        pids.append(await _prepare(mover))
        # The client fixture's session. Its transaction stays open, so the
        # request runs on this connection (NullPool would hand a commit's
        # successor a new backend, and the pid would name the wrong one).
        request_pid = await _prepare(db_session)
        await _start_move(mover, rig)

        task = asyncio.create_task(request())
        await _wait_blocked(request_pid, task)
        await asyncio.wait_for(mover.commit(), _STEP)
        return await asyncio.wait_for(task, _STEP)  # StaleDataError on main
    finally:
        await _cleanup(task, [mover], pids)


@pytest.mark.parametrize("ops", [1, 2])
async def test_record_ops_poll_racing_a_move_answers_200(
    client: AsyncClient, db_session: AsyncSession, ops: int
) -> None:
    """One op: the flush matched no row (StaleDataError, a 500). Several: the
    batched UPDATE's row count goes unchecked, so the poll answered 200 and
    shipped ops the move had already discarded."""
    rig = await _rig(db_session, f"1929p{ops}", ops=ops)

    async def poll() -> Response:
        return await client.get("/api/v1/dns/agents/record-ops", headers=rig["auth"])

    resp = await _agent_request_racing_a_move(rig, db_session, poll)
    assert resp.status_code == 200, resp.text
    assert resp.json()["ops"] == []  # the move discarded them
    assert await _count(DNSRecordOp, DNSRecordOp.server_id == rig["server_id"]) == 0


async def test_zone_state_report_racing_a_move_answers_200(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rig = await _rig(db_session, "1929z", ops=0, state=True)

    async def report() -> Response:
        return await client.post(
            "/api/v1/dns/agents/zone-state",
            headers=rig["auth"],
            json={"zones": [{"zone_name": rig["zone_name"], "serial": 7}]},
        )

    resp = await _agent_request_racing_a_move(rig, db_session, report)
    assert resp.status_code == 200, resp.text
    # The zone belongs to the group the server left: skipped, not recorded.
    assert resp.json() == {"updated": 0, "skipped": 1}
    assert await _count(DNSServerZoneState, DNSServerZoneState.server_id == rig["server_id"]) == 0


async def test_heartbeat_acking_ops_racing_a_move_answers_200(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rig = await _rig(db_session, "1929h")

    async def heartbeat() -> Response:
        return await client.post(
            "/api/v1/dns/agents/heartbeat",
            headers=rig["auth"],
            json={"ops_ack": [{"op_id": str(i), "result": "ok"} for i in rig["op_ids"]]},
        )

    resp = await _agent_request_racing_a_move(rig, db_session, heartbeat)
    assert resp.status_code == 200, resp.text
    assert await _count(DNSRecordOp, DNSRecordOp.server_id == rig["server_id"]) == 0


async def test_poll_holding_its_ops_and_a_move_do_not_deadlock(db_session: AsyncSession) -> None:
    """#1923's walk: the poll has marked its page ``in_flight`` (holding those
    rows) and has yet to write ``last_config_etag`` when the move arrives."""
    rig = await _rig(db_session, "1929d")

    poller = _TestSessionLocal()
    mover = _TestSessionLocal()
    pids: list[int] = []
    task: asyncio.Task[None] | None = None
    try:
        pids.append(await _prepare(poller))
        mover_pid = await _prepare(mover)
        pids.append(mover_pid)
        server = await asyncio.wait_for(poller.get(DNSServer, rig["server_id"]), _STEP)
        assert server is not None
        page, _remaining = await asyncio.wait_for(page_pending_ops(poller, server), _STEP)
        assert len(page) == 2

        async def move() -> None:
            await _start_move(mover, rig)
            await asyncio.wait_for(mover.commit(), _STEP)

        task = asyncio.create_task(move())
        await _wait_blocked(mover_pid, task)

        # The poll's commit writes the server row. Before the fix the move
        # held it FOR UPDATE while it waited for the poll's ops: 40P01.
        server.last_config_etag = "etag1929"
        await asyncio.wait_for(poller.commit(), _STEP)
        await asyncio.wait_for(task, _STEP)
    finally:
        await _cleanup(task, [poller, mover], pids)

    async with _TestSessionLocal() as check:
        row = await check.get(DNSServer, rig["server_id"])
        assert row is not None
        assert row.group_id == rig["dst_id"]
        assert row.last_config_etag == "etag1929"
    # Shipped in_flight before the move, then discarded with the old group.
    assert await _count(DNSRecordOp, DNSRecordOp.server_id == rig["server_id"]) == 0
