"""A zone writer and a record create on the same zone must not deadlock (#3389).

A record create bumps the zone's serial and flushes at once, so its transaction
holds the ``dns_zone`` row from then on; it takes the audit-chain advisory lock
only at its commit, whose flush carries its audit row (``compute_audit_hashes``
runs in ``before_flush``). The ACL replace that flips ``dynamic_update_enabled``,
the zone PUT and ``apply-record`` left their zone change for that same commit
flush, so they took the two locks the other way round: the chain lock first,
then ``UPDATE dns_zone``, waiting for the record create's row lock while the
record create waited for the chain lock. Postgres aborted one of them (40P01)
and it answered a bare 500.

The real ``create_record`` runs on a session of its own and is held right after
its serial-bump flush; the zone writer is the real endpoint. Each step waits
until Postgres reports the other backend blocked on a lock, never on a sleep
(the ``test_dns_server_move_render_deadlock_1703`` pattern). Every await is
bounded, both backends run with a ``lock_timeout``, and ``finally`` closes and
terminates the record create's backend.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import router as dns_router
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSZone
from app.services.audit_chain import _AUDIT_CHAIN_LOCK_KEY
from tests.conftest import _TestSessionLocal
from tests.test_dns_dynamic_update_acl import _bind9_group_zone_key, _superadmin
from tests.test_dns_server_move_render_deadlock_1703 import (
    _STEP,
    _cleanup,
    _prepare,
    _wait_blocked,
)

# pg_locks shows a bigint advisory key as its high and low 32 bits, objsubid 1.
_CHAIN_HI = (_AUDIT_CHAIN_LOCK_KEY >> 32) & 0xFFFFFFFF
_CHAIN_LO = _AUDIT_CHAIN_LOCK_KEY & 0xFFFFFFFF


async def _holds_audit_chain_lock(pid: int) -> bool:
    async with _TestSessionLocal() as probe:
        row = (
            await asyncio.wait_for(
                probe.execute(
                    text(
                        "SELECT 1 FROM pg_locks WHERE pid = :p AND locktype = 'advisory' "
                        "AND granted AND classid = :hi AND objid = :lo AND objsubid = 1"
                    ),
                    {"p": pid, "hi": _CHAIN_HI, "lo": _CHAIN_LO},
                ),
                _STEP,
            )
        ).first()
        return row is not None


async def _record_create_holds_zone_row_then(
    monkeypatch: pytest.MonkeyPatch,
    ids: tuple[uuid.UUID, uuid.UUID, uuid.UUID],
    writer: AsyncSession,
    write: Callable[[], Awaitable[Response]],
) -> tuple[Response, str, bool]:
    """The reported interleave: a record create has flushed its serial bump, so
    it holds the zone row, when the zone writer arrives. Returns the writer's
    response, the statement it blocked in, and whether it held the audit-chain
    lock while it waited."""
    group_id, zone_id, user_id = ids
    flushed = asyncio.Event()
    resume = asyncio.Event()
    real_enqueue = dns_router.enqueue_record_op

    async def held_enqueue(*args: Any, **kwargs: Any) -> Any:
        # ``create_record`` calls this right after its serial-bump flush.
        flushed.set()
        await asyncio.wait_for(resume.wait(), _STEP)
        return await real_enqueue(*args, **kwargs)

    monkeypatch.setattr(dns_router, "enqueue_record_op", held_enqueue)

    creator = _TestSessionLocal()
    pids: list[int] = []
    create: asyncio.Task[DNSRecord] | None = None
    write_task: asyncio.Task[Response] | None = None
    try:
        pids.append(await _prepare(creator))
        writer_pid = await _prepare(writer)  # the client fixture's session
        user = await asyncio.wait_for(creator.get(User, user_id), _STEP)
        assert user is not None
        body = dns_router.RecordCreate(name="r3389", record_type="A", value="192.0.2.89")
        create = asyncio.create_task(
            dns_router.create_record(group_id, zone_id, body, creator, user)
        )
        await asyncio.wait_for(flushed.wait(), _STEP)

        write_task = asyncio.create_task(write())
        blocked_in = await _wait_blocked(writer_pid, write_task)
        held_chain_lock = await _holds_audit_chain_lock(writer_pid)

        # The writer is queued for the zone row. The record create must still
        # commit (its audit row takes the chain lock), and then the writer.
        resume.set()
        record = await asyncio.wait_for(create, _STEP)  # 40P01 on one side on main
        assert record.fqdn == "r3389.api.example.com."
        resp = await asyncio.wait_for(write_task, _STEP)
        return resp, blocked_in, held_chain_lock
    finally:
        resume.set()
        if write_task is not None and not write_task.done():
            write_task.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(write_task, 5)
        await _cleanup(create, [creator], pids)


async def _setup(db: AsyncSession) -> tuple[tuple[uuid.UUID, uuid.UUID, uuid.UUID], dict]:
    user, headers = await _superadmin(db)
    group, zone, _key = await _bind9_group_zone_key(db)
    await db.commit()
    return (group.id, zone.id, user.id), headers


async def _assert_both_landed(zone_id: uuid.UUID, writer_audit: tuple[str, str]) -> DNSZone:
    """The record and both audit rows are stored: nothing was rolled back."""
    async with _TestSessionLocal() as check:
        zone = (
            await asyncio.wait_for(
                check.execute(select(DNSZone).where(DNSZone.id == zone_id)), _STEP
            )
        ).scalar_one()
        fqdns = (
            (await check.execute(select(DNSRecord.fqdn).where(DNSRecord.zone_id == zone_id)))
            .scalars()
            .all()
        )
        assert fqdns == ["r3389.api.example.com."]
        audited = set((await check.execute(select(AuditLog.resource_type, AuditLog.action))).all())
        assert ("dns_record", "create") in audited
        assert writer_audit in audited
        assert zone.last_serial  # the record create's serial bump was kept
        return zone


async def test_acl_flag_flip_waits_for_an_in_flight_record_create(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reported request: the Dynamic Updates save that turns the flag on."""
    ids, headers = await _setup(db_session)
    group_id, zone_id, _ = ids

    async def put_acl() -> Response:
        return await client.put(
            f"/api/v1/dns/groups/{group_id}/zones/{zone_id}/update-acl",
            headers=headers,
            json={
                "dynamic_update_enabled": True,
                "entries": [{"match_kind": "ip", "action": "grant", "ip_cidr": "192.0.2.61/32"}],
            },
        )

    resp, blocked_in, held_chain_lock = await _record_create_holds_zone_row_then(
        monkeypatch, ids, db_session, put_acl
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["dynamic_update_enabled"] is True
    zone = await _assert_both_landed(zone_id, ("dns_zone", "update"))
    assert zone.dynamic_update_enabled is True
    # It waits for the zone row before it takes the audit-chain lock.
    assert "UPDATE dns_zone" in blocked_in, blocked_in
    assert held_chain_lock is False


async def test_zone_put_waits_for_an_in_flight_record_create(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The zone edit writes the same row the same way (the flag is a zone field too)."""
    ids, headers = await _setup(db_session)
    group_id, zone_id, _ = ids

    async def put_zone() -> Response:
        return await client.put(
            f"/api/v1/dns/groups/{group_id}/zones/{zone_id}",
            headers=headers,
            json={"dynamic_update_enabled": True},
        )

    resp, blocked_in, held_chain_lock = await _record_create_holds_zone_row_then(
        monkeypatch, ids, db_session, put_zone
    )
    assert resp.status_code == 200, resp.text
    zone = await _assert_both_landed(zone_id, ("dns_zone", "update"))
    assert zone.dynamic_update_enabled is True
    assert "UPDATE dns_zone" in blocked_in, blocked_in
    assert held_chain_lock is False


async def test_apply_record_waits_for_an_in_flight_record_create(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``apply-record`` bumps the serial in its commit flush, after the chain lock."""
    ids, headers = await _setup(db_session)
    group_id, zone_id, _ = ids
    server_id = (
        await db_session.execute(select(DNSServer.id).where(DNSServer.group_id == group_id))
    ).scalar_one()
    await db_session.commit()

    async def apply_record() -> Response:
        return await client.post(
            f"/api/v1/dns/servers/{server_id}/apply-record",
            headers=headers,
            json={"zone_id": str(zone_id), "record_id": str(uuid.uuid4()), "op": "delete"},
        )

    resp, blocked_in, held_chain_lock = await _record_create_holds_zone_row_then(
        monkeypatch, ids, db_session, apply_record
    )
    assert resp.status_code == 202, resp.text
    zone = await _assert_both_landed(zone_id, ("dns_zone", "apply_record"))
    assert zone.last_pushed_at is not None
    assert "UPDATE dns_zone" in blocked_in, blocked_in
    assert held_chain_lock is False
