"""Record delete, trash restore and subnet create must not deadlock a record
create on the same zone (#3503).

The #3389 shape on three more paths. A record create bumps its zone's serial
and flushes at once, so it holds the ``dns_zone`` row from then on, and takes
the audit-chain advisory lock only at its commit. Each of these took that lock
first and wrote the zone row afterwards:

* ``delete_record`` flushed its audit rows together with its serial bump, and
  the ``before_flush`` audit hook takes the chain lock before the flush runs
  ``UPDATE dns_zone``;
* trash restore flushed its audit rows, and recounted subnet utilization
  (which takes the chain lock, #3345), before ``push_records_restore`` bumped
  the zone;
* ``create_subnet`` flushed its audit row and recounted before the gateway's
  PTR bumped the reverse zone.

Each held the chain lock and waited for the zone row while the record create
held the row and waited for the lock: Postgres aborted one (40P01), a 500.

Same harness as ``test_dns_zone_row_audit_lock_order_3389``: the real
``create_record`` runs on its own session and is held right after its serial
flush; the other request is the real endpoint. Every step waits for Postgres
to report a backend blocked, never on a sleep, and every await is bounded.
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
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPBlock, IPSpace
from tests.conftest import _TestSessionLocal
from tests.test_dns_dynamic_update_acl import _bind9_group_zone_key, _superadmin
from tests.test_dns_server_move_render_deadlock_1703 import (
    _STEP,
    _cleanup,
    _prepare,
    _wait_blocked,
)
from tests.test_dns_zone_row_audit_lock_order_3389 import _holds_audit_chain_lock


async def _record_create_holds_zone_row_then(
    monkeypatch: pytest.MonkeyPatch,
    group_id: uuid.UUID,
    zone_id: uuid.UUID,
    user_id: uuid.UUID,
    body: dns_router.RecordCreate,
    writer: AsyncSession,
    write: Callable[[], Awaitable[Response]],
) -> tuple[Response, str, bool]:
    """A record create has flushed its serial bump (it holds the zone row) when
    the other request arrives. Returns that request's response, the statement
    it blocked in, and whether it held the audit-chain lock while it waited."""
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
        create = asyncio.create_task(
            dns_router.create_record(group_id, zone_id, body, creator, user)
        )
        await asyncio.wait_for(flushed.wait(), _STEP)

        write_task = asyncio.create_task(write())
        blocked_in = await _wait_blocked(writer_pid, write_task)
        held_chain_lock = await _holds_audit_chain_lock(writer_pid)

        resume.set()
        await asyncio.wait_for(create, _STEP)  # 40P01 on one side without the fix
        resp = await asyncio.wait_for(write_task, _STEP)
        return resp, blocked_in, held_chain_lock
    finally:
        resume.set()
        if write_task is not None and not write_task.done():
            write_task.cancel()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(write_task, 5)
        await _cleanup(create, [creator], pids)


async def _audited(resource_type: str, action: str) -> bool:
    async with _TestSessionLocal() as check:
        rows = set((await check.execute(select(AuditLog.resource_type, AuditLog.action))).all())
        return ("dns_record", "create") in rows and (resource_type, action) in rows


async def _live_fqdns(zone_id: uuid.UUID) -> list[str]:
    async with _TestSessionLocal() as check:
        rows = await check.execute(select(DNSRecord.fqdn).where(DNSRecord.zone_id == zone_id))
        return sorted(rows.scalars().all())


_A_BODY = dns_router.RecordCreate(name="r3503", record_type="A", value="192.0.2.35")


async def _committed_record(db: AsyncSession, zone: DNSZone, name: str) -> DNSRecord:
    rec = DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type="A",
        value="192.0.2.10",
    )
    db.add(rec)
    await db.commit()
    return rec


async def test_record_delete_waits_for_an_in_flight_record_create(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The soft (default) delete: its audit rows and serial bump in one flush."""
    user, headers = await _superadmin(db_session)
    group, zone, _ = await _bind9_group_zone_key(db_session)
    victim = await _committed_record(db_session, zone, "old")
    group_id, zone_id, record_id = group.id, zone.id, victim.id

    async def delete() -> Response:
        return await client.delete(
            f"/api/v1/dns/groups/{group_id}/zones/{zone_id}/records/{record_id}",
            headers=headers,
        )

    resp, blocked_in, held_chain_lock = await _record_create_holds_zone_row_then(
        monkeypatch, group_id, zone_id, user.id, _A_BODY, db_session, delete
    )
    assert resp.status_code == 204, resp.text
    assert await _live_fqdns(zone_id) == ["r3503.api.example.com."]
    assert await _audited("dns_record", "soft_delete")
    assert "UPDATE dns_zone" in blocked_in or "FOR NO KEY UPDATE" in blocked_in, blocked_in
    assert held_chain_lock is False


async def test_permanent_record_delete_waits_for_an_in_flight_record_create(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user, headers = await _superadmin(db_session)
    group, zone, _ = await _bind9_group_zone_key(db_session)
    victim = await _committed_record(db_session, zone, "old")
    group_id, zone_id, record_id = group.id, zone.id, victim.id

    async def delete() -> Response:
        return await client.delete(
            f"/api/v1/dns/groups/{group_id}/zones/{zone_id}/records/{record_id}",
            headers=headers,
            params={"permanent": "true"},
        )

    resp, blocked_in, held_chain_lock = await _record_create_holds_zone_row_then(
        monkeypatch, group_id, zone_id, user.id, _A_BODY, db_session, delete
    )
    assert resp.status_code == 204, resp.text
    assert await _live_fqdns(zone_id) == ["r3503.api.example.com."]
    assert await _audited("dns_record", "delete")
    assert held_chain_lock is False


async def test_trash_restore_waits_for_an_in_flight_record_create(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A soft-deleted record restored on its own: ``push_records_restore``
    bumps the zone after the restore's audit rows and recounts."""
    user, headers = await _superadmin(db_session)
    group, zone, _ = await _bind9_group_zone_key(db_session)
    victim = await _committed_record(db_session, zone, "old")
    group_id, zone_id, record_id = group.id, zone.id, victim.id
    r = await client.delete(
        f"/api/v1/dns/groups/{group_id}/zones/{zone_id}/records/{record_id}", headers=headers
    )
    assert r.status_code == 204, r.text
    assert await _live_fqdns(zone_id) == []

    async def restore() -> Response:
        return await client.post(
            f"/api/v1/admin/trash/dns_record/{record_id}/restore", headers=headers
        )

    resp, blocked_in, held_chain_lock = await _record_create_holds_zone_row_then(
        monkeypatch, group_id, zone_id, user.id, _A_BODY, db_session, restore
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["restored"] == 1
    assert await _live_fqdns(zone_id) == ["old.api.example.com.", "r3503.api.example.com."]
    assert await _audited("dns_record", "restore")
    # The zone row itself: its serial bump, or the id-ordered zone pre-lock
    # the re-push takes before it (#3617).
    assert "UPDATE dns_zone" in blocked_in or "FOR NO KEY UPDATE" in blocked_in, blocked_in
    assert held_chain_lock is False


async def test_subnet_create_waits_for_an_in_flight_record_create(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The new subnet's gateway PTR goes into an existing reverse zone that a
    record create is writing at the same moment."""
    user, headers = await _superadmin(db_session)
    group, forward, _ = await _bind9_group_zone_key(db_session)
    reverse = DNSZone(
        group_id=group.id, name="23.86.10.in-addr.arpa.", zone_type="primary", kind="reverse"
    )
    space = IPSpace(name=f"sp3503-{uuid.uuid4().hex[:8]}", description="")
    db_session.add_all([reverse, space])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.86.0.0/16", name="b")
    db_session.add(block)
    await db_session.commit()
    group_id, reverse_id, forward_id = group.id, reverse.id, forward.id
    space_id, block_id = space.id, block.id

    async def create_subnet() -> Response:
        return await client.post(
            "/api/v1/ipam/subnets",
            headers=headers,
            json={
                "space_id": str(space_id),
                "block_id": str(block_id),
                "network": "10.86.23.0/24",
                "dns_group_id": str(group_id),
                "dns_zone_id": str(forward_id),
            },
        )

    body = dns_router.RecordCreate(name="99", record_type="PTR", value="host.api.example.com.")
    resp, blocked_in, held_chain_lock = await _record_create_holds_zone_row_then(
        monkeypatch, group_id, reverse_id, user.id, body, db_session, create_subnet
    )
    assert resp.status_code == 201, resp.text
    assert await _live_fqdns(reverse_id) == [
        "1.23.86.10.in-addr.arpa.",  # the gateway's PTR
        "99.23.86.10.in-addr.arpa.",
    ]
    assert await _audited("subnet", "create")
    assert "dns_zone" in blocked_in, blocked_in
    assert held_chain_lock is False


async def test_a_flush_carrying_an_audit_row_locks_its_zone_rows_first() -> None:
    """The durable half: whichever path stages them, a flush with an audit row
    and a zone change takes the zone row before the audit-chain lock
    (``compute_audit_hashes``), so it never holds the lock while it waits."""
    async with _TestSessionLocal() as setup:
        _, zone, _ = await _bind9_group_zone_key(setup)
        await setup.commit()
        zone_id = zone.id

    holder = _TestSessionLocal()
    writer = _TestSessionLocal()
    pids: list[int] = []
    flush: asyncio.Task[None] | None = None
    try:
        pids.append(await _prepare(holder))
        writer_pid = await _prepare(writer)
        pids.append(writer_pid)
        # A record writer between its serial-bump flush and its commit.
        await asyncio.wait_for(
            holder.execute(
                text("UPDATE dns_zone SET last_serial = last_serial + 1 WHERE id = :z"),
                {"z": zone_id},
            ),
            _STEP,
        )
        row = await asyncio.wait_for(writer.get(DNSZone, zone_id), _STEP)
        assert row is not None
        row.last_serial = (row.last_serial or 0) + 100
        writer.add(
            AuditLog(
                user_display_name="system",
                action="update",
                resource_type="dns_zone",
                resource_id=str(zone_id),
                resource_display="api.example.com.",
            )
        )
        flush = asyncio.create_task(writer.flush())
        blocked_in = await _wait_blocked(writer_pid, flush)
        assert "FOR NO KEY UPDATE" in blocked_in, blocked_in
        assert await _holds_audit_chain_lock(writer_pid) is False
        await asyncio.wait_for(holder.commit(), _STEP)
        await asyncio.wait_for(flush, _STEP)
        await asyncio.wait_for(writer.commit(), _STEP)
    finally:
        await _cleanup(flush, [holder, writer], pids)


async def test_the_guard_flags_a_zone_write_after_the_chain_lock_and_only_that() -> None:
    """``tests/_audit_lock_order_guard.py`` (installed by conftest for every
    test) is what keeps a new path from reintroducing this. It must flag a zone
    row written after the chain lock was taken, by an audit flush or by
    ``lock_audit_chain``, and must not flag the safe orders."""
    from app.services.audit_chain import lock_audit_chain
    from tests import _audit_lock_order_guard as guard

    async with _TestSessionLocal() as setup:
        _, zone, _ = await _bind9_group_zone_key(setup)
        await setup.commit()
        zone_id = zone.id

    def audit() -> AuditLog:
        return AuditLog(
            user_display_name="system",
            action="update",
            resource_type="dns_zone",
            resource_id=str(zone_id),
            resource_display="api.example.com.",
        )

    async def run(steps: Callable[[AsyncSession, DNSZone], Awaitable[None]]) -> list[str]:
        guard.violations.clear()
        async with _TestSessionLocal() as s:
            z = await s.get(DNSZone, zone_id)
            assert z is not None
            await steps(s, z)
            await s.rollback()
        found = list(guard.violations)
        guard.violations.clear()
        return found

    async def audit_then_zone(s: AsyncSession, z: DNSZone) -> None:
        s.add(audit())
        await s.flush()
        z.last_serial = (z.last_serial or 0) + 1
        await s.flush()

    async def explicit_lock_then_zone(s: AsyncSession, z: DNSZone) -> None:
        await lock_audit_chain(s)
        z.last_serial = (z.last_serial or 0) + 1
        await s.flush()

    async def both_in_one_flush(s: AsyncSession, z: DNSZone) -> None:
        z.last_serial = (z.last_serial or 0) + 1
        s.add(audit())
        await s.flush()

    async def zone_audit_zone(s: AsyncSession, z: DNSZone) -> None:
        z.last_serial = (z.last_serial or 0) + 1
        await s.flush()
        s.add(audit())
        await s.flush()
        z.last_serial += 1  # the row is already this transaction's
        await s.flush()

    async def row_locked_then_audit_then_zone(s: AsyncSession, z: DNSZone) -> None:
        # A SELECT ... FOR NO KEY UPDATE takes the row as surely as a write.
        await s.execute(
            select(DNSZone.id).where(DNSZone.id == zone_id).with_for_update(key_share=True)
        )
        s.add(audit())
        await s.flush()
        z.last_serial = (z.last_serial or 0) + 1
        await s.flush()

    assert len(await run(audit_then_zone)) == 1
    assert await run(row_locked_then_audit_then_zone) == []
    assert len(await run(explicit_lock_then_zone)) == 1
    assert await run(both_in_one_flush) == []
    assert await run(zone_audit_zone) == []


async def test_subnet_create_spanning_an_existing_reverse_zone_takes_it_first(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A /23 whose first /24 already has a reverse zone: the subnet create
    makes the second zone (audited, so its flush takes the audit-chain lock)
    and the gateway's PTR then goes into the EXISTING one. That zone row must
    be this transaction's before the lock, or it is the #3503 order again."""
    from tests import _audit_lock_order_guard as guard

    _, headers = await _superadmin(db_session)
    group, forward, _ = await _bind9_group_zone_key(db_session)
    existing = DNSZone(
        group_id=group.id, name="22.87.10.in-addr.arpa.", zone_type="primary", kind="reverse"
    )
    space = IPSpace(name=f"sp3503b-{uuid.uuid4().hex[:8]}", description="")
    db_session.add_all([existing, space])
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.87.0.0/16", name="b")
    db_session.add(block)
    await db_session.commit()
    existing_id = existing.id

    guard.violations.clear()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": "10.87.22.0/23",
            "dns_group_id": str(group.id),
            "dns_zone_id": str(forward.id),
        },
    )
    assert resp.status_code == 201, resp.text
    found = list(guard.violations)
    guard.violations.clear()
    assert found == []
    assert await _live_fqdns(existing_id) == ["1.22.87.10.in-addr.arpa."]
    async with _TestSessionLocal() as check:
        names = set(
            (await check.execute(select(DNSZone.name).where(DNSZone.group_id == group.id)))
            .scalars()
            .all()
        )
    assert "23.87.10.in-addr.arpa." in names


async def _guarded(run: Callable[[], Awaitable[Any]]) -> tuple[Any, list[str]]:
    """``run``'s result and the guard's violations for it alone."""
    from tests import _audit_lock_order_guard as guard

    guard.violations.clear()
    result = await run()
    found = list(guard.violations)
    guard.violations.clear()
    return result, found


async def test_address_import_writes_a_later_rows_zone_before_the_audit_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The first row publishes nothing, so its audit row, flushed with the
    second row's insert, took the chain lock before the second row's sync
    bumped the zone. The audit rows are now added after the loop."""
    from tests.test_dns_sync_address_zone_2104 import _setup

    env = await _setup(client, db_session)
    zone_id = env.zone.id

    async def commit() -> Response:
        return await client.post(
            "/api/v1/ipam/import/addresses/commit",
            headers=env.headers,
            files={
                "file": (
                    "a.csv",
                    b"address,hostname\n10.104.5.40,\n10.104.5.41,h41\n",
                    "text/csv",
                )
            },
            data={"subnet_id": env.sid, "strategy": "skip"},
        )

    resp, found = await _guarded(commit)
    assert resp.status_code == 200, resp.text
    assert resp.json()["errors"] == [], resp.text
    assert found == []
    assert f"h41.{env.zone.name.rstrip('.')}" in await _live_fqdns(zone_id)
    async with _TestSessionLocal() as check:
        audited = set(
            (
                await check.execute(
                    select(AuditLog.resource_display).where(
                        AuditLog.resource_type == "ip_address", AuditLog.action == "create"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert sorted(d.split(" ")[0] for d in audited if d.startswith("10.104.5.4")) == [
        "10.104.5.40",
        "10.104.5.41",
    ]


async def test_permanent_zone_delete_through_the_copilot_audits_after_the_delete(
    db_session: AsyncSession,
) -> None:
    """``_apply_delete_zone``: its audit row went out with the set-based record
    delete's autoflush, taking the chain lock before ``db.delete(zone)``."""
    from app.services.ai.operations_risky import DeleteZoneArgs, _apply_delete_zone

    user, _ = await _superadmin(db_session)
    group, zone, _ = await _bind9_group_zone_key(db_session)
    db_session.add(
        DNSRecord(
            zone_id=zone.id, name="www", fqdn=f"www.{zone.name}", record_type="A", value="192.0.2.7"
        )
    )
    await db_session.commit()
    group_id, zone_id = group.id, zone.id

    async def delete() -> Any:
        return await _apply_delete_zone(
            db_session, user, DeleteZoneArgs(group_id=group_id, zone_id=zone_id, permanent=True)
        )

    result, found = await _guarded(delete)
    assert result == {"zone_id": str(zone_id), "mode": "delete"}
    assert found == []
    async with _TestSessionLocal() as check:
        gone = (
            await check.execute(
                select(DNSZone.id)
                .where(DNSZone.id == zone_id)
                .execution_options(include_deleted=True)
            )
        ).first() is None
        audited = (
            await check.execute(
                select(AuditLog.id).where(
                    AuditLog.resource_type == "dns_zone",
                    AuditLog.action == "delete",
                    AuditLog.resource_id == str(zone_id),
                )
            )
        ).first() is not None
    assert gone and audited
