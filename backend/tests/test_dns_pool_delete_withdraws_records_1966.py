"""#1966 — deleting a DNS pool member (or a whole pool) withdraws its records.

``delete_member`` took the member out of ``pool.members`` so ``apply_pool_state``
could enqueue the record's delete before the row went. But the member is a
delete-orphan, and ``apply_pool_state``'s first query autoflushed it: the
``dns_record.pool_member_id`` FK ``ON DELETE CASCADE`` then removed the
record row too, the orphan sweep found nothing, and no delete op was ever
sent — the agent kept serving the address until some unrelated write made it
reconcile the whole zone. Driven through the real endpoints.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token
from app.drivers.dns import _DRIVERS, register_driver
from app.models.dns import (
    DNSPool,
    DNSRecord,
    DNSRecordOp,
    DNSServer,
    DNSServerGroup,
    DNSZone,
)
from tests.test_dns_agentless_after_commit_1539 import _FakeProvider
from tests.test_dns_pool_geo_steering import _pool_with_members, _superadmin

ADDRS = ["192.0.2.21", "192.0.2.22", "192.0.2.23"]


async def _group(db: AsyncSession, driver: str) -> tuple[DNSServerGroup, DNSZone, DNSServer]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver=driver,
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4() if driver != "windows_dns" else None,
    )
    db.add(server)
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    return grp, zone, server


async def _setup(
    db: AsyncSession, driver: str
) -> tuple[dict[str, str], DNSPool, DNSServer, dict[str, uuid.UUID]]:
    user = await _superadmin(db)
    grp, zone, server = await _group(db, driver)
    pool = await _pool_with_members(db, grp, zone, [{"address": a} for a in ADDRS])
    by_addr = {m.address: m.id for m in pool.members}
    pool_id, server_id = pool.id, server.id
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    await db.commit()
    pool = await db.get(DNSPool, pool_id)  # type: ignore[assignment]
    server = await db.get(DNSServer, server_id)  # type: ignore[assignment]
    return headers, pool, server, by_addr  # type: ignore[return-value]


async def _fresh_ops(db: AsyncSession, server_id: uuid.UUID, op: str) -> list[DNSRecordOp]:
    async with AsyncSession(db.bind, expire_on_commit=False) as other:
        return list(
            (
                await other.execute(
                    select(DNSRecordOp).where(
                        DNSRecordOp.server_id == server_id, DNSRecordOp.op == op
                    )
                )
            )
            .scalars()
            .all()
        )


async def _served_values(db: AsyncSession, zone_id: uuid.UUID) -> set[str]:
    async with AsyncSession(db.bind, expire_on_commit=False) as other:
        rows = await other.execute(
            select(DNSRecord.value).where(DNSRecord.zone_id == zone_id, DNSRecord.name == "www")
        )
        return set(rows.scalars().all())


@pytest.mark.asyncio
async def test_deleting_a_member_enqueues_a_delete_op_for_its_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, pool, server, by_addr = await _setup(db_session, "bind9")
    zone_id, server_id = pool.zone_id, server.id
    # The create ops queued when the pool was seeded are not what we look for.
    assert await _fresh_ops(db_session, server_id, "delete") == []

    gone = ADDRS[2]
    r = await client.delete(f"/api/v1/dns/pool-members/{by_addr[gone]}", headers=headers)
    assert r.status_code == 204, r.text

    deletes = await _fresh_ops(db_session, server_id, "delete")
    assert [(o.record["value"], o.record.get("rrset_action")) for o in deletes] == [
        (gone, "delete_value")
    ], "no delete op was queued: the agent keeps serving the removed member"
    assert await _served_values(db_session, zone_id) == set(ADDRS[:2])


@pytest.mark.asyncio
async def test_deleting_every_member_one_by_one_withdraws_each_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _pool, server, by_addr = await _setup(db_session, "bind9")
    server_id = server.id
    for addr in ADDRS:
        r = await client.delete(f"/api/v1/dns/pool-members/{by_addr[addr]}", headers=headers)
        assert r.status_code == 204, r.text
    deletes = await _fresh_ops(db_session, server_id, "delete")
    assert sorted(o.record["value"] for o in deletes) == sorted(ADDRS)


@pytest.mark.asyncio
async def test_deleting_a_pool_withdraws_every_member_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, pool, server, _by_addr = await _setup(db_session, "bind9")
    zone_id, server_id, pool_id = pool.zone_id, server.id, pool.id
    r = await client.delete(f"/api/v1/dns/pools/{pool_id}", headers=headers)
    assert r.status_code == 204, r.text
    deletes = await _fresh_ops(db_session, server_id, "delete")
    assert sorted(o.record["value"] for o in deletes) == sorted(ADDRS)
    assert await _served_values(db_session, zone_id) == set()


@pytest.mark.asyncio
async def test_agentless_group_member_delete_reaches_the_provider(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(_DRIVERS, "windows_dns", _DRIVERS["windows_dns"])  # restore on exit
    register_driver("windows_dns", _FakeProvider)  # type: ignore[arg-type]
    _FakeProvider.calls = []
    _FakeProvider.batches = []
    _FakeProvider.fail = False
    _FakeProvider.hook = None
    headers, _pool, _server, by_addr = await _setup(db_session, "windows_dns")
    _FakeProvider.calls = []  # the seeding pass's creates are not under test

    gone = ADDRS[1]
    r = await client.delete(f"/api/v1/dns/pool-members/{by_addr[gone]}", headers=headers)
    assert r.status_code == 204, r.text
    assert ("delete", "www", gone) in _FakeProvider.calls, _FakeProvider.calls


@pytest.mark.asyncio
async def test_apply_pool_state_orphan_sweep_survives_autoflush(
    db_session: AsyncSession,
) -> None:
    """The safety net under the endpoints: a caller that drops a member from
    ``pool.members`` and reconciles still gets a delete op, though the
    member is a pending delete-orphan the first read would autoflush."""
    from app.services.dns.pool_apply import apply_pool_state

    _headers, pool, server, by_addr = await _setup(db_session, "bind9")
    zone_id, server_id = pool.zone_id, server.id
    gone = ADDRS[0]
    pool.members = [m for m in pool.members if m.id != by_addr[gone]]
    summary = await apply_pool_state(db_session, pool)
    await db_session.commit()
    assert summary["deleted"] == 1
    deletes = await _fresh_ops(db_session, server_id, "delete")
    assert [o.record["value"] for o in deletes] == [gone]
    assert await _served_values(db_session, zone_id) == set(ADDRS[1:])


@pytest.mark.asyncio
async def test_disable_unhealthy_and_reenable_still_reconcile(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The non-delete paths that share ``_delete_pool_record``: an operator
    disable, a health-check flip to unhealthy, and a re-enable."""
    from app.services.dns.pool_apply import apply_pool_state

    headers, pool, server, by_addr = await _setup(db_session, "bind9")
    zone_id, server_id, pool_id = pool.zone_id, server.id, pool.id

    r = await client.put(
        f"/api/v1/dns/pool-members/{by_addr[ADDRS[0]]}", headers=headers, json={"enabled": False}
    )
    assert r.status_code == 200, r.text
    assert await _served_values(db_session, zone_id) == set(ADDRS[1:])

    # Health-check flip, the task's own call.
    db_session.expire_all()
    pool = await db_session.get(DNSPool, pool_id)  # type: ignore[assignment]
    for m in pool.members:
        if m.address == ADDRS[1]:
            m.last_check_state = "unhealthy"
    await apply_pool_state(db_session, pool)
    await db_session.commit()
    assert await _served_values(db_session, zone_id) == {ADDRS[2]}
    deletes = await _fresh_ops(db_session, server_id, "delete")
    assert sorted(o.record["value"] for o in deletes) == sorted(ADDRS[:2])

    r = await client.put(
        f"/api/v1/dns/pool-members/{by_addr[ADDRS[0]]}", headers=headers, json={"enabled": True}
    )
    assert r.status_code == 200, r.text
    assert await _served_values(db_session, zone_id) == {ADDRS[0], ADDRS[2]}
