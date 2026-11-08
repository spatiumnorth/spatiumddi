"""#3787: a subnet, block or space restored from the Trash gets back the DNS
records of the DHCP lease mirrors that come back with it.

The delete withdraws the A / PTR of the mirrors its scopes' teardown has yet to
remove (#3744), so they are deleted, not trashed, and a restore cannot bring
them back. The restore now hands the restored subnets to a post-commit task
that re-runs the DDNS policy for every active, unexpired lease mirror.

These tests go through the real endpoints: the leases are published by the
lease-events handler, the DELETE withdraws their records (its inline teardown
is given no time, so every lease outlives it, as a large scope's do), and the
Trash restore enqueues the task, which the test then runs against its own
session. On the unfixed code nothing is enqueued and the records stay gone.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPScope
from app.models.dns import DNSRecord, DNSRecordOp
from app.models.ipam import IPAddress, Subnet
from app.services.dhcp import lease_cleanup
from app.tasks import dhcp_lease_cleanup as lease_tasks
from app.tasks import ipam_dns_sync
from tests.test_ddns_lease_rename_1618 import _lease, _post, _setup
from tests.test_dhcp_scope_lease_teardown import _make_admin

_IPS = (60, 61, 62)


def _ips(octet: int) -> list[str]:
    return [f"10.93.{octet}.{n}" for n in _IPS]


async def _publish_leases(
    client: AsyncClient, db: AsyncSession, server: Any, octet: int
) -> list[str]:
    ips = _ips(octet)
    for ip in ips:
        await _post(client, db, server, _lease(ip, f"h{ip.split('.')[-1]}"))
    return ips


async def _records_by_ip(db: AsyncSession, subnet_id: Any) -> dict[str, list[str]]:
    """Live A / PTR records of the subnet's lease mirrors, by address, sorted —
    a list, so a duplicate shows."""
    db.expunge_all()
    rows = (
        await db.execute(
            select(IPAddress.address, DNSRecord.record_type)
            .join(DNSRecord, DNSRecord.ip_address_id == IPAddress.id)
            .where(IPAddress.subnet_id == subnet_id, IPAddress.auto_from_lease.is_(True))
        )
    ).all()
    out: dict[str, list[str]] = {}
    for addr, rtype in rows:
        out.setdefault(str(addr), []).append(rtype)
    return {k: sorted(v) for k, v in out.items()}


def _published(ips: list[str]) -> dict[str, list[str]]:
    return {ip: ["A", "PTR"] for ip in ips}


def _no_inline_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every lease outlives the delete: no inline teardown, and the follow-up
    task is never run (a restore that lands before it reaches them)."""
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_INLINE_DEADLINE_S", 0.0)
    monkeypatch.setattr(lease_tasks.tear_down_trashed_scope_leases, "delay", lambda *a: None)


def _capture_republish(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    queued: list[list[str]] = []

    class _Task:
        @staticmethod
        def delay(ids: list[str]) -> None:
            queued.append(list(ids))

    # ``raising=False``: on the unfixed code the task does not exist, nothing
    # is queued, and the assertions on the records are what fail.
    monkeypatch.setattr(ipam_dns_sync, "republish_restored_lease_ddns_task", _Task, raising=False)
    return queued


async def _run_queued(db: AsyncSession, queued: list[list[str]]) -> int:
    fired = 0
    for ids in queued:
        n, _wake = await ipam_dns_sync.republish_restored_lease_ddns(
            db, [uuid.UUID(i) for i in ids]
        )
        fired += n
    return fired


async def _delete_and_restore(
    client: AsyncClient,
    kind: str,
    subnet: Subnet,
    headers: dict[str, str],
    *,
    between: Any = None,
) -> None:
    url, target = {
        "subnet": (f"/api/v1/ipam/subnets/{subnet.id}", subnet.id),
        "block": (f"/api/v1/ipam/blocks/{subnet.block_id}", subnet.block_id),
        "space": (f"/api/v1/ipam/spaces/{subnet.space_id}", subnet.space_id),
    }[kind]
    gone = await client.delete(url, headers=headers)
    assert gone.status_code == 204, gone.text
    if between is not None:
        await between()
    trash_type = {"subnet": "subnet", "block": "ip_block", "space": "ip_space"}[kind]
    back = await client.post(f"/api/v1/admin/trash/{trash_type}/{target}/restore", headers=headers)
    assert back.status_code == 200, back.text


async def _setup_with_admin(
    db: AsyncSession, octet: int, **kwargs: Any
) -> tuple[Any, Subnet, dict[str, str]]:
    server, subnet, _zone, _ip = await _setup(db, octet, **kwargs)
    _admin, token = await _make_admin(db)
    await db.commit()
    return server, subnet, {"Authorization": f"Bearer {token}"}


async def _subnet(db: AsyncSession, sid: Any) -> Subnet:
    db.expunge_all()
    row = await db.get(Subnet, sid)
    assert row is not None
    return row


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["subnet", "block", "space"])
async def test_a_restore_brings_back_the_a_and_ptr_of_its_lease_mirrors(
    kind: str,
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    octet = {"subnet": 20, "block": 21, "space": 22}[kind]
    server, subnet, headers = await _setup_with_admin(db_session, octet)
    sid = subnet.id
    ips = await _publish_leases(client, db_session, server, octet)
    assert await _records_by_ip(db_session, sid) == _published(ips)

    _no_inline_teardown(monkeypatch)
    queued = _capture_republish(monkeypatch)

    async def _withdrawn() -> None:
        # The delete withdrew every record of the leases it left alive.
        assert await _records_by_ip(db_session, sid) == {}

    await _delete_and_restore(
        client, kind, await _subnet(db_session, sid), headers, between=_withdrawn
    )

    # Every lease came back with its mirror ...
    leases = (
        await db_session.execute(
            select(func.count())
            .select_from(DHCPLease)
            .join(DHCPScope, DHCPScope.id == DHCPLease.scope_id)
            .where(DHCPScope.subnet_id == sid)
        )
    ).scalar_one()
    assert leases == len(ips)
    # ... and the task the restore queued for the subnet gives them their names.
    assert queued == [[str(sid)]]
    assert await _run_queued(db_session, queued) == len(ips)
    assert await _records_by_ip(db_session, sid) == _published(ips)

    # A retried task, and a renewal of each lease, write nothing more and
    # duplicate nothing.
    ops = (await db_session.execute(select(func.count()).select_from(DNSRecordOp))).scalar_one()
    assert await _run_queued(db_session, queued) == 0
    for ip in ips:
        await _post(client, db_session, server, _lease(ip, f"h{ip.split('.')[-1]}"))
    assert await _records_by_ip(db_session, sid) == _published(ips)
    after = (await db_session.execute(select(func.count()).select_from(DNSRecordOp))).scalar_one()
    assert after == ops


@pytest.mark.asyncio
async def test_expired_and_released_leases_are_not_published(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    octet = 23
    server, subnet, headers = await _setup_with_admin(db_session, octet)
    sid = subnet.id
    live, expired, released = await _publish_leases(client, db_session, server, octet)
    _no_inline_teardown(monkeypatch)
    queued = _capture_republish(monkeypatch)

    async def _age() -> None:
        # While the subnet is in the Trash, one lease runs out and another is
        # released, neither swept yet.
        await db_session.execute(
            update(DHCPLease)
            .where(DHCPLease.ip_address == expired)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=60))
        )
        await db_session.execute(
            update(DHCPLease).where(DHCPLease.ip_address == released).values(state="expired")
        )
        await db_session.commit()

    await _delete_and_restore(
        client, "subnet", await _subnet(db_session, sid), headers, between=_age
    )

    assert await _run_queued(db_session, queued) == 1
    assert await _records_by_ip(db_session, sid) == _published([live])


@pytest.mark.asyncio
async def test_a_mirror_the_teardown_removed_after_the_enqueue_is_skipped(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#3777's race: the teardown batch in flight at the restore commits after
    the task has listed the mirrors. The task re-reads the rows under its locks,
    so it publishes nothing for a mirror that batch removed."""
    octet = 24
    server, subnet, headers = await _setup_with_admin(db_session, octet)
    sid = subnet.id
    ips = await _publish_leases(client, db_session, server, octet)
    _no_inline_teardown(monkeypatch)
    queued = _capture_republish(monkeypatch)
    await _delete_and_restore(client, "subnet", await _subnet(db_session, sid), headers)

    stale = await ipam_dns_sync.active_lease_mirror_ids(db_session, sid)
    assert len(stale) == len(ips)
    await db_session.rollback()
    # The batch in flight removes the first lease and its mirror ...
    gone = (
        await db_session.execute(select(DHCPLease).where(DHCPLease.ip_address == ips[0]))
    ).scalar_one()
    await lease_cleanup.purge_lease(db_session, gone, spare_if_peer_holds=False)
    await db_session.commit()

    # ... after the task listed it.
    async def _listed(_db: Any, _subnet_id: Any) -> list[Any]:
        return list(stale)

    monkeypatch.setattr(ipam_dns_sync, "active_lease_mirror_ids", _listed)
    assert await _run_queued(db_session, queued) == len(ips) - 1
    assert await _records_by_ip(db_session, sid) == _published(ips[1:])


@pytest.mark.asyncio
async def test_a_ddns_off_subnet_publishes_nothing(db_session: AsyncSession) -> None:
    server, subnet, _zone, _ip = await _setup(db_session, 25, ddns=False)
    sid = subnet.id
    scope = (
        await db_session.execute(select(DHCPScope).where(DHCPScope.subnet_id == sid))
    ).scalar_one()
    db_session.add(
        DHCPLease(
            server_id=server.id,
            scope_id=scope.id,
            ip_address="10.93.25.60",
            mac_address="aa:bb:cc:00:37:87",
            hostname="h60",
            state="active",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    db_session.add(
        IPAddress(
            subnet_id=sid,
            address="10.93.25.60",
            status="dhcp",
            hostname="h60",
            auto_from_lease=True,
        )
    )
    await db_session.commit()

    fired, wake = await ipam_dns_sync.republish_restored_lease_ddns(db_session, [sid])

    assert (fired, wake) == (0, set())
    assert await _records_by_ip(db_session, sid) == {}
    assert (await db_session.execute(select(DNSRecordOp))).scalars().all() == []


@pytest.mark.asyncio
async def test_a_subnet_deleted_again_before_the_task_runs_gets_nothing(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Delete, restore, delete again, and only then does the worker pick the
    task up: it must not publish the records the second delete withdrew."""
    octet = 26
    server, subnet, headers = await _setup_with_admin(db_session, octet)
    sid = subnet.id
    await _publish_leases(client, db_session, server, octet)
    _no_inline_teardown(monkeypatch)
    queued = _capture_republish(monkeypatch)
    await _delete_and_restore(client, "subnet", await _subnet(db_session, sid), headers)
    again = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert again.status_code == 204, again.text

    assert await _run_queued(db_session, queued) == 0
    assert await _records_by_ip(db_session, sid) == {}
