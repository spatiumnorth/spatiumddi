"""#5008 — the scheduled lease pull reads agentless servers concurrently, and
writes the results one server at a time."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dhcp import DHCPLease, DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings
from app.services.dhcp import pull_leases as pl
from app.tasks import dhcp_pull_leases as task
from tests.test_dhcp_pull_leases_no_open_txn_4776 import (  # noqa: F401 — fixture
    _fake_redis,
    _FakeRedis,
    _install_task_sessions,
)


async def _arm_n(db: AsyncSession, n: int) -> list[DHCPServer]:
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.dhcp_pull_leases_enabled = True
    ps.dhcp_pull_leases_interval_seconds = 15
    ps.dhcp_pull_leases_last_run_at = None
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    servers = []
    for i in range(n):
        srv = DHCPServer(
            name=f"s{i}-{uuid.uuid4().hex[:6]}",
            driver="windows_dhcp",
            host=f"192.0.2.{i + 1}",
            port=67,
            server_group_id=grp.id,
        )
        db.add(srv)
        servers.append(srv)
    await db.commit()
    return servers


class _SlowDrv:
    def __init__(self, delay: float, fail_hosts: set[str] | None = None) -> None:
        self.delay = delay
        self.fail_hosts = fail_hosts or set()

    async def get_scopes(self, server: Any) -> list[dict[str, Any]]:
        return []

    async def get_failover_relationships(self, server: Any) -> dict[str, Any]:
        return {"ok": True, "relationships": []}

    async def get_leases(self, server: Any) -> list[dict[str, Any]]:
        await asyncio.sleep(self.delay)
        if server.host in self.fail_hosts:
            raise RuntimeError("winrm unreachable")
        last = int(server.host.rsplit(".", 1)[1])
        return [
            {"ip_address": f"10.9.0.{last}", "mac_address": f"aa:bb:cc:dd:ee:0{last}"},
        ]


@pytest.mark.asyncio
async def test_servers_are_read_concurrently_and_results_match_serial(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _arm_n(db_session, 3)
    _install_task_sessions(monkeypatch)
    monkeypatch.setattr(pl, "get_driver", lambda _n: _SlowDrv(1.0))

    t0 = time.monotonic()
    res = await task._run_pull()
    took = time.monotonic() - t0

    assert took < 2.5  # three 1 s reads together, not 3 s end to end
    assert res["status"] == "ran" and res["servers_scanned"] == 3
    assert res["server_leases"] == 3 and res["imported"] == 3 and res["errors"] == 0
    db_session.expire_all()
    assert len((await db_session.execute(select(DHCPLease))).scalars().all()) == 3
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "dhcp-lease-pull")))
        .scalars()
        .all()
    )
    assert len(audit) == 1
    assert audit[0].new_value["servers_scanned"] == 3 and audit[0].new_value["imported"] == 3
    assert _FakeRedis.store == {}  # every pass claim and the scan claim released


@pytest.mark.asyncio
async def test_one_failing_server_does_not_stop_the_others(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    servers = await _arm_n(db_session, 3)
    bad_id = servers[1].id
    _install_task_sessions(monkeypatch)
    monkeypatch.setattr(pl, "get_driver", lambda _n: _SlowDrv(0.1, {servers[1].host}))

    res = await task._run_pull()

    assert res["imported"] == 2 and res["errors"] == 1
    db_session.expire_all()
    bad = await db_session.get(DHCPServer, bad_id)
    assert bad is not None and "winrm unreachable" in (bad.last_sync_error or "")
    for srv in (servers[0], servers[2]):
        ok = await db_session.get(DHCPServer, srv.id)
        assert ok is not None and ok.last_sync_error is None


@pytest.mark.asyncio
async def test_a_stalled_server_times_out_and_is_recorded(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    servers = await _arm_n(db_session, 2)
    stalled = servers[0]
    stalled_id = stalled.id
    stalled_host = stalled.host
    _install_task_sessions(monkeypatch)
    monkeypatch.setattr(task, "_READ_TIMEOUT_S", 0.3)

    class _D(_SlowDrv):
        async def get_leases(self, server: Any) -> list[dict[str, Any]]:
            if server.host == stalled_host:
                await asyncio.sleep(30)
            return await super().get_leases(server)

    monkeypatch.setattr(pl, "get_driver", lambda _n: _D(0.0))

    t0 = time.monotonic()
    res = await task._run_pull()

    assert time.monotonic() - t0 < 5
    assert res["imported"] == 1 and res["errors"] >= 1
    db_session.expire_all()
    row = await db_session.get(DHCPServer, stalled_id)
    assert row is not None and "timed out" in (row.last_sync_error or "")
    assert _FakeRedis.store == {}


@pytest.mark.asyncio
async def test_a_server_held_by_a_manual_sync_is_skipped_and_never_read(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    servers = await _arm_n(db_session, 2)
    _install_task_sessions(monkeypatch)
    read: list[str] = []

    class _D(_SlowDrv):
        async def get_leases(self, server: Any) -> list[dict[str, Any]]:
            read.append(server.host)
            return await super().get_leases(server)

    monkeypatch.setattr(pl, "get_driver", lambda _n: _D(0.0))
    held = servers[0]
    await _FakeRedis().set(pl._PASS_CLAIM_PREFIX + str(held.id), "manual", nx=True, px=60_000)
    held_host = held.host

    res = await task._run_pull()

    assert res["servers_busy"] == 1 and res["imported"] == 1
    assert held_host not in read
    assert _FakeRedis.store[pl._PASS_CLAIM_PREFIX + str(held.id)][0] == "manual"
