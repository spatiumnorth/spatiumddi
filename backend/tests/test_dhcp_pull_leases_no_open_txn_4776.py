"""#4776 — the agentless lease pull must not hold a DB transaction across the
WinRM reads, and must still write the result (or drop it when the server was
deleted meanwhile)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers import _winrm
from app.drivers.dhcp import windows as dhcp_windows
from app.models.dhcp import DHCPLease, DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings
from app.services.dhcp import pull_leases as pl
from app.tasks import dhcp_pull_leases as task
from tests.conftest import _TestSessionLocal


class _FakeEngine:
    async def dispose(self) -> None:
        return None


def _install_task_sessions(monkeypatch: pytest.MonkeyPatch) -> list[AsyncSession]:
    sessions: list[AsyncSession] = []
    monkeypatch.setattr(task, "create_async_engine", lambda *a, **k: _FakeEngine())

    def factory(*a: Any, **k: Any) -> Any:
        def make() -> Any:
            s = _TestSessionLocal()
            sessions.append(s)
            return s

        return make

    monkeypatch.setattr(task, "async_sessionmaker", factory)
    return sessions


async def _arm(db: AsyncSession) -> DHCPServer:
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
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="windows_dhcp",
        host="192.0.2.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.commit()
    return srv


class _Drv:
    """Records whether any session had a transaction open at each wire read."""

    def __init__(self, sessions: list[AsyncSession], on_read: Any = None) -> None:
        self.sessions = sessions
        self.seen: list[bool] = []
        self.on_read = on_read

    def _note(self) -> None:
        self.seen.append(any(s.in_transaction() for s in self.sessions))

    async def get_scopes(self, server: Any) -> list[dict[str, Any]]:
        self._note()
        return []

    async def get_failover_relationships(self, server: Any) -> dict[str, Any]:
        self._note()
        return {"ok": True, "relationships": []}

    async def get_leases(self, server: Any) -> list[dict[str, Any]]:
        self._note()
        if self.on_read is not None:
            await self.on_read()
        return [{"ip_address": "10.9.0.50", "mac_address": "aa:bb:cc:dd:ee:01", "hostname": "h"}]


@pytest.mark.asyncio
async def test_pull_reads_the_wire_with_no_open_transaction(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _arm(db_session)
    srv_id = srv.id
    sessions = _install_task_sessions(monkeypatch)
    drv = _Drv(sessions)
    monkeypatch.setattr(pl, "get_driver", lambda _n: drv)

    res = await task._run_pull()

    assert res["status"] == "ran" and res["servers_scanned"] == 1
    assert drv.seen == [False, False, False]  # scopes, failover, leases
    db_session.expire_all()
    rows = (
        (await db_session.execute(select(DHCPLease).where(DHCPLease.server_id == srv_id)))
        .scalars()
        .all()
    )
    assert [str(r.ip_address) for r in rows] == ["10.9.0.50"]


@pytest.mark.asyncio
async def test_pull_result_dropped_when_server_deleted_mid_pull(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _arm(db_session)
    srv_id = srv.id
    sessions = _install_task_sessions(monkeypatch)

    async def _delete() -> None:
        async with _TestSessionLocal() as other:
            await other.delete(await other.get(DHCPServer, srv_id))
            await other.commit()

    monkeypatch.setattr(pl, "get_driver", lambda _n: _Drv(sessions, on_read=_delete))

    res = await task._run_pull()  # must not raise

    assert res["status"] == "ran" and res["servers_busy"] == 1 and res["errors"] == 0
    db_session.expire_all()
    assert await db_session.get(DHCPServer, srv_id) is None


@pytest.mark.asyncio
async def test_pull_without_release_flag_keeps_its_transaction(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The manual Sync (no flag) is untouched: it still reads inside the
    request's transaction and commits nothing itself."""
    srv = await _arm(db_session)
    drv = _Drv([db_session])
    monkeypatch.setattr(pl, "get_driver", lambda _n: drv)

    result = await pl.pull_leases_from_server(db_session, srv, apply=True)

    assert result.errors == [] and result.imported == 1
    assert drv.seen == [True, True, True]


def test_windows_pull_reads_pass_the_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    kwargs: list[dict[str, Any]] = []

    def fake_run(server: Any, creds: Any, script: str, **kw: Any) -> str:
        kwargs.append(kw)
        return "[]"

    monkeypatch.setattr(dhcp_windows, "_run_ps", fake_run)
    monkeypatch.setattr(dhcp_windows, "_load_credentials", lambda s: {})
    drv = dhcp_windows.WindowsDHCPReadOnlyDriver()
    srv = type("S", (), {"id": "x", "name": "w"})()

    async def go() -> None:
        await drv.get_leases(srv)
        await drv.get_scopes(srv)
        try:
            await drv.get_failover_relationships(srv)
        except Exception:  # noqa: BLE001 — "[]" may not parse; the kwarg is what matters
            pass

    asyncio.run(go())
    assert len(kwargs) == 3
    assert all(k.get("connect_timeout_sec") == _winrm.PROBE_CONNECT_TIMEOUT_SEC for k in kwargs)
