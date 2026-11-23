"""#4775 — an agentless DHCP task must not hold a DB transaction across the
WinRM call, and the probe must fail fast on a host that answers nothing."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers import _winrm
from app.drivers.dhcp import windows as dhcp_windows
from app.models.dhcp import DHCPMACBlock, DHCPServer, DHCPServerGroup
from app.tasks import dhcp_health, dhcp_mac_blocks
from tests.conftest import _TestSessionLocal


class _FakeEngine:
    async def dispose(self) -> None:
        return None


def _install(monkeypatch: pytest.MonkeyPatch, module: Any) -> list[AsyncSession]:
    sessions: list[AsyncSession] = []
    monkeypatch.setattr(module, "create_async_engine", lambda *a, **k: _FakeEngine())

    def factory(*a: Any, **k: Any) -> Any:
        def make() -> Any:
            s = _TestSessionLocal()
            sessions.append(s)
            return s

        return make

    monkeypatch.setattr(module, "async_sessionmaker", factory)
    return sessions


def _any_open_txn(sessions: list[AsyncSession]) -> bool:
    return any(s.in_transaction() for s in sessions)


async def _server(db: AsyncSession) -> DHCPServer:
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="windows_dhcp",
        host="192.0.2.1",
        port=67,
        server_group_id=group.id,
    )
    db.add(srv)
    await db.flush()
    return srv


@pytest.mark.asyncio
async def test_health_probe_runs_with_no_open_transaction(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _server(db_session)
    await db_session.commit()
    srv_id = srv.id
    sessions = _install(monkeypatch, dhcp_health)
    seen: list[bool] = []

    class _Drv:
        async def health_check(self, server: Any) -> tuple[bool, str]:
            seen.append(_any_open_txn(sessions))
            return False, "down"

    monkeypatch.setattr(dhcp_health, "get_driver", lambda _n: _Drv())
    await dhcp_health._check_health(srv_id)
    assert seen == [False]
    db_session.expire_all()
    row = await db_session.get(DHCPServer, srv_id)
    assert row is not None and row.status == "unreachable" and row.last_health_check_at


@pytest.mark.asyncio
async def test_health_result_dropped_when_server_deleted_mid_probe(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _server(db_session)
    await db_session.commit()
    srv_id = srv.id
    _install(monkeypatch, dhcp_health)

    class _Drv:
        async def health_check(self, server: Any) -> tuple[bool, str]:
            async with _TestSessionLocal() as other:
                await other.delete(await other.get(DHCPServer, srv_id))
                await other.commit()
            return True, "ok"

    monkeypatch.setattr(dhcp_health, "get_driver", lambda _n: _Drv())
    await dhcp_health._check_health(srv_id)  # must not raise
    db_session.expire_all()
    assert await db_session.get(DHCPServer, srv_id) is None


@pytest.mark.asyncio
async def test_mac_sync_runs_with_no_open_transaction(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _server(db_session)
    db_session.add(DHCPMACBlock(group_id=srv.server_group_id, mac_address="aa:bb:cc:dd:ee:ff"))
    await db_session.commit()
    srv_id = srv.id
    sessions = _install(monkeypatch, dhcp_mac_blocks)
    seen: list[bool] = []

    class _Drv:
        async def sync_mac_blocks(self, server: Any, *, desired: Any) -> tuple[int, int]:
            seen.append(_any_open_txn(sessions))
            return (1, 0)

    monkeypatch.setattr(dhcp_mac_blocks, "get_driver", lambda _n: _Drv())
    result = await dhcp_mac_blocks._run_sync(force=True)
    assert seen == [False]
    assert result["servers_synced"] == 1
    db_session.expire_all()
    row = await db_session.get(DHCPServer, srv_id)
    assert row is not None and row.mac_blocks_pushed is True


def test_run_ps_connect_timeout_fails_fast_without_building_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, Any]] = []

    def fake_connect(addr: Any, timeout: Any = None) -> Any:
        calls.append((addr, timeout))
        raise TimeoutError("timed out")

    monkeypatch.setattr(_winrm.socket, "create_connection", fake_connect)
    with pytest.raises(RuntimeError, match="cannot connect to 192.0.2.1:5985 within 10s"):
        _winrm.run_ps(
            "192.0.2.1", {"username": "u", "password": "p"}, "1", connect_timeout_sec=10.0
        )
    assert calls == [(("192.0.2.1", 5985), 10.0)]


@pytest.mark.asyncio
async def test_driver_probe_paths_pass_the_connect_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs: list[dict[str, Any]] = []

    def fake_run(server: Any, creds: Any, script: str, **kw: Any) -> str:
        kwargs.append(kw)
        return "[]"

    monkeypatch.setattr(dhcp_windows, "_run_ps", fake_run)
    monkeypatch.setattr(dhcp_windows, "_load_credentials", lambda s: {})
    drv = dhcp_windows.WindowsDHCPReadOnlyDriver()
    srv = type("S", (), {"id": "x", "name": "w"})()
    await drv.health_check(srv)
    await drv.sync_mac_blocks(srv, desired=[])
    assert kwargs and all(
        k.get("connect_timeout_sec") == _winrm.PROBE_CONNECT_TIMEOUT_SEC for k in kwargs
    )
