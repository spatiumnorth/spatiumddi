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


class _FakeRedis:
    """Just the calls the pass claim makes; ``now`` is a controllable clock."""

    store: dict[str, tuple[str, float]] = {}
    now: float = 0.0

    def __init__(self, *a: Any, **k: Any) -> None:
        pass

    async def set(self, key: str, val: str, nx: bool = False, px: int = 0) -> bool:
        cur = self.store.get(key)
        if nx and cur is not None and cur[1] > self.now:
            return False
        self.store[key] = (val, self.now + px / 1000)
        return True

    async def eval(self, _script: str, _n: int, key: str, token: str) -> int:
        cur = self.store.get(key)
        if cur is not None and cur[0] == token:
            del self.store[key]
            return 1
        return 0

    async def aclose(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _fake_redis(monkeypatch: pytest.MonkeyPatch) -> type[_FakeRedis]:
    _FakeRedis.store = {}
    _FakeRedis.now = 0.0
    monkeypatch.setattr(pl, "make_async_redis", lambda *a, **k: _FakeRedis())
    return _FakeRedis


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
async def test_pull_result_dropped_when_driver_changed_mid_pull(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-pointed at an agent-based driver while the reads ran: the stale wire
    data is not written."""
    srv = await _arm(db_session)
    srv_id = srv.id
    sessions = _install_task_sessions(monkeypatch)

    async def _repoint() -> None:
        async with _TestSessionLocal() as other:
            row = await other.get(DHCPServer, srv_id)
            assert row is not None
            row.driver = "kea"
            await other.commit()

    monkeypatch.setattr(pl, "get_driver", lambda _n: _Drv(sessions, on_read=_repoint))

    res = await task._run_pull()

    assert res["servers_busy"] == 1 and res["imported"] == 0
    db_session.expire_all()
    rows = (
        (await db_session.execute(select(DHCPLease).where(DHCPLease.server_id == srv_id)))
        .scalars()
        .all()
    )
    assert rows == []


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


@pytest.mark.asyncio
async def test_second_pass_while_first_is_mid_read_answers_busy_and_reads_nothing(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _arm(db_session)
    sessions = _install_task_sessions(monkeypatch)
    outcomes: list[Any] = []

    async def _overlap() -> None:
        # The first pass is inside its wire read, holding no transaction.
        async with _TestSessionLocal() as other:
            other_srv = await other.get(DHCPServer, srv.id)
            assert other_srv is not None
            drv2 = _Drv([])
            monkeypatch.setattr(pl, "get_driver", lambda _n: drv2)
            outcomes.append(
                (
                    await pl.pull_leases_from_server(
                        other, other_srv, apply=True, release_txn_for_wire=True
                    ),
                    drv2,
                )
            )
            await other.rollback()
            monkeypatch.setattr(pl, "get_driver", lambda _n: drv1)

    drv1 = _Drv(sessions, on_read=_overlap)
    monkeypatch.setattr(pl, "get_driver", lambda _n: drv1)

    res = await task._run_pull()

    second, drv2 = outcomes[0]
    assert second.busy is True and drv2.seen == []
    assert res["servers_scanned"] == 1 and res["imported"] == 1
    assert _FakeRedis.store == {}  # released after the pass


@pytest.mark.asyncio
async def test_claim_released_after_a_failed_pass(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _arm(db_session)

    class _Boom(_Drv):
        async def get_leases(self, server: Any) -> list[dict[str, Any]]:
            raise RuntimeError("boom")

    monkeypatch.setattr(pl, "get_driver", lambda _n: _Boom([]))

    # A crash inside the core (not just a driver error) must also release.
    async def _explode(*a: Any, **k: Any) -> Any:
        raise RuntimeError("core")

    result = await pl.pull_leases_from_server(
        db_session, srv, apply=True, release_txn_for_wire=True
    )
    assert result.errors and _FakeRedis.store == {}
    monkeypatch.setattr(pl, "_pull_leases_core", _explode)
    with pytest.raises(RuntimeError):
        await pl.pull_leases_from_server(db_session, srv, apply=True, release_txn_for_wire=True)
    assert _FakeRedis.store == {}


@pytest.mark.asyncio
async def test_stale_claim_from_a_crashed_worker_is_reclaimable(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _arm(db_session)
    drv = _Drv([])
    monkeypatch.setattr(pl, "get_driver", lambda _n: drv)
    await _FakeRedis().set(pl._PASS_CLAIM_PREFIX + str(srv.id), "dead", nx=True, px=300_000)

    busy = await pl.pull_leases_from_server(db_session, srv, apply=True, release_txn_for_wire=True)
    assert busy.busy is True and drv.seen == []

    _FakeRedis.now += 301  # the TTL passes; the crashed worker never released
    ok = await pl.pull_leases_from_server(db_session, srv, apply=True, release_txn_for_wire=True)
    assert ok.busy is False and ok.imported == 1


@pytest.mark.asyncio
async def test_second_scan_while_first_holds_the_scan_claim_reads_no_server(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _arm(db_session)
    _install_task_sessions(monkeypatch)
    drv = _Drv([])
    monkeypatch.setattr(pl, "get_driver", lambda _n: drv)
    await _FakeRedis().set(pl._SCAN_CLAIM_KEY, "other-scan", nx=True, px=300_000)

    res = await task._run_pull()

    assert res == {"status": "skipped", "reason": "pass_busy"}
    assert drv.seen == []
    assert _FakeRedis.store[pl._SCAN_CLAIM_KEY][0] == "other-scan"  # not released by us


@pytest.mark.asyncio
async def test_scan_claim_released_after_an_exception(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _arm(db_session)
    _install_task_sessions(monkeypatch)

    async def _explode(*a: Any, **k: Any) -> Any:
        raise RuntimeError("boom")

    import app.services.dhcp.pull_leases as mod

    monkeypatch.setattr(mod, "pull_leases_from_server", _explode)
    res = await task._run_pull()  # per-server failures are recorded, not raised
    assert res["status"] == "ran" and _FakeRedis.store == {}

    def _fatal(*a: Any, **k: Any) -> Any:
        raise RuntimeError("fatal")

    monkeypatch.setattr(task, "is_agentless", _fatal)
    await _arm(db_session)  # re-opens the interval gate
    with pytest.raises(RuntimeError):
        await task._run_pull()
    assert _FakeRedis.store == {}


@pytest.mark.asyncio
async def test_scan_claim_expiry_scales_with_server_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ok, tok = await pl.claim_scan(2)
    assert ok
    assert _FakeRedis.store[pl._SCAN_CLAIM_KEY][1] == 300.0  # floor
    await pl.release_scan(tok)
    ok, tok = await pl.claim_scan(20)
    assert ok
    assert _FakeRedis.store[pl._SCAN_CLAIM_KEY][1] == 20 * 60.0  # covers 20 servers
    await pl.release_scan(tok)
    assert _FakeRedis.store == {}


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
