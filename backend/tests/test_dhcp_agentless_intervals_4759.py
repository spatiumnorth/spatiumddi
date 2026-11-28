"""#4759 — the agentless DHCP health sweep and MAC-block sync ran every 60 s,
hard-coded, one WinRM session per server, and the sync read the filter list
even when no block had ever existed.

Covered: the health fan-out honours ``dhcp_health_interval_seconds`` for
agentless servers while still checking agent-based ones on every tick; the MAC
sync honours its own interval (and ``force``), skips a server with nothing to
push and nothing pushed before, and still syncs once to clear a removed last
block; the setting validators.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.settings.router import SettingsUpdate
from app.models.dhcp import DHCPMACBlock, DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings
from app.tasks import dhcp_health, dhcp_mac_blocks
from tests.conftest import _TestSessionLocal


class _FakeEngine:
    async def dispose(self) -> None:
        return None


def _use_test_db(monkeypatch: pytest.MonkeyPatch, module: Any) -> None:
    monkeypatch.setattr(module, "create_async_engine", lambda *a, **k: _FakeEngine())
    monkeypatch.setattr(module, "async_sessionmaker", lambda *a, **k: _TestSessionLocal)


async def _server(
    db: AsyncSession, driver: str, group: DHCPServerGroup | None = None
) -> DHCPServer:
    if group is None:
        group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        db.add(group)
        await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host="127.0.0.1",
        port=67,
        server_group_id=group.id,
    )
    db.add(srv)
    await db.flush()
    return srv


async def _ps(db: AsyncSession, **fields: Any) -> PlatformSettings:
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    for k, v in fields.items():
        setattr(ps, k, v)
    await db.commit()
    return ps


# ── health fan-out ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_fanout_gates_agentless_but_not_agent_servers(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    kea = await _server(db_session, "kea")
    win = await _server(db_session, "windows_dhcp")
    await _ps(
        db_session,
        dhcp_health_interval_seconds=600,
        dhcp_health_last_run_at=datetime.now(UTC) - timedelta(seconds=60),
    )
    _use_test_db(monkeypatch, dhcp_health)
    enqueued: list[str] = []
    monkeypatch.setattr(
        dhcp_health.check_dhcp_server_health, "delay", lambda sid: enqueued.append(sid)
    )

    batches: list[list[str]] = []
    monkeypatch.setattr(
        dhcp_health.check_agentless_dhcp_servers_health, "delay", lambda ids: batches.append(ids)
    )

    await dhcp_health._enqueue_all()
    assert enqueued == [str(kea.id)]  # agentless one waits for its 600 s interval
    assert batches == []

    # Interval elapsed: both are checked, and the stamp moves.
    await _ps(db_session, dhcp_health_last_run_at=datetime.now(UTC) - timedelta(seconds=601))
    enqueued.clear()
    await dhcp_health._enqueue_all()
    assert enqueued == [str(kea.id)]
    assert batches == [[str(win.id)]]  # #4829 — agentless go out as one batch
    db_session.expire_all()
    ps = await db_session.get(PlatformSettings, 1)
    assert ps is not None and datetime.now(UTC) - ps.dhcp_health_last_run_at < timedelta(seconds=30)


# ── MAC-block sync ───────────────────────────────────────────────


class _Driver:
    def __init__(self) -> None:
        self.calls: list[list[Any]] = []

    async def sync_mac_blocks(self, server: Any, *, desired: Any) -> tuple[int, int]:
        self.calls.append(list(desired))
        return (0, 0)


def _patch_driver(monkeypatch: pytest.MonkeyPatch) -> _Driver:
    drv = _Driver()
    monkeypatch.setattr(dhcp_mac_blocks, "get_driver", lambda _name: drv)
    _use_test_db(monkeypatch, dhcp_mac_blocks)
    return drv


@pytest.mark.asyncio
async def test_mac_sync_skips_server_with_no_blocks_and_nothing_pushed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _server(db_session, "windows_dhcp")
    await db_session.commit()
    drv = _patch_driver(monkeypatch)
    result = await dhcp_mac_blocks._run_sync()
    assert result["status"] == "ok"
    assert drv.calls == []
    assert result["servers_synced"] == 0


@pytest.mark.asyncio
async def test_mac_sync_pushes_then_clears_once_after_last_block_removed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _server(db_session, "windows_dhcp")
    block = DHCPMACBlock(group_id=srv.server_group_id, mac_address="aa:bb:cc:dd:ee:ff")
    db_session.add(block)
    await db_session.commit()
    srv_id, block_id = srv.id, block.id
    drv = _patch_driver(monkeypatch)

    await dhcp_mac_blocks._run_sync()
    assert len(drv.calls) == 1 and len(drv.calls[0]) == 1
    db_session.expire_all()
    assert (await db_session.get(DHCPServer, srv_id)).mac_blocks_pushed is True  # type: ignore[union-attr]

    # Last block removed: one more sync, with an empty desired list, clears the server.
    await db_session.delete(await db_session.get(DHCPMACBlock, block_id))
    await db_session.commit()
    await dhcp_mac_blocks._run_sync(force=True)
    assert len(drv.calls) == 2 and drv.calls[1] == []
    db_session.expire_all()
    assert (await db_session.get(DHCPServer, srv_id)).mac_blocks_pushed is False  # type: ignore[union-attr]

    # And from then on the server is left alone.
    await dhcp_mac_blocks._run_sync(force=True)
    assert len(drv.calls) == 2


@pytest.mark.asyncio
async def test_mac_sync_follows_a_server_moved_between_groups(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server never pushed to still syncs when it joins a group that has blocks,
    and one moved out of a blocked group into an unblocked one is cleared once."""
    blocked = DHCPServerGroup(name=f"b-{uuid.uuid4().hex[:6]}", description="")
    free = DHCPServerGroup(name=f"f-{uuid.uuid4().hex[:6]}", description="")
    db_session.add_all([blocked, free])
    await db_session.flush()
    db_session.add(DHCPMACBlock(group_id=blocked.id, mac_address="aa:bb:cc:dd:ee:01"))
    srv = await _server(db_session, "windows_dhcp", free)
    await db_session.commit()
    srv_id, blocked_id, free_id = srv.id, blocked.id, free.id
    drv = _patch_driver(monkeypatch)

    await dhcp_mac_blocks._run_sync(force=True)
    assert drv.calls == []  # flag false, nothing applies

    (await db_session.get(DHCPServer, srv_id)).server_group_id = blocked_id  # type: ignore[union-attr]
    await db_session.commit()
    await dhcp_mac_blocks._run_sync(force=True)
    assert len(drv.calls) == 1 and len(drv.calls[0]) == 1  # applies newly: pushed despite flag

    db_session.expire_all()
    (await db_session.get(DHCPServer, srv_id)).server_group_id = free_id  # type: ignore[union-attr]
    await db_session.commit()
    await dhcp_mac_blocks._run_sync(force=True)
    assert len(drv.calls) == 2 and drv.calls[1] == []  # cleared once on leaving
    await dhcp_mac_blocks._run_sync(force=True)
    assert len(drv.calls) == 2


@pytest.mark.asyncio
async def test_mac_sync_honours_interval_and_force(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _server(db_session, "windows_dhcp")
    db_session.add(DHCPMACBlock(group_id=srv.server_group_id, mac_address="aa:bb:cc:dd:ee:01"))
    await _ps(
        db_session,
        dhcp_mac_blocks_sync_interval_seconds=900,
        dhcp_mac_blocks_sync_last_run_at=datetime.now(UTC) - timedelta(seconds=60),
    )
    drv = _patch_driver(monkeypatch)

    result = await dhcp_mac_blocks._run_sync()
    assert result["status"] == "skipped" and drv.calls == []

    # An operator's write kicks the task with force and is pushed now.
    await dhcp_mac_blocks._run_sync(force=True)
    assert len(drv.calls) == 1

    # Once the interval has elapsed the beat tick runs on its own.
    await _ps(
        db_session,
        dhcp_mac_blocks_sync_last_run_at=datetime.now(UTC) - timedelta(seconds=901),
    )
    await dhcp_mac_blocks._run_sync()
    assert len(drv.calls) == 2


# ── validation ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "field", ["dhcp_health_interval_seconds", "dhcp_mac_blocks_sync_interval_seconds"]
)
def test_interval_validation(field: str) -> None:
    assert getattr(SettingsUpdate(**{field: 300}), field) == 300
    for bad in (10, 59, 3601):
        with pytest.raises(ValidationError):
            SettingsUpdate(**{field: bad})
