"""#2306 — a failing scheduled lease pull is persisted on the server row.

The pull task used to put a failure only in the audit log, so a Windows DHCP
server whose lease cmdlet kept failing stayed green on the server list. The
error is now stored on ``dhcp_server.last_sync_error`` and the API returns it;
a later successful pull clears it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings
from app.services.dhcp import pull_leases as pl
from app.tasks import dhcp_pull_leases as task


async def _arm(db: AsyncSession) -> uuid.UUID:
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.dhcp_pull_leases_enabled = True
    ps.dhcp_pull_leases_interval_seconds = 10
    ps.dhcp_pull_leases_last_run_at = None
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"w-{uuid.uuid4().hex[:6]}",
        driver="windows_dhcp",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.commit()
    return srv.id


async def _reset_interval(db: AsyncSession) -> None:
    await db.execute(update(PlatformSettings).values(dhcp_pull_leases_last_run_at=None))
    await db.commit()


async def _row(db: AsyncSession, sid: uuid.UUID) -> DHCPServer:
    db.expire_all()
    return (await db.execute(select(DHCPServer).where(DHCPServer.id == sid))).scalar_one()


@pytest.mark.asyncio
async def test_failed_pull_is_persisted_then_cleared_by_success(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid = await _arm(db_session)
    outcome: dict[str, bool] = {"fail": True}

    async def _pull(db, server, apply=True):  # type: ignore[no-untyped-def]
        if outcome["fail"]:
            raise RuntimeError("Get-DhcpServerv4Lease: access denied")
        server.last_sync_error = None  # what the real success path does
        server.last_sync_error_at = None
        return pl.PullLeasesResult()

    monkeypatch.setattr(pl, "pull_leases_from_server", _pull)

    res = await task._run_pull()
    assert res["status"] == "ran"
    row = await _row(db_session, sid)
    assert row.last_sync_error is not None
    assert "access denied" in row.last_sync_error
    assert row.last_sync_error_at is not None

    outcome["fail"] = False
    await _reset_interval(db_session)
    await task._run_pull()
    row = await _row(db_session, sid)
    assert row.last_sync_error is None
    assert row.last_sync_error_at is None


@pytest.mark.asyncio
async def test_real_successful_pull_clears_a_stored_error(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid = await _arm(db_session)

    class _Driver:
        async def get_leases(self, server):  # type: ignore[no-untyped-def]
            return []

    monkeypatch.setattr(pl, "get_driver", lambda _d: _Driver())
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)
    srv = await _row(db_session, sid)
    srv.last_sync_error = "stale failure"
    await db_session.commit()

    await pl.pull_leases_from_server(db_session, srv, apply=True)
    await db_session.commit()
    row = await _row(db_session, sid)
    assert row.last_sync_error is None
    assert row.last_sync_at is not None


@pytest.mark.asyncio
async def test_api_response_exposes_the_error(db_session: AsyncSession) -> None:
    from app.api.v1.dhcp.servers import ServerResponse

    sid = await _arm(db_session)
    srv = await _row(db_session, sid)
    srv.last_sync_error = "boom"
    await db_session.commit()
    out = ServerResponse.from_model(await _row(db_session, sid))
    assert out.last_sync_error == "boom"


@pytest.mark.asyncio
async def test_caught_lease_read_failure_sets_error_then_good_pull_clears(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The realistic failure: the driver's read raises INSIDE the pull, which
    catches it into ``result.errors`` — no exception reaches the caller."""
    sid = await _arm(db_session)
    state = {"fail": True}

    class _Driver:
        async def get_leases(self, server):  # type: ignore[no-untyped-def]
            if state["fail"]:
                raise RuntimeError("Get-DhcpServerv4Lease: access denied")
            return []

    monkeypatch.setattr(pl, "get_driver", lambda _d: _Driver())
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)

    srv = await _row(db_session, sid)
    result = await pl.pull_leases_from_server(db_session, srv, apply=True)
    await db_session.commit()
    assert result.errors  # caught, not raised
    row = await _row(db_session, sid)
    assert row.last_sync_error is not None
    assert "access denied" in row.last_sync_error
    assert len(row.last_sync_error) <= 2000
    assert row.last_sync_error_at is not None

    state["fail"] = False
    await pl.pull_leases_from_server(db_session, row, apply=True)
    await db_session.commit()
    row = await _row(db_session, sid)
    assert row.last_sync_error is None
    assert row.last_sync_error_at is None


@pytest.mark.asyncio
async def test_partial_failure_flags_and_names_the_failing_part(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scopes read fine but the lease read fails: still failing, and named."""
    sid = await _arm(db_session)

    class _Driver:
        async def get_scopes(self, server):  # type: ignore[no-untyped-def]
            return []

        async def get_leases(self, server):  # type: ignore[no-untyped-def]
            raise RuntimeError("winrm boom")

    monkeypatch.setattr(pl, "get_driver", lambda _d: _Driver())
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)
    srv = await _row(db_session, sid)
    await pl.pull_leases_from_server(db_session, srv, apply=True)
    await db_session.commit()
    row = await _row(db_session, sid)
    assert row.last_sync_error and "get_leases failed" in row.last_sync_error


@pytest.mark.asyncio
async def test_dry_run_does_not_touch_the_error(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid = await _arm(db_session)

    class _Driver:
        async def get_leases(self, server):  # type: ignore[no-untyped-def]
            raise RuntimeError("x")

    monkeypatch.setattr(pl, "get_driver", lambda _d: _Driver())
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)
    srv = await _row(db_session, sid)
    await pl.pull_leases_from_server(db_session, srv, apply=False)
    await db_session.commit()
    assert (await _row(db_session, sid)).last_sync_error is None


@pytest.mark.asyncio
async def test_busy_pull_leaves_the_error_untouched(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A busy result (#2262) did no pull, so it records nothing. Writing the
    row would also wait on the lock the holding pass has on it, which is what
    hung the manual Sync's 409."""
    sid = await _arm(db_session)

    async def _busy(db, server, apply=True):  # type: ignore[no-untyped-def]
        return pl.PullLeasesResult(busy=True)

    monkeypatch.setattr(pl, "_pull_leases_core", _busy)
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)
    srv = await _row(db_session, sid)
    srv.last_sync_error = "earlier failure"
    await db_session.commit()

    srv = await _row(db_session, sid)
    result = await pl.pull_leases_from_server(db_session, srv, apply=True)
    assert result.busy
    await db_session.commit()
    assert (await _row(db_session, sid)).last_sync_error == "earlier failure"
