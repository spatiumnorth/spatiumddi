"""#2262 — overlapping agentless lease pulls duplicated a lease and wedged the
server's pull.

The scheduled pull stamped its interval only at the END of a pass and took no
lock, so a pull slower than the 10 s beat tick ran again on every tick, and the
manual ``sync-leases`` raced it too. Both passes saw a new lease as absent and
both inserted it; from then on ``scalar_one_or_none()`` raised
``MultipleResultsFound`` for that address and the server's whole pull aborted
on every tick, leaving leases and IPAM mirrors stale.

Covered here: the pull recovers from a duplicate that already exists; two
pulls of one server at once write one row; the manual sync answers 409 while
another pull holds the server; concurrent beat ticks run one pass; the
migration dedupes by lease identity, keeping the newest row; and a Kea
lease-event batch that loses an insert race on the new identity index answers
503 (which the agent retries) rather than 409 (which it drops).
"""

from __future__ import annotations

import asyncio
import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings
from tests.conftest import _TestSessionLocal

_TIMEOUT = 15


class _StubDriver:
    def __init__(self, leases: list[dict]) -> None:
        self._leases = leases

    async def get_leases(self, _server: DHCPServer) -> list[dict]:
        return self._leases


def _patch(monkeypatch: pytest.MonkeyPatch, leases: list[dict]) -> None:
    from app.services.dhcp import pull_leases as pl

    monkeypatch.setattr(pl, "get_driver", lambda _drv: _StubDriver(leases))


async def _server(db: AsyncSession) -> DHCPServer:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="windows_dhcp",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.flush()
    return srv


async def _rows(db: AsyncSession, server_id: uuid.UUID, ip: str) -> list[DHCPLease]:
    return list(
        (
            await db.execute(
                select(DHCPLease).where(
                    DHCPLease.server_id == server_id, DHCPLease.ip_address == ip
                )
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_pull_recovers_from_an_existing_duplicate(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two rows already on one address: the pull keeps one, at the wire's MAC,
    instead of raising on every tick."""
    from app.services.dhcp import pull_leases as pl

    srv = await _server(db_session)
    old = datetime.now(UTC) - timedelta(hours=2)
    for mac, seen in (("aa:bb:cc:dd:ee:01", old), ("aa:bb:cc:dd:ee:02", old + timedelta(hours=1))):
        db_session.add(
            DHCPLease(
                server_id=srv.id,
                ip_address="10.9.0.50",
                mac_address=mac,
                state="active",
                last_seen_at=seen,
            )
        )
    await db_session.commit()

    _patch(
        monkeypatch,
        [{"ip_address": "10.9.0.50", "mac_address": "aa:bb:cc:dd:ee:03", "hostname": "h"}],
    )
    result = await pl.pull_leases_from_server(db_session, srv, apply=True)
    await db_session.commit()

    assert result.errors == []
    rows = await _rows(db_session, srv.id, "10.9.0.50")
    assert len(rows) == 1
    assert str(rows[0].mac_address) == "aa:bb:cc:dd:ee:03"
    assert rows[0].state == "active"

    # And the next tick is an ordinary refresh, not another failure.
    again = await pl.pull_leases_from_server(db_session, srv, apply=True)
    await db_session.commit()
    assert again.errors == []
    assert again.refreshed == 1
    assert len(await _rows(db_session, srv.id, "10.9.0.50")) == 1


@pytest.mark.asyncio
async def test_two_pulls_of_one_server_write_one_lease_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second pull while the first is still in its transaction does nothing;
    both commit and the new lease exists once."""
    from app.services.dhcp import pull_leases as pl

    srv = await _server(db_session)
    await db_session.commit()
    _patch(monkeypatch, [{"ip_address": "10.9.0.60", "mac_address": "aa:bb:cc:dd:ee:60"}])

    async with _TestSessionLocal() as a, _TestSessionLocal() as b:
        srv_a = await a.get(DHCPServer, srv.id)
        srv_b = await b.get(DHCPServer, srv.id)
        assert srv_a is not None and srv_b is not None
        await asyncio.wait_for(pl.pull_leases_from_server(a, srv_a, apply=True), _TIMEOUT)
        # A has not committed: B must not insert the same lease alongside it.
        await asyncio.wait_for(pl.pull_leases_from_server(b, srv_b, apply=True), _TIMEOUT)
        await b.commit()
        await a.commit()

        # The lock went with A's commit: the next pull refreshes normally.
        third = await asyncio.wait_for(pl.pull_leases_from_server(b, srv_b, apply=True), _TIMEOUT)
        await b.commit()
        assert third.refreshed == 1

    assert len(await _rows(db_session, srv.id, "10.9.0.60")) == 1


async def _superadmin(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_manual_sync_answers_409_while_a_pull_holds_the_server(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.dhcp import pull_leases as pl

    token = await _superadmin(db_session)
    srv = await _server(db_session)
    await db_session.commit()
    _patch(monkeypatch, [{"ip_address": "10.9.0.70", "mac_address": "aa:bb:cc:dd:ee:70"}])

    async with _TestSessionLocal() as other:
        # The scheduled pull, mid-pass on this server.
        srv_other = await other.get(DHCPServer, srv.id)
        assert srv_other is not None
        await pl.pull_leases_from_server(other, srv_other, apply=True)

        r = await asyncio.wait_for(
            client.post(
                f"/api/v1/dhcp/servers/{srv.id}/sync-leases",
                headers={"Authorization": f"Bearer {token}"},
            ),
            _TIMEOUT,
        )
        assert r.status_code == 409, r.text
        await other.commit()

    assert len(await _rows(db_session, srv.id, "10.9.0.70")) == 1


@pytest.mark.asyncio
async def test_concurrent_beat_ticks_run_one_pass(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two ticks that both find the interval elapsed: only one pulls."""
    from app.services.dhcp import pull_leases as pl
    from app.tasks import dhcp_pull_leases as task

    await _server(db_session)
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dhcp_pull_leases_enabled = True
    ps.dhcp_pull_leases_interval_seconds = 15
    ps.dhcp_pull_leases_last_run_at = None
    await db_session.commit()

    calls = 0

    async def _slow_pull(_db, _server, *, apply=True):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.5)
        return pl.PullLeasesResult()

    monkeypatch.setattr(pl, "pull_leases_from_server", _slow_pull)

    results = await asyncio.wait_for(asyncio.gather(task._run_pull(), task._run_pull()), _TIMEOUT)

    assert calls == 1, results
    assert sorted(r["status"] for r in results) == ["ran", "skipped"]


def _dedupe_sql():  # type: ignore[no-untyped-def]
    path = (
        Path(__file__).parent.parent / "alembic/versions/e4b8c2d17a95_dhcp_lease_identity_unique.py"
    )
    spec = importlib.util.spec_from_file_location("mig_2262", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.DEDUPE_LEASES_SQL


@pytest.mark.asyncio
async def test_migration_dedupes_by_lease_identity_keeping_the_newest(
    db_session: AsyncSession,
) -> None:
    """Duplicates of one identity collapse to the newest row; leases of
    different clients on one address (the Kea replay case, #1318) survive."""
    # The model now carries the unique indexes the migration creates; drop them
    # inside this transaction to stage the pre-migration state. Rolled back.
    await db_session.execute(text("DROP INDEX uq_dhcp_lease_server_ip_mac"))
    await db_session.execute(text("DROP INDEX uq_dhcp_lease_server_ip_duid"))
    srv = await _server(db_session)
    base = datetime.now(UTC) - timedelta(days=1)

    def lease(ip: str, *, mac: str | None = None, duid: str | None = None, iaid=None, age=0):  # type: ignore[no-untyped-def]
        row = DHCPLease(
            server_id=srv.id,
            ip_address=ip,
            mac_address=mac,
            duid=duid,
            iaid=iaid,
            state="active",
            last_seen_at=base + timedelta(minutes=age),
        )
        db_session.add(row)
        return row

    v4_old = lease("10.9.1.1", mac="aa:bb:cc:00:00:01", age=0)
    v4_new = lease("10.9.1.1", mac="aa:bb:cc:00:00:01", age=5)
    other_client = lease("10.9.1.1", mac="aa:bb:cc:00:00:02", age=1)
    duid = "00:01:00:01:aa:bb:cc:dd:ee:ff:00:11"
    v6_old = lease("2001:db8::10", duid=duid, iaid=None, age=0)
    v6_new = lease("2001:db8::10", duid=duid, iaid=None, age=9)
    v6_other_iaid = lease("2001:db8::10", duid=duid, iaid=7, age=2)
    await db_session.flush()
    kept = {v4_new.id, other_client.id, v6_new.id, v6_other_iaid.id}
    gone = {v4_old.id, v6_old.id}

    await db_session.execute(_dedupe_sql())
    remaining = set(
        (
            await db_session.execute(select(DHCPLease.id).where(DHCPLease.server_id == srv.id))
        ).scalars()
    )
    assert remaining == kept
    assert not remaining & gone

    # The indexes build on what is left.
    await db_session.execute(
        text(
            "CREATE UNIQUE INDEX uq_dhcp_lease_server_ip_mac ON dhcp_lease "
            "(server_id, ip_address, mac_address) WHERE duid IS NULL"
        )
    )
    await db_session.execute(
        text(
            "CREATE UNIQUE INDEX uq_dhcp_lease_server_ip_duid ON dhcp_lease "
            "(server_id, ip_address, duid, iaid) NULLS NOT DISTINCT WHERE duid IS NOT NULL"
        )
    )
    count = (
        await db_session.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.server_id == srv.id)
        )
    ).scalar_one()
    assert count == 4
    await db_session.rollback()


@pytest.mark.asyncio
async def test_kea_lease_event_identity_race_answers_503_and_converges_on_retry(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Kea lease-event path does select-then-insert too, so the new
    identity index can fire there when another request inserts the same lease
    between the two. The global handler would answer 409, which the agent's
    spool classifies as REJECTED and drops the whole batch. It must answer 503
    (RETRY) instead, with the receipt rolled back, so the retry lands."""
    from app.api.v1.dhcp import agents
    from app.main import app
    from app.models.agent_ingest import AgentIngestReceipt

    grp = DHCPServerGroup(name=f"k-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    srv = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        status="active",
        server_group_id=grp.id,
    )
    db_session.add(srv)
    await db_session.flush()
    sid = srv.id
    await db_session.commit()

    now = datetime.now(UTC)
    ev = {
        "ip_address": "10.73.1.5",
        "mac_address": "aa:bb:cc:73:00:05",
        "hostname": "first",
        "state": "active",
        "starts_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    far = int((now + timedelta(days=30)).timestamp())

    async def post(body: dict):  # type: ignore[no-untyped-def]
        # Re-read per request: the test client shares this session, and the
        # handler's rollback on the race expires the instance.
        server = await db_session.get(DHCPServer, sid)
        app.dependency_overrides[agents._auth_agent] = lambda: (server, {"exp": far})
        try:
            return await client.post("/api/v1/dhcp/agents/lease-events", json=body)
        finally:
            app.dependency_overrides.pop(agents._auth_agent, None)

    r = await post({"leases": [ev], "batch_id": uuid.uuid4().hex})
    assert r.status_code == 200, r.text

    # Stage the race: the handler's SELECT "misses" the committed row, exactly
    # as it would when another request committed it after the SELECT ran.
    real_identity = agents._lease_identity
    calls = iter(range(10_000))
    monkeypatch.setattr(agents, "_lease_identity", lambda *a: (*real_identity(*a), next(calls)))
    raced = {"leases": [{**ev, "hostname": "second"}], "batch_id": uuid.uuid4().hex}
    r = await post(raced)
    assert r.status_code == 503, r.text
    assert r.headers.get("retry-after") == "1"
    receipts = await db_session.scalar(
        select(func.count())
        .select_from(AgentIngestReceipt)
        .where(AgentIngestReceipt.batch_id == raced["batch_id"])
    )
    assert receipts == 0  # rolled back with the batch, so the retry is not a "duplicate"

    # The agent retries the same batch; it now finds the row and updates it.
    monkeypatch.setattr(agents, "_lease_identity", real_identity)
    r = await post(raced)
    assert r.status_code == 200, r.text
    assert r.json()["duplicate"] is False
    db_session.expire_all()
    rows = await _rows(db_session, sid, "10.73.1.5")
    assert len(rows) == 1
    assert rows[0].hostname == "second"
