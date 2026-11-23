"""#4808 — the DNS health check, DNS pool check, DNS server sync and cloud
reconcile must not hold a DB transaction (or the pool row lock) across their
network calls, and must drop a result for a row that went away meanwhile."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.drivers.dns.base import RecordData
from app.models.audit import AuditLog
from app.models.cloud import CloudEndpoint
from app.models.dns import DNSPool, DNSPoolMember, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPSpace
from app.models.settings import PlatformSettings
from app.services.cloud import reconcile as reconcile_mod
from app.services.cloud.base import CloudInventory
from app.services.dns import pull_from_server as pfs
from app.services.dns.pool_healthcheck import CheckResult
from app.tasks import dns as dns_tasks
from app.tasks import dns_pool_healthcheck, dns_pull
from tests.conftest import _TestSessionLocal
from tests.test_dns_sync_serial_3004 import _Driver, _serve, _zone


class _FakeEngine:
    async def dispose(self) -> None:
        return None


def _install(monkeypatch: pytest.MonkeyPatch, module: Any) -> list[AsyncSession]:
    """Point ``module``'s per-task engine at the test DB, recording every session."""
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


# ── DNS server health check ─────────────────────────────────────────────────


async def _dns_server(db: AsyncSession) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    srv = DNSServer(
        group_id=group.id,
        name="ns1",
        driver="windows_dns",
        host="192.0.2.1",
        port=53,
        is_enabled=True,
        is_primary=True,
    )
    db.add(srv)
    await db.commit()
    return srv


@pytest.mark.asyncio
async def test_dns_health_probe_runs_with_no_open_transaction(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _dns_server(db_session)
    srv_id = srv.id
    sessions = _install(monkeypatch, dns_tasks)
    seen: list[bool] = []

    class _Drv:
        async def health_check(self, server: Any) -> tuple[bool, str]:
            seen.append(_any_open_txn(sessions))
            return False, "down"

    monkeypatch.setattr("app.drivers.dns.get_driver", lambda _n: _Drv())
    await dns_tasks._check_health(srv_id)
    assert seen == [False]
    db_session.expire_all()
    row = await db_session.get(DNSServer, srv_id)
    assert row is not None and row.status == "unreachable" and row.last_health_check_at


@pytest.mark.asyncio
async def test_dns_health_result_dropped_when_server_deleted_mid_probe(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _dns_server(db_session)
    srv_id = srv.id
    _install(monkeypatch, dns_tasks)

    class _Drv:
        async def health_check(self, server: Any) -> tuple[bool, str]:
            async with _TestSessionLocal() as other:
                await other.delete(await other.get(DNSServer, srv_id))
                await other.commit()
            return True, "ok"

    monkeypatch.setattr("app.drivers.dns.get_driver", lambda _n: _Drv())
    await dns_tasks._check_health(srv_id)  # must not raise
    db_session.expire_all()
    assert await db_session.get(DNSServer, srv_id) is None


# ── DNS pool health check ───────────────────────────────────────────────────


async def _pool(db: AsyncSession) -> tuple[DNSPool, uuid.UUID]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    zone = DNSZone(
        group_id=group.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
    )
    db.add(zone)
    await db.flush()
    pool = DNSPool(
        group_id=group.id,
        zone_id=zone.id,
        name="p",
        record_name="p",
        record_type="A",
        ttl=30,
        enabled=True,
        hc_type="tcp",
        hc_target_port=80,
    )
    db.add(pool)
    await db.flush()
    db.add(DNSPoolMember(pool_id=pool.id, address="192.0.2.10", enabled=True))
    await db.commit()
    return pool, pool.id


@pytest.mark.asyncio
async def test_pool_probe_runs_with_no_open_transaction_and_no_row_lock(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pool_row, pool_id = await _pool(db_session)
    sessions = _install(monkeypatch, dns_pool_healthcheck)
    seen: list[tuple[bool, bool]] = []

    async def fake_check(pool: Any, member: Any) -> Any:
        # A writer to the pool row must not wait: SKIP LOCKED sees it free.
        async with _TestSessionLocal() as other:
            free = (
                await other.execute(
                    select(DNSPool.id)
                    .where(DNSPool.id == pool_id)
                    .with_for_update(skip_locked=True)
                )
            ).scalar_one_or_none()
        seen.append((_any_open_txn(sessions), free is None))
        return CheckResult(healthy=True, error=None)

    monkeypatch.setattr(dns_pool_healthcheck, "run_check", fake_check)
    out = await dns_pool_healthcheck._run_pool_check_async(str(pool_id))
    assert out["status"] == "ok" and out["members_checked"] == 1
    assert seen == [(False, False)]
    db_session.expire_all()
    member = (
        await db_session.execute(select(DNSPoolMember).where(DNSPoolMember.pool_id == pool_id))
    ).scalar_one()
    assert member.last_check_state == "healthy"


@pytest.mark.asyncio
async def test_pool_result_dropped_when_pool_deleted_mid_probe(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pool_row, pool_id = await _pool(db_session)
    _install(monkeypatch, dns_pool_healthcheck)

    async def fake_check(pool: Any, member: Any) -> Any:
        async with _TestSessionLocal() as other:
            # Before the fix the task still holds the row lock here; fail
            # fast instead of waiting on it forever.
            await other.execute(text("SET LOCAL lock_timeout = '2s'"))
            await other.delete(await other.get(DNSPool, pool_id))
            await other.commit()
        return CheckResult(healthy=True, error=None)

    monkeypatch.setattr(dns_pool_healthcheck, "run_check", fake_check)
    out = await dns_pool_healthcheck._run_pool_check_async(str(pool_id))
    assert out == {"status": "skipped", "reason": "changed_during_check"}


@pytest.mark.asyncio
async def test_pool_second_run_skips_while_another_holds_the_lock(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The advisory lock replaces the row lock as the single-flight guard."""
    _pool_row, pool_id = await _pool(db_session)
    _install(monkeypatch, dns_pool_healthcheck)

    async def must_not_probe(pool: Any, member: Any) -> Any:
        raise AssertionError("a run holding no lock must not probe")

    monkeypatch.setattr(dns_pool_healthcheck, "run_check", must_not_probe)
    async with _TestSessionLocal() as holder:
        await holder.scalar(
            text("SELECT pg_advisory_lock(:ns, hashtext(:pid))"),
            {"ns": dns_pool_healthcheck._POOL_CHECK_LOCK_NS, "pid": str(pool_id)},
        )
        try:
            out = await dns_pool_healthcheck._run_pool_check_async(str(pool_id))
        finally:
            await holder.execute(text("SELECT pg_advisory_unlock_all()"))
            await holder.commit()
    assert out == {"status": "skipped", "reason": "locked_or_deleted"}


# ── cloud reconcile ─────────────────────────────────────────────────────────


async def _endpoint(db: AsyncSession) -> CloudEndpoint:
    space = IPSpace(name=f"cloud-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    ep = CloudEndpoint(
        name=f"cloud-{uuid.uuid4().hex[:6]}",
        provider="aws",
        credentials_encrypted=encrypt_dict({"access_key_id": "x", "secret_access_key": "y"}),
        provider_config={},
        regions=["us-east-1"],
        ipam_space_id=space.id,
    )
    db.add(ep)
    await db.commit()
    return ep


@pytest.mark.asyncio
async def test_cloud_fetch_runs_with_no_open_transaction(db_session: AsyncSession) -> None:
    ep = await _endpoint(db_session)
    seen: list[bool] = []

    class _Conn:
        async def fetch_inventory(self, **kw: Any) -> CloudInventory:
            seen.append(db_session.in_transaction())
            return CloudInventory(account_id="1", networks=[], subnets=[], instances=[])

    with patch.object(reconcile_mod, "get_connector", return_value=_Conn()):
        summary = await reconcile_mod.reconcile_endpoint(db_session, ep)
    assert seen == [False]
    assert summary.ok, summary.error


@pytest.mark.asyncio
async def test_cloud_result_dropped_when_endpoint_deleted_mid_fetch(
    db_session: AsyncSession,
) -> None:
    ep = await _endpoint(db_session)
    ep_id = ep.id

    class _Conn:
        async def fetch_inventory(self, **kw: Any) -> CloudInventory:
            async with _TestSessionLocal() as other:
                await other.delete(await other.get(CloudEndpoint, ep_id))
                await other.commit()
            return CloudInventory(account_id="1", networks=[], subnets=[], instances=[])

    with patch.object(reconcile_mod, "get_connector", return_value=_Conn()):
        summary = await reconcile_mod.reconcile_endpoint(db_session, ep)
    assert summary.ok is False
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "cloud.reconcile", AuditLog.resource_id == str(ep_id)
                )
            )
        )
        .scalars()
        .all()
    )
    assert audit == []


@pytest.mark.asyncio
async def test_cloud_manual_sync_of_disabled_endpoint_still_applies(
    db_session: AsyncSession,
) -> None:
    """ "Sync now" is allowed on a disabled endpoint; the post-fetch re-read must
    only drop a row that was switched off DURING the pull."""
    ep = await _endpoint(db_session)
    ep.enabled = False
    await db_session.commit()

    class _Conn:
        async def fetch_inventory(self, **kw: Any) -> CloudInventory:
            return CloudInventory(account_id="1", networks=[], subnets=[], instances=[])

    with patch.object(reconcile_mod, "get_connector", return_value=_Conn()):
        summary = await reconcile_mod.reconcile_endpoint(db_session, ep)
    assert summary.ok, summary.error


@pytest.mark.asyncio
async def test_cloud_enabled_endpoint_disabled_mid_fetch_is_dropped(
    db_session: AsyncSession,
) -> None:
    ep = await _endpoint(db_session)
    ep_id = ep.id

    class _Conn:
        async def fetch_inventory(self, **kw: Any) -> CloudInventory:
            async with _TestSessionLocal() as other:
                row = await other.get(CloudEndpoint, ep_id)
                assert row is not None
                row.enabled = False
                await other.commit()
            return CloudInventory(account_id="1", networks=[], subnets=[], instances=[])

    with patch.object(reconcile_mod, "get_connector", return_value=_Conn()):
        summary = await reconcile_mod.reconcile_endpoint(db_session, ep)
    assert summary.ok is False


# ── scheduled DNS server sync ───────────────────────────────────────────────


async def _enable_sync(db: AsyncSession) -> None:
    db.add(
        PlatformSettings(
            id=1,
            dns_pull_from_server_enabled=True,
            dns_pull_from_server_interval_minutes=1,
            dns_pull_from_server_last_run_at=None,
        )
    )
    await db.commit()


@pytest.mark.asyncio
async def test_dns_pull_transfer_runs_with_no_open_transaction(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, _servers = await _zone(db_session, "bind9")
    await _enable_sync(db_session)
    driver = _Driver()
    _serve(monkeypatch, driver, [])
    monkeypatch.setattr(dns_pull, "get_driver", lambda name: driver)
    sessions = _install(monkeypatch, dns_pull)
    seen: list[bool] = []

    async def _pull(drv: Any, server: Any, zone_name: str, keys: Any, **kw: Any) -> Any:
        seen.append(_any_open_txn(sessions))
        return [RecordData(name="www", record_type="A", value="192.0.2.5", ttl=300)], None

    monkeypatch.setattr(pfs, "pull_zone_records_signed", _pull)
    out = await dns_pull._run_sync()
    assert out["status"] == "ran" and out["zones_scanned"] == 1 and out["errors"] == 0
    assert seen == [False]


@pytest.mark.asyncio
async def test_dns_pull_zone_deleted_mid_transfer_is_skipped(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, _servers = await _zone(db_session, "bind9")
    zone_id = zone.id
    await _enable_sync(db_session)
    driver = _Driver()
    _serve(monkeypatch, driver, [])
    monkeypatch.setattr(dns_pull, "get_driver", lambda name: driver)
    _install(monkeypatch, dns_pull)

    async def _pull(drv: Any, server: Any, zone_name: str, keys: Any, **kw: Any) -> Any:
        async with _TestSessionLocal() as other:
            await other.delete(await other.get(DNSZone, zone_id))
            await other.commit()
        # A record the zone would have imported; it must not be written.
        return [RecordData(name="new", record_type="A", value="192.0.2.99", ttl=300)], None

    monkeypatch.setattr(pfs, "pull_zone_records_signed", _pull)
    out = await dns_pull._run_sync()
    assert out["status"] == "ran"
    assert (out["imported"], out["pushed"], out["errors"]) == (0, 0, 0)
