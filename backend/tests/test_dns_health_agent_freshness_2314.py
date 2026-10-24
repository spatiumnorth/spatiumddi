"""The DNS health task judges an agent by its heartbeat, not its own stamp (#2314).

``last_health_check_at`` is written by the health task itself every 60 s, so
using it as "the agent is alive" let an active server renew its own
freshness forever and never reach the probe. Only ``last_seen_at`` is written
by the agent. These tests drive the real ``_check_health`` against the test
session and assert on the stored status.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup
from app.tasks import dns as dns_tasks


class _NullEngine:
    async def dispose(self) -> None:
        return None


def _wire(monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, soa_ok: bool) -> list[str]:
    probes: list[str] = []

    async def _probe(host: str, port: int) -> bool:
        probes.append(host)
        return soa_ok

    @contextlib.asynccontextmanager
    async def _factory_cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())
    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _factory_cm)
    monkeypatch.setattr(dns_tasks, "_probe_server_soa", _probe)
    return probes


async def _server(db: AsyncSession, **kw: object) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db.add(group)
    await db.flush()
    srv = DNSServer(
        group_id=group.id,
        name=f"s-{uuid.uuid4().hex[:8]}",
        driver="bind9",
        host="192.0.2.53",
        port=53,
        **kw,
    )
    db.add(srv)
    await db.flush()
    return srv


@pytest.mark.asyncio
async def test_stale_heartbeat_is_unreachable_even_when_named_answers(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    srv = await _server(
        db_session,
        status="active",
        last_seen_at=now - timedelta(minutes=10),
        # The task's own previous stamp is fresh: it must not count.
        last_health_check_at=now - timedelta(seconds=30),
    )
    probes = _wire(monkeypatch, db_session, soa_ok=True)

    await dns_tasks._check_health(srv.id)

    await db_session.refresh(srv)
    assert srv.status == "unreachable"
    assert probes == []


@pytest.mark.asyncio
async def test_fresh_heartbeat_is_active(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _server(
        db_session, status="unreachable", last_seen_at=datetime.now(UTC) - timedelta(seconds=20)
    )
    _wire(monkeypatch, db_session, soa_ok=False)

    await dns_tasks._check_health(srv.id)

    await db_session.refresh(srv)
    assert srv.status == "active"


@pytest.mark.asyncio
@pytest.mark.parametrize("soa_ok,expected", [(True, "active"), (False, "unreachable")])
async def test_never_seen_agent_falls_back_to_probe(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, soa_ok: bool, expected: str
) -> None:
    srv = await _server(db_session, status="active", last_seen_at=None)
    probes = _wire(monkeypatch, db_session, soa_ok=soa_ok)

    await dns_tasks._check_health(srv.id)

    await db_session.refresh(srv)
    assert srv.status == expected
    assert probes == ["192.0.2.53"]


@pytest.mark.asyncio
async def test_paused_server_is_left_alone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    srv = await _server(
        db_session,
        status="active",
        maintenance_mode=True,
        last_seen_at=datetime.now(UTC) - timedelta(hours=2),
    )
    probes = _wire(monkeypatch, db_session, soa_ok=False)

    await dns_tasks._check_health(srv.id)

    await db_session.refresh(srv)
    assert srv.status == "active"
    assert srv.last_health_check_at is not None
    assert probes == []
