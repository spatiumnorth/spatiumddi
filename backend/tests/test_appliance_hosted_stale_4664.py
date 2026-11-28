"""#4664 — DNS / DHCP server rows hosted on an appliance agent node go
``unreachable`` once their agent stops heartbeating, exactly like a
standalone agent's. Nothing the appliance's supervisor does (heartbeat,
role-health verdicts, Fleet rollup) may vouch for the row's liveness."""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup
from app.tasks import dhcp_health
from app.tasks import dns as dns_tasks
from tests.test_dhcp_container_oom_2023 import (
    _appliance,
    _kea_server,
    _role_health,
    _supervisor_hb,
)


class _Eng:
    async def dispose(self) -> None:
        return None


async def test_appliance_hosted_rows_flip_unreachable_when_agent_silent(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    now = datetime.now(UTC)
    appliance, token = await _appliance(db_session, "ddi-gone-1")
    silent = now - timedelta(minutes=10)
    kea, _h = await _kea_server(
        db_session, host="ddi-gone-1", appliance_id=appliance.id, last_seen_at=silent
    )
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add(group)
    await db_session.flush()
    dns = DNSServer(
        group_id=group.id,
        name="gone-dns",
        driver="bind9",
        host="ddi-gone-1",
        port=53,
        status="active",
        agent_id=uuid.uuid4(),
        appliance_id=appliance.id,
        last_seen_at=silent,
    )
    db_session.add(dns)
    await db_session.commit()

    # The appliance's supervisor is alive and reporting healthy role pods.
    await _supervisor_hb(
        client,
        appliance,
        token,
        _role_health(killed_at=now - timedelta(days=1), running_since=now - timedelta(days=1)),
    )

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dhcp_health, "create_async_engine", lambda *a, **kw: _Eng())
    monkeypatch.setattr(dhcp_health, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _Eng())
    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    await dhcp_health._check_health(kea.id)
    await dns_tasks._dns_agent_stale_sweep_async()

    db_session.expunge_all()
    kea2 = await db_session.get(DHCPServer, kea.id)
    dns2 = await db_session.get(DNSServer, dns.id)
    assert kea2 is not None and dns2 is not None
    assert kea2.status == "unreachable"
    assert dns2.status == "unreachable"
