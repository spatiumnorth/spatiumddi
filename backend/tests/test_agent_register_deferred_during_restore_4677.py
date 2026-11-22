"""An agent register during a restore is deferred, not judged (#4677).

The replay puts the archive's server rows back before the running appliance's
identity is carried over, so a register then compares the agent's fingerprint
with the archive's and un-approves the server. Both register handlers answer
503 + Retry-After while the install-wide restore lock is held; the agents
retry any non-200 register with a backoff, without a strike.
"""

from __future__ import annotations

import uuid

import asyncpg
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer
from app.services.backup.restore import _RESTORE_LOCK_KEY

_CASES = [
    ("/api/v1/dhcp/agents/register", "X-DHCP-Agent-Key", "DHCP_AGENT_KEY", "kea", DHCPServer),
    ("/api/v1/dns/agents/register", "X-DNS-Agent-Key", "DNS_AGENT_KEY", "bind9", DNSServer),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("path", "header", "env", "driver", "model"), _CASES)
async def test_register_is_deferred_while_a_restore_runs(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    header: str,
    env: str,
    driver: str,
    model,
) -> None:
    monkeypatch.setenv(env, "k4677")
    body = {
        "hostname": "node1",
        "driver": driver,
        "fingerprint": "fp",
        "agent_id": str(uuid.uuid4()),
        "version": "0.0.0-test",
        "group_name": "g",
    }
    lock = await asyncpg.connect(str(settings.database_url).replace("+asyncpg", "", 1))
    try:
        await lock.fetchval("SELECT pg_advisory_lock($1)", _RESTORE_LOCK_KEY)
        r = await client.post(path, headers={header: "k4677"}, json=body)
    finally:
        await lock.close()
    assert r.status_code == 503, r.text
    assert r.headers["Retry-After"] == "1"
    assert (await db_session.execute(select(model))).first() is None

    ok = await client.post(path, headers={header: "k4677"}, json=body)
    assert ok.status_code == 200, ok.text
