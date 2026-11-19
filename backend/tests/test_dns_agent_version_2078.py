"""The DNS agent's own version is stored on the server row (#2078).

The agent used to register with a literal date string, and the control plane
seeded the operator's ``notes`` with it and kept no version anywhere else (the
heartbeat's ``agent_version`` was accepted and dropped).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import ServerResponse
from app.models.dns import DNSServer

KEY = "psk-2078"


async def _register(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
    version: str | None,
    agent_id: str | None = None,
) -> dict:
    monkeypatch.setenv("DNS_AGENT_KEY", KEY)
    body: dict = {
        "hostname": name,
        "fingerprint": "fp-2078",
        "driver": "bind9",
        "roles": ["authoritative"],
        "agent_id": agent_id or str(uuid.uuid4()),
        "group_name": f"g-{name}",
    }
    if version is not None:
        body["version"] = version
    resp = await client.post(
        "/api/v1/dns/agents/register", headers={"X-DNS-Agent-Key": KEY}, json=body
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _row(db: AsyncSession, server_id: str) -> DNSServer:
    db.expire_all()
    res = await db.execute(select(DNSServer).where(DNSServer.id == uuid.UUID(server_id)))
    return res.scalar_one()


@pytest.mark.asyncio
async def test_register_stores_the_version_and_leaves_notes_alone(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = await _register(client, monkeypatch, name="ns-2078a", version="2026.10.02-1")
    row = await _row(db_session, data["server_id"])
    assert row.agent_version == "2026.10.02-1"
    assert row.notes == ""
    # An unstamped agent says "dev"; it is stored as sent.
    data = await _register(client, monkeypatch, name="ns-2078d", version="dev")
    assert (await _row(db_session, data["server_id"])).agent_version == "dev"


@pytest.mark.asyncio
async def test_an_old_agent_without_a_version_leaves_it_null(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = await _register(client, monkeypatch, name="ns-2078b", version=None)
    row = await _row(db_session, data["server_id"])
    assert row.agent_version is None
    assert row.notes == ""
    assert ServerResponse.from_model(row).agent_version is None


@pytest.mark.asyncio
async def test_heartbeat_updates_it_and_reregister_keeps_notes_and_version(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent_id = str(uuid.uuid4())
    data = await _register(client, monkeypatch, name="ns-2078c", version="1.0.0", agent_id=agent_id)
    headers = {"Authorization": f"Bearer {data['agent_token']}"}

    row = await _row(db_session, data["server_id"])
    row.notes = "rack 4, owned by net-eng"
    await db_session.commit()

    resp = await client.post(
        "/api/v1/dns/agents/heartbeat", headers=headers, json={"agent_version": "1.1.0"}
    )
    assert resp.status_code == 200, resp.text
    assert (await _row(db_session, data["server_id"])).agent_version == "1.1.0"

    # A heartbeat that omits it (an older agent) does not blank it.
    resp = await client.post("/api/v1/dns/agents/heartbeat", headers=headers, json={})
    assert resp.status_code == 200, resp.text
    assert (await _row(db_session, data["server_id"])).agent_version == "1.1.0"

    # Re-registering an older agent without a version keeps both; with one, updates it.
    await _register(client, monkeypatch, name="ns-2078c", version=None, agent_id=agent_id)
    row = await _row(db_session, data["server_id"])
    assert row.agent_version == "1.1.0"
    assert row.notes == "rack 4, owned by net-eng"
    await _register(client, monkeypatch, name="ns-2078c", version="1.2.0", agent_id=agent_id)
    row = await _row(db_session, data["server_id"])
    assert row.agent_version == "1.2.0"
    assert row.notes == "rack 4, owned by net-eng"


@pytest.mark.asyncio
async def test_the_pre_fix_literal_is_not_stored_as_a_version(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Every DNS agent released before this fix registered with this literal,
    # whatever build it ran; its heartbeat already sent the real stamp.
    agent_id = str(uuid.uuid4())
    data = await _register(
        client, monkeypatch, name="ns-2078e", version="2026.04.14.1", agent_id=agent_id
    )
    assert (await _row(db_session, data["server_id"])).agent_version is None

    headers = {"Authorization": f"Bearer {data['agent_token']}"}
    resp = await client.post(
        "/api/v1/dns/agents/heartbeat", headers=headers, json={"agent_version": "2026.10.02-1"}
    )
    assert resp.status_code == 200, resp.text
    # An old agent re-registering (401/404 recovery) must not put the
    # literal back over the version its heartbeat reported.
    await _register(client, monkeypatch, name="ns-2078e", version="2026.04.14.1", agent_id=agent_id)
    assert (await _row(db_session, data["server_id"])).agent_version == "2026.10.02-1"


@pytest.mark.asyncio
async def test_find_dns_servers_reports_it(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.ai.tools.dns import FindDnsServersArgs, find_dns_servers

    await _register(client, monkeypatch, name="ns-2078f", version="2026.10.02-1")
    await _register(client, monkeypatch, name="ns-2078g", version=None)
    db_session.expire_all()
    rows = await find_dns_servers(db_session, None, FindDnsServersArgs(search="ns-2078"))  # type: ignore[arg-type]
    by_name = {r["name"]: r["agent_version"] for r in rows}
    assert by_name == {"ns-2078f": "2026.10.02-1", "ns-2078g": None}
