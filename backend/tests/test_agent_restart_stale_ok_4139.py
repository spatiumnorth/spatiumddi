"""#4139 — a restarted agent no longer reads its predecessor's ``ok``.

The server row kept the previous process's ``config_apply_status=ok`` (and
``daemon_status=ok``) until the new process's first heartbeat, up to a
heartbeat interval later, even when the restart then failed to apply. A new
agent process is recognised by its ``X-Spatium-Agent-Instance`` on the first
config poll; that claim now retires the stale ``ok`` to NULL (unknown), and the
new process's own report sets the real state.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.services.agents import instance_ownership
from app.services.agents.config_apply import apply_reported_status
from app.services.dhcp.agent_token import hash_token
from app.services.dhcp.agent_token import mint_agent_token as mint_dhcp_token
from app.services.dns import agent_instance
from app.services.dns.agent_token import mint_agent_token as mint_dns_token

OK_REPORT = {"status": "ok", "etag": "abc"}
FAILED_REPORT = {"status": "reverted", "error": "zone x cannot load", "failed_etag": "def"}


async def _dns_server(db: AsyncSession) -> DNSServer:
    grp = DNSServerGroup(name=f"g4139-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        agent_id=uuid.uuid4(),
    )
    db.add(server)
    await db.flush()
    return server


def _settled_ok(server: DNSServer | DHCPServer, instance: str) -> None:
    server.agent_instance = instance
    server.agent_instance_seen_at = datetime.now(UTC) - timedelta(minutes=1)
    server.config_apply_status = "ok"
    server.config_apply_at = datetime.now(UTC) - timedelta(minutes=1)
    server.daemon_status = "ok"
    server.daemon_status_since = datetime.now(UTC) - timedelta(hours=1)


@pytest.mark.asyncio
async def test_dns_restart_forgets_ok_until_the_new_process_reports(
    db_session: AsyncSession,
) -> None:
    server = await _dns_server(db_session)
    _settled_ok(server, "old-process")
    await db_session.commit()

    assert await agent_instance.claim_poll(db_session, server, "new-process") is True
    assert server.config_apply_status is None
    assert server.config_apply_at is None
    assert server.daemon_status is None

    apply_reported_status(server, OK_REPORT, agent_kind="dns", server_id=str(server.id))
    assert server.config_apply_status == "ok"


@pytest.mark.asyncio
async def test_dns_restart_that_fails_to_apply_reads_failed_not_ok(
    db_session: AsyncSession,
) -> None:
    server = await _dns_server(db_session)
    _settled_ok(server, "old-process")
    await db_session.commit()

    await agent_instance.claim_poll(db_session, server, "new-process")
    assert server.config_apply_status != "ok"
    apply_reported_status(server, FAILED_REPORT, agent_kind="dns", server_id=str(server.id))
    assert server.config_apply_status == "reverted"
    assert server.config_apply_error == "zone x cannot load"


@pytest.mark.asyncio
async def test_same_process_polling_again_keeps_its_ok(db_session: AsyncSession) -> None:
    server = await _dns_server(db_session)
    _settled_ok(server, "same-process")
    await db_session.commit()

    assert await agent_instance.claim_poll(db_session, server, "same-process") is True
    assert server.config_apply_status == "ok"
    assert server.daemon_status == "ok"


@pytest.mark.asyncio
async def test_a_failure_verdict_survives_a_restart_until_replaced(
    db_session: AsyncSession,
) -> None:
    server = await _dns_server(db_session)
    _settled_ok(server, "old-process")
    server.config_apply_status = "reverted"
    server.config_apply_error = "boom"
    await db_session.commit()

    await agent_instance.claim_poll(db_session, server, "new-process")
    assert server.config_apply_status == "reverted"
    assert server.config_apply_error == "boom"


@pytest.mark.asyncio
async def test_dhcp_restart_forgets_ok_until_the_new_process_reports(
    db_session: AsyncSession,
) -> None:
    grp = DHCPServerGroup(name=f"g4139-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    server = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="10.0.0.1",
        port=67,
        server_group_id=grp.id,
        agent_id=uuid.uuid4(),
        agent_registered=True,
        agent_approved=True,
        agent_fingerprint="fp",
    )
    db_session.add(server)
    await db_session.flush()
    _settled_ok(server, "old-process")
    await db_session.commit()

    assert await instance_ownership.claim_poll(db_session, server, "new-process", kind="dhcp")
    assert server.config_apply_status is None
    assert server.daemon_status is None
    apply_reported_status(server, FAILED_REPORT, agent_kind="dhcp", server_id=str(server.id))
    assert server.config_apply_status == "reverted"


# ── the announce heartbeat: the takeover happens BEFORE the boot apply ──────
#
# The agents send one heartbeat naming the new process before their boot apply
# (1.4 s to a minute). The takeover used to be the first config poll, which
# comes after the boot apply, so the old ``ok`` stood through all of it.

INSTANCE = "X-Spatium-Agent-Instance"
DNS_HEARTBEAT = "/api/v1/dns/agents/heartbeat"
DHCP_HEARTBEAT = "/api/v1/dhcp/agents/heartbeat"


async def _reload[M: (DNSServer, DHCPServer)](db: AsyncSession, model: type[M], pk: uuid.UUID) -> M:
    return (
        await db.execute(
            select(model).where(model.id == pk).execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _dhcp_server(db: AsyncSession) -> tuple[DHCPServer, dict[str, str]]:
    grp = DHCPServerGroup(name=f"g4139-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="10.0.0.1",
        port=67,
        server_group_id=grp.id,
        agent_id=uuid.uuid4(),
        agent_registered=True,
        agent_approved=True,
        agent_fingerprint="fp",
    )
    db.add(server)
    await db.flush()
    token, _exp = mint_dhcp_token(str(server.id), str(server.agent_id), "fp")
    server.agent_token_hash = hash_token(token)
    return server, {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_dns_announce_heartbeat_clears_the_stale_ok_before_any_poll(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server = await _dns_server(db_session)
    _settled_ok(server, "old-process")
    token, _exp = mint_dns_token(str(server.id), str(server.agent_id), "fp")
    headers = {"Authorization": f"Bearer {token}", INSTANCE: "new-process"}
    await db_session.commit()
    sid = server.id

    # What the agent sends before its boot apply: an empty config block.
    resp = await client.post(DNS_HEARTBEAT, headers=headers, json={"config": {}, "daemon": {}})
    assert resp.status_code == 200, resp.text
    srv = await _reload(db_session, DNSServer, sid)
    assert srv.agent_instance == "new-process"
    assert srv.config_apply_status is None
    assert srv.daemon_status is None

    # The boot apply fails: the row reads the failure, never the old ok.
    resp = await client.post(
        DNS_HEARTBEAT,
        headers=headers,
        json={"config": FAILED_REPORT, "daemon": {"status": "degraded", "reason": "x"}},
    )
    assert resp.status_code == 200, resp.text
    srv = await _reload(db_session, DNSServer, sid)
    assert srv.config_apply_status == "reverted"
    assert srv.config_apply_error == "zone x cannot load"

    # And a good boot apply returns the row to ok.
    resp = await client.post(
        DNS_HEARTBEAT, headers=headers, json={"config": OK_REPORT, "daemon": {"status": "ok"}}
    )
    assert resp.status_code == 200, resp.text
    assert (await _reload(db_session, DNSServer, sid)).config_apply_status == "ok"


@pytest.mark.asyncio
async def test_dns_heartbeat_without_an_instance_id_keeps_the_ok(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An older agent names no process: today's behaviour, nothing cleared."""
    server = await _dns_server(db_session)
    _settled_ok(server, "old-process")
    token, _exp = mint_dns_token(str(server.id), str(server.agent_id), "fp")
    await db_session.commit()
    sid = server.id

    resp = await client.post(
        DNS_HEARTBEAT, headers={"Authorization": f"Bearer {token}"}, json={"config": {}}
    )
    assert resp.status_code == 200, resp.text
    srv = await _reload(db_session, DNSServer, sid)
    assert srv.agent_instance == "old-process"
    assert srv.config_apply_status == "ok"


@pytest.mark.asyncio
async def test_dhcp_announce_heartbeat_clears_the_stale_ok_before_any_poll(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _dhcp_server(db_session)
    _settled_ok(server, "old-process")
    await db_session.commit()
    sid = server.id
    headers = {**headers, INSTANCE: "new-process"}

    resp = await client.post(DHCP_HEARTBEAT, headers=headers, json={"config": {}, "daemon": {}})
    assert resp.status_code == 200, resp.text
    srv = await _reload(db_session, DHCPServer, sid)
    assert srv.agent_instance == "new-process"
    assert srv.config_apply_status is None
    assert srv.daemon_status is None

    # The cache boot now reports ok (the agent change), so the row returns to ok.
    resp = await client.post(
        DHCP_HEARTBEAT, headers=headers, json={"config": OK_REPORT, "daemon": {"status": "ok"}}
    )
    assert resp.status_code == 200, resp.text
    assert (await _reload(db_session, DHCPServer, sid)).config_apply_status == "ok"


@pytest.mark.asyncio
async def test_dhcp_boot_apply_failure_reads_failed_not_ok(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _dhcp_server(db_session)
    _settled_ok(server, "old-process")
    await db_session.commit()
    sid = server.id
    headers = {**headers, INSTANCE: "new-process"}

    await client.post(DHCP_HEARTBEAT, headers=headers, json={"config": {}})
    resp = await client.post(DHCP_HEARTBEAT, headers=headers, json={"config": FAILED_REPORT})
    assert resp.status_code == 200, resp.text
    srv = await _reload(db_session, DHCPServer, sid)
    assert srv.config_apply_status == "reverted"
