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
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.services.agents import instance_ownership
from app.services.agents.config_apply import apply_reported_status
from app.services.dns import agent_instance

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
