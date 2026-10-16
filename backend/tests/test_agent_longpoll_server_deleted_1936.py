"""#1936 — a server row deleted under an open agent long-poll.

``DELETE .../servers/{id}`` wakes the server's channel and removes the row; the
poll wakes and refreshes a row that is gone. That used to surface as an
unhandled 500 (``Could not refresh instance``). It must answer what an unknown
agent is answered at the start of a request: 404, which makes the agent
re-bootstrap from its PSK.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents as dhcp_agents
from app.api.v1.dns import agents as dns_agents
from app.core import agent_wake
from app.models.dhcp import DHCPServer
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_token import mint_agent_token as dns_mint


def _delete_row_on_wake(
    monkeypatch: pytest.MonkeyPatch, db: AsyncSession, model: Any, server_id: uuid.UUID
) -> None:
    """Make the poll's first wait delete the server row (as the DELETE route
    would from another request), without leaving the instance detached from the
    poll's session, which is what a separate api request looks like."""

    async def _wait(self: Any, timeout: float) -> Any:
        await db.execute(
            delete(model).where(model.id == server_id),
            execution_options={"synchronize_session": False},
        )
        await db.commit()
        return agent_wake.WakeResult.WAKE

    monkeypatch.setattr(agent_wake.WakeSubscription, "wait", _wait)


@pytest.mark.asyncio
async def test_dns_longpoll_answers_404_when_its_server_row_is_deleted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dns_agents, "LONGPOLL_TIMEOUT_SECONDS", 20)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    db_session.add(server)
    await db_session.flush()
    token, _ = dns_mint(str(server.id), str(server.agent_id), "fp")
    headers = {"Authorization": f"Bearer {token}"}
    sid = server.id
    await db_session.commit()

    first = await client.get("/api/v1/dns/agents/config", headers=headers)
    assert first.status_code == 200, first.text
    headers["If-None-Match"] = first.headers["etag"]

    _delete_row_on_wake(monkeypatch, db_session, DNSServer, sid)
    resp = await client.get("/api/v1/dns/agents/config", headers=headers)
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_dhcp_longpoll_answers_404_when_its_server_row_is_deleted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dhcp_agents, "LONGPOLL_TIMEOUT_SECONDS", 20)
    server = DHCPServer(
        name=f"k-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="10.0.0.2",
        agent_id=uuid.uuid4(),
        agent_approved=True,
    )
    db_session.add(server)
    await db_session.flush()
    token, _ = dhcp_agents.mint_agent_token(
        server_id=str(server.id), agent_id=str(server.agent_id), fingerprint="fp"
    )
    headers = {"Authorization": f"Bearer {token}"}
    sid = server.id
    await db_session.commit()

    first = await client.get("/api/v1/dhcp/agents/config", headers=headers)
    assert first.status_code == 200, first.text
    headers["If-None-Match"] = first.headers["etag"]

    _delete_row_on_wake(monkeypatch, db_session, DHCPServer, sid)
    resp = await client.get("/api/v1/dhcp/agents/config", headers=headers)
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_refresh_error_on_a_row_that_still_exists_is_not_a_404(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a row that is really gone is a 404. Any other refresh error is a
    bug of ours and must stay one, whatever its message says."""
    from fastapi import HTTPException
    from sqlalchemy.exc import InvalidRequestError

    from app.services.agents.server_gone import refresh_agent_server

    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    server = DNSServer(group_id=grp.id, driver="bind9", host="10.0.0.3", name="still-here")
    db_session.add(server)
    await db_session.flush()

    async def _boom(*_a: Any, **_k: Any) -> None:
        raise InvalidRequestError("Could not refresh instance (but the row is there)")

    monkeypatch.setattr(db_session, "refresh", _boom)
    with pytest.raises(InvalidRequestError):
        await refresh_agent_server(db_session, server)
    monkeypatch.undo()

    await db_session.execute(
        delete(DNSServer).where(DNSServer.id == server.id),
        execution_options={"synchronize_session": False},
    )
    with pytest.raises(HTTPException) as exc_info:
        await refresh_agent_server(db_session, server)
    assert exc_info.value.status_code == 404
