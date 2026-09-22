"""``POST /api/v1/dns/groups/{gid}/servers/{sid}/approve`` — the way back in
for a DNS agent held ``pending_approval`` (spatiumddi#1121).

With ``DNS_REQUIRE_AGENT_APPROVAL=true`` the register path holds a
re-registering agent whose fingerprint changed: its config long-poll answers
``{"pending_approval": true, "etag": null}`` and never a bundle, so ``named``
stays deferred. Before this endpoint nothing cleared the flag —
``ServerUpdate`` carries no approval field, and the DHCP side has had
``POST /dhcp/servers/{id}/approve`` all along — so the only recovery was a
database write or delete-and-re-register.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_token import hash_token, mint_agent_token

CONFIG_URL = "/api/v1/dns/agents/config"
APPROVE_TEMPLATE = "/api/v1/dns/groups/{group_id}/servers/{server_id}/approve"
REKEYED = "fp-after-the-wipe"


def _approve_url(group_id: uuid.UUID, server_id: uuid.UUID) -> str:
    return APPROVE_TEMPLATE.format(group_id=group_id, server_id=server_id)


async def _user(db: AsyncSession, *, superadmin: bool) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Approver" if superadmin else "Viewer",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _held_agent(db: AsyncSession) -> tuple[DNSServer, dict[str, str]]:
    """A registered agent the anti-hijack gate has held: ``pending_approval``
    set and the row carrying the fingerprint it re-registered with, exactly as
    ``agent_register`` leaves it."""
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
        agent_fingerprint=REKEYED,
        pending_approval=True,
    )
    db.add(server)
    await db.flush()
    token, _exp = mint_agent_token(str(server.id), str(server.agent_id), REKEYED)
    server.agent_jwt_hash = hash_token(token)
    await db.flush()
    return server, {"Authorization": f"Bearer {token}"}


async def _approve_events(db: AsyncSession, server: DNSServer) -> list[AuditLog]:
    rows = await db.execute(
        select(AuditLog)
        .where(AuditLog.action == "dns.server.approve", AuditLog.resource_id == str(server.id))
        .order_by(AuditLog.timestamp)
    )
    return list(rows.scalars().all())


@pytest.mark.asyncio
async def test_approve_readmits_a_held_agent(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    server, agent = await _held_agent(db_session)
    admin, headers = await _user(db_session, superadmin=True)
    await db_session.commit()

    # The lockout the gate produces: no bundle, ever, while the row is held.
    held = await client.get(CONFIG_URL, headers=agent)
    assert held.status_code == 200, held.text
    assert held.json() == {"pending_approval": True, "etag": None}
    assert held.headers.get("x-spatium-pending-approval") == "1"

    resp = await client.post(_approve_url(server.group_id, server.id), headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == str(server.id)
    assert body["pending_approval"] is False

    await db_session.refresh(server)
    assert server.pending_approval is False
    # Approving accepts the identity the agent re-registered with, as-is.
    assert server.agent_fingerprint == REKEYED

    events = await _approve_events(db_session, server)
    assert len(events) == 1
    event = events[0]
    assert event.user_id == admin.id
    assert event.resource_type == "dns_server"
    assert event.resource_display == server.name
    assert event.old_value == {"pending_approval": True}
    assert event.new_value == {"pending_approval": False}
    assert event.result == "success"

    # And the agent's next poll serves the bundle.
    back = await client.get(CONFIG_URL, headers=agent)
    assert back.status_code == 200, back.text
    assert "x-spatium-pending-approval" not in back.headers
    assert back.json()["etag"].startswith("sha256:")
    assert back.headers["etag"]


@pytest.mark.asyncio
async def test_approve_is_idempotent_and_audits_every_call(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Mirrors the DHCP twin: a second approve is a 200 with the row, not an
    error, and each operator action leaves its own audit event."""
    server, _agent = await _held_agent(db_session)
    _admin, headers = await _user(db_session, superadmin=True)
    await db_session.commit()

    url = _approve_url(server.group_id, server.id)
    first = await client.post(url, headers=headers)
    second = await client.post(url, headers=headers)
    assert (first.status_code, second.status_code) == (200, 200), (first.text, second.text)
    assert second.json()["pending_approval"] is False

    events = await _approve_events(db_session, server)
    assert [e.old_value for e in events] == [
        {"pending_approval": True},
        {"pending_approval": False},
    ]


@pytest.mark.asyncio
async def test_approve_is_superadmin_only(client: AsyncClient, db_session: AsyncSession) -> None:
    server, _agent = await _held_agent(db_session)
    _viewer, headers = await _user(db_session, superadmin=False)
    await db_session.commit()

    resp = await client.post(_approve_url(server.group_id, server.id), headers=headers)
    assert resp.status_code == 403, resp.text
    await db_session.refresh(server)
    assert server.pending_approval is True
    assert await _approve_events(db_session, server) == []


@pytest.mark.asyncio
async def test_approve_404s_outside_the_servers_group_and_for_a_missing_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _agent = await _held_agent(db_session)
    _admin, headers = await _user(db_session, superadmin=True)
    other = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(other)
    await db_session.flush()
    await db_session.commit()

    wrong_group = await client.post(_approve_url(other.id, server.id), headers=headers)
    assert wrong_group.status_code == 404, wrong_group.text
    missing = await client.post(_approve_url(server.group_id, uuid.uuid4()), headers=headers)
    assert missing.status_code == 404, missing.text
    await db_session.refresh(server)
    assert server.pending_approval is True


def test_the_route_is_in_the_openapi_document() -> None:
    """The issue was confirmed live from ``GET /api/openapi.json`` — four
    ``approve`` paths, none under ``/api/v1/dns/``. This pins the fifth."""
    paths = app.openapi()["paths"]
    assert APPROVE_TEMPLATE in paths
    assert "post" in paths[APPROVE_TEMPLATE]
