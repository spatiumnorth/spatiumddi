"""A disabled DNS server stays ``disabled`` through its agent's heartbeat (#2853).

The heartbeat wrote ``status = "active"`` on every check-in whatever
``is_enabled`` said, so a disabled server flipped back to active until the
health task wrote ``disabled`` again, and its zone's sync verdict counted it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerZoneState, DNSZone
from app.services.dns import agent_token as dns_tokens

SERIAL = 2026102601


async def _server(db: AsyncSession, grp: DNSServerGroup, name: str, **kw: Any) -> DNSServer:
    srv = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host=f"10.1.0.{len(name)}",
        name=name,
        agent_id=uuid.uuid4(),
        agent_fingerprint="fp",
        **kw,
    )
    db.add(srv)
    await db.flush()
    return srv


def _auth(srv: DNSServer) -> dict[str, str]:
    token, _ = dns_tokens.mint_agent_token(str(srv.id), str(srv.agent_id), "fp")
    srv.agent_jwt_hash = dns_tokens.hash_token(token)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_heartbeat_keeps_disabled_then_reenable_returns_active(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = DNSServerGroup(name=f"g2853-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    old = datetime.now(UTC) - timedelta(hours=1)
    srv = await _server(
        db_session, grp, "ns-off", is_enabled=False, status="disabled", last_seen_at=old
    )
    headers = _auth(srv)
    await db_session.commit()

    r = await client.post("/api/v1/dns/agents/heartbeat", headers=headers, json={})
    assert r.status_code == 200, r.text
    await db_session.refresh(srv)
    assert srv.status == "disabled"
    assert srv.last_seen_at is not None and srv.last_seen_at > old

    srv.is_enabled = True
    await db_session.commit()
    r = await client.post("/api/v1/dns/agents/heartbeat", headers=headers, json={})
    assert r.status_code == 200, r.text
    await db_session.refresh(srv)
    assert srv.status == "active"


@pytest.mark.asyncio
async def test_zone_server_state_excludes_disabled_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user = User(
        username=f"u2853-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    grp = DNSServerGroup(name=f"g2853z-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="example.com.",
        zone_type="primary",
        kind="forward",
        last_serial=SERIAL,
    )
    db_session.add(zone)
    on = await _server(db_session, grp, "ns-on", status="active")
    off = await _server(db_session, grp, "ns-off", is_enabled=False, status="disabled")
    await db_session.flush()
    # The disabled server never caught up; the enabled one is current.
    db_session.add(
        DNSServerZoneState(
            server_id=on.id, zone_id=zone.id, current_serial=SERIAL, reported_at=datetime.now(UTC)
        )
    )
    db_session.add(
        DNSServerZoneState(
            server_id=off.id, zone_id=zone.id, current_serial=1, reported_at=datetime.now(UTC)
        )
    )
    await db_session.commit()

    r = await client.get(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/server-state",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    by = {s["server_name"]: s for s in body["servers"]}
    assert by["ns-off"]["freshness"] == "disabled"
    assert by["ns-off"]["counted"] is False
    assert body["in_sync"] is True
