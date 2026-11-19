"""DHCPv6 high availability, control-plane side (#1258).

kea-dhcp6 runs its own HA hook on its own HTTP listener, so the control plane
derives a second URL per peer (the v4 port + 1), ships it only once every
member's agent can render it, opens it on the appliance firewall only while the
group serves IPv6, and stores the DHCPv6 daemon's HA state beside the DHCPv4
one. A payload from an agent or control plane that predates any of this must
keep working.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance.supervisor import _build_role_assignment
from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.appliance.firewall import _dhcp_ha_ports, compile_firewall_body
from app.services.dhcp import agent_token as dhcp_tokens
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.ha_members import v6_peer_port, v6_peer_url
from tests.conftest import _TestSessionLocal

CAPS = ["ha_peer_tls", "ha_v6"]


@pytest.mark.parametrize(
    ("url", "derived"),
    [
        ("http://10.0.0.5:8000/", "http://10.0.0.5:8001/"),
        ("http://dhcp-a:8000", "http://dhcp-a:8001"),
        ("http://[2001:db8::5]:8000/", "http://[2001:db8::5]:8001/"),
        ("https://10.0.0.5:8443/x", "https://10.0.0.5:8444/x"),
        ("http://10.0.0.5/", "http://10.0.0.5:81/"),
        ("http://10.0.0.5:65535/", None),
        ("http://10.0.0.5:99999/", None),
        ("dhcp-a:8000", None),
        ("", None),
    ],
)
def test_the_v6_listener_is_the_v4_port_plus_one(url: str, derived: str | None) -> None:
    assert v6_peer_url(url) == derived
    assert v6_peer_port(url) == (int(derived.rsplit(":", 1)[1].split("/")[0]) if derived else None)


async def _pair(
    db: AsyncSession, caps_a: list[str] | None, caps_b: list[str] | None, v6_scope: bool = True
) -> tuple[DHCPServerGroup, DHCPServer, DHCPServer]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", mode="hot-standby")
    db.add(grp)
    await db.flush()
    servers = []
    for label, caps, ip in (("a", caps_a, "10.0.0.1"), ("b", caps_b, "10.0.0.2")):
        srv = DHCPServer(
            name=f"{label}-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host=ip,
            port=67,
            server_group_id=grp.id,
            ha_peer_url=f"http://{ip}:8000/",
            agent_capabilities=caps,
            agent_id=uuid.uuid4(),
            agent_registered=True,
            agent_approved=True,
            agent_fingerprint="fp",
        )
        db.add(srv)
        servers.append(srv)
    if v6_scope:
        space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
        db.add(space)
        await db.flush()
        net = f"2001:db8:{uuid.uuid4().int % 9000 + 1000:x}::/64"
        block = IPBlock(space_id=space.id, network=net, name="b")
        db.add(block)
        await db.flush()
        subnet = Subnet(space_id=space.id, block_id=block.id, network=net, name="s")
        db.add(subnet)
        await db.flush()
        db.add(DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="v6", address_family="ipv6"))
    await db.flush()
    await db.refresh(grp, ["servers"])
    return grp, servers[0], servers[1]


# ── bundle ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bundle_carries_a_v6_url_per_peer_once_every_member_supports_it(
    db_session: AsyncSession,
) -> None:
    _grp, a, b = await _pair(db_session, CAPS, CAPS)
    failover = (await build_config_bundle(db_session, a)).failover
    assert failover is not None
    assert sorted((p["url"], p["url_v6"]) for p in failover.peers) == [
        ("http://10.0.0.1:8000/", "http://10.0.0.1:8001/"),
        ("http://10.0.0.2:8000/", "http://10.0.0.2:8001/"),
    ]
    # The partner's bundle agrees on every peer entry.
    other = (await build_config_bundle(db_session, b)).failover
    assert other is not None and other.peers == failover.peers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("caps_a", "caps_b"),
    [(CAPS, ["ha_peer_tls"]), (CAPS, None), (CAPS, []), (None, None)],
)
async def test_one_older_member_keeps_v6_ha_out_of_the_bundle(
    db_session: AsyncSession, caps_a: list[str] | None, caps_b: list[str] | None
) -> None:
    _grp, a, _b = await _pair(db_session, caps_a, caps_b)
    failover = (await build_config_bundle(db_session, a)).failover
    assert failover is not None
    assert failover.peers
    assert all("url_v6" not in p for p in failover.peers)


@pytest.mark.asyncio
async def test_a_peer_url_with_no_room_for_a_v6_port_keeps_v6_ha_out(
    db_session: AsyncSession,
) -> None:
    _grp, a, b = await _pair(db_session, CAPS, CAPS)
    b.ha_peer_url = "http://10.0.0.2:65535/"
    await db_session.flush()
    failover = (await build_config_bundle(db_session, a)).failover
    assert failover is not None
    assert all("url_v6" not in p for p in failover.peers)


# ── appliance firewall ───────────────────────────────────────────────────────


def _appliance(group_id: uuid.UUID, ip: str) -> Appliance:
    der = os.urandom(32)
    return Appliance(
        id=uuid.uuid4(),
        hostname=f"ap-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        assigned_roles=["dhcp"],
        assigned_dhcp_group_id=group_id,
        node_ips=[ip],
    )


@pytest.mark.asyncio
async def test_firewall_opens_the_v6_listener_only_while_v6_ha_runs(
    db_session: AsyncSession,
) -> None:
    grp, a, _b = await _pair(db_session, CAPS, CAPS)
    me = _appliance(grp.id, "10.0.0.1")
    db_session.add(me)
    await db_session.flush()
    a.appliance_id = me.id
    await db_session.flush()
    ra = await _build_role_assignment(db_session, me)
    assert (ra.dhcp_ha_port, ra.dhcp_ha_v6_port) == (8000, 8001)
    assert ra.dhcp_ha_peer_cidrs == ["10.0.0.2/32"]

    # A member whose agent cannot render it: nothing extra is opened.
    a.agent_capabilities = ["ha_peer_tls"]
    await db_session.flush()
    ra = await _build_role_assignment(db_session, me)
    assert (ra.dhcp_ha_port, ra.dhcp_ha_v6_port) == (8000, None)


@pytest.mark.asyncio
async def test_firewall_opens_no_v6_listener_for_a_group_without_v6_scopes(
    db_session: AsyncSession,
) -> None:
    grp, a, _b = await _pair(db_session, CAPS, CAPS, v6_scope=False)
    me = _appliance(grp.id, "10.0.0.1")
    db_session.add(me)
    await db_session.flush()
    a.appliance_id = me.id
    await db_session.flush()
    ra = await _build_role_assignment(db_session, me)
    assert (ra.dhcp_ha_port, ra.dhcp_ha_v6_port) == (8000, None)


def test_the_renderer_puts_both_ports_in_one_peer_scoped_rule() -> None:
    ra: dict[str, Any] = {
        "roles": ["dhcp"],
        "dhcp_ha_port": 8000,
        "dhcp_ha_v6_port": 8001,
        "dhcp_ha_peer_cidrs": ["10.0.0.2/32"],
    }
    body = compile_firewall_body(ra)
    assert 'ip saddr { 10.0.0.2/32 } tcp dport { 8000, 8001 } accept comment "role:dhcp-ha' in body
    assert all("saddr" in ln for ln in body.splitlines() if "8001" in ln)
    # Without the field the rule is the one #1167 always rendered.
    del ra["dhcp_ha_v6_port"]
    assert "tcp dport 8000 accept" in compile_firewall_body(ra)
    for junk in (None, 0, "x", 8000, 70000):
        assert _dhcp_ha_ports({"dhcp_ha_v6_port": junk}, 8000) == "8000"


# ── reported state ───────────────────────────────────────────────────────────


async def _reporting_member(db: AsyncSession) -> tuple[uuid.UUID, dict[str, str], dict[str, str]]:
    _grp, a, _b = await _pair(db, CAPS, CAPS)
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(a.id), agent_id=str(a.agent_id), fingerprint="fp"
    )
    a.agent_token_hash = dhcp_tokens.hash_token(token)
    admin = User(
        username=f"ha1258-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="HA Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(admin)
    server_id = a.id
    await db.commit()
    return (
        server_id,
        {"Authorization": f"Bearer {token}"},
        {"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
    )


@pytest.fixture
def fresh_session_per_request() -> Any:
    """Each request gets its own session, as in production."""

    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_v4_and_v6_ha_state_are_stored_and_returned_separately(
    db_session: AsyncSession, fresh_session_per_request: None
) -> None:
    sid, agent, admin = await _reporting_member(db_session)
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    r = await client.post(
        "/api/v1/dhcp/agents/ha-status",
        json={"state": "hot-standby", "raw": {}, "state_v6": "partner-down", "raw_v6": {"x": 1}},
        headers=agent,
    )
    assert r.status_code == 200, r.text
    row = (await client.get(f"/api/v1/dhcp/servers/{sid}", headers=admin)).json()
    assert (row["ha_state"], row["ha_state_v6"]) == ("hot-standby", "partner-down")
    # The group roll-up the DHCP page reads carries both too.
    groups = (await client.get("/api/v1/dhcp/server-groups", headers=admin)).json()
    member = next(s for g in groups for s in g["servers"] if s["id"] == str(sid))
    assert (member["ha_state"], member["ha_state_v6"]) == ("hot-standby", "partner-down")


@pytest.mark.asyncio
async def test_an_agent_that_predates_v6_ha_still_reports(
    db_session: AsyncSession, fresh_session_per_request: None
) -> None:
    """The old payload carries no v6 keys; it must be accepted and read as no v6 state."""
    sid, agent, admin = await _reporting_member(db_session)
    (await db_session.get(DHCPServer, sid)).ha_state_v6 = "normal"  # type: ignore[union-attr]
    await db_session.commit()
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    r = await client.post(
        "/api/v1/dhcp/agents/ha-status",
        json={"state": "normal", "raw": {}},
        headers=agent,
    )
    assert r.status_code == 200, r.text
    row = (await client.get(f"/api/v1/dhcp/servers/{sid}", headers=admin)).json()
    assert row["ha_state"] == "normal"
    assert row["ha_state_v6"] is None
