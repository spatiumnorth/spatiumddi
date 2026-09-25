"""The appliance firewall opens the Kea HA listener to the pair (#1167).

A DHCP group with two or more Kea members renders ``libdhcp_ha.so`` with a
dedicated HTTP listener on the port in each member's own ``ha_peer_url``. The
appliance ``input`` chain is ``policy drop`` and nothing opened that port, so
two appliances in one HA group could not reach each other. The control plane
now derives the port and the other members' addresses and the renderers open
exactly that — never ``any``, since Kea's HA API is unauthenticated by
default and accepts lease updates.
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance.supervisor import _build_role_assignment
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.appliance.firewall import _dhcp_ha_rule
from app.services.dhcp.ha_firewall import dhcp_ha_firewall_inputs, listener_port


def _appliance(hostname: str, *, group_id: uuid.UUID | None, node_ips: list[str]) -> Appliance:
    der = os.urandom(32)
    return Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        assigned_roles=["dhcp"],
        assigned_dhcp_group_id=group_id,
        node_ips=node_ips,
    )


def _kea(
    group: DHCPServerGroup, host: str, url: str, last_seen_ip: str | None = None
) -> DHCPServer:
    return DHCPServer(
        name=host,
        driver="kea",
        host=host,
        port=67,
        server_group_id=group.id,
        ha_peer_url=url,
        last_seen_ip=last_seen_ip,
    )


async def _group(db: AsyncSession) -> DHCPServerGroup:
    grp = DHCPServerGroup(name=f"ha-{uuid.uuid4().hex[:6]}", description="", mode="hot-standby")
    db.add(grp)
    await db.flush()
    return grp


@pytest.mark.parametrize(
    ("url", "port"),
    [
        ("http://10.0.0.5:8000/", 8000),
        ("http://dhcp-a:8000", 8000),
        ("http://[2001:db8::5]:8001/", 8001),
        ("http://10.0.0.5/", 80),
        ("https://10.0.0.5/", 443),
        ("http://10.0.0.5:99999/", None),
        ("dhcp-a:8000", None),  # no scheme — not a URL Kea accepts either
        ("", None),
    ],
)
def test_listener_port(url: str, port: int | None) -> None:
    assert listener_port(url) == port


@pytest.mark.asyncio
async def test_the_pair_opens_to_every_other_member_by_their_best_address(
    db_session: AsyncSession,
) -> None:
    grp = await _group(db_session)
    me = _appliance("dhcp-a", group_id=grp.id, node_ips=["192.168.0.11"])
    partner = _appliance("dhcp-b", group_id=grp.id, node_ips=["192.168.0.12", "2001:db8::12"])
    db_session.add_all([me, partner])
    db_session.add_all(
        [
            _kea(grp, "dhcp-a", "http://192.168.0.11:8000/"),
            # A hostname URL: the address comes from the partner's appliance.
            _kea(grp, "dhcp-b", "http://dhcp-b:8000/"),
            # A 3rd member plays ``backup`` and still receives lease updates.
            # No appliance and a hostname URL: its agent's last address.
            _kea(grp, "dhcp-c", "http://dhcp-c:8000/", last_seen_ip="192.168.0.13"),
        ]
    )
    await db_session.flush()

    port, peers = await dhcp_ha_firewall_inputs(db_session, me)
    assert port == 8000
    assert peers == ["192.168.0.12/32", "192.168.0.13/32", "2001:db8::12/128"]

    # And it reaches the heartbeat's role assignment.
    ra = await _build_role_assignment(db_session, me)
    assert (ra.dhcp_ha_port, ra.dhcp_ha_peer_cidrs) == (port, peers)


@pytest.mark.asyncio
async def test_an_ip_literal_url_wins_over_the_appliance(db_session: AsyncSession) -> None:
    grp = await _group(db_session)
    me = _appliance("dhcp-a", group_id=grp.id, node_ips=[])
    partner = _appliance("dhcp-b", group_id=grp.id, node_ips=["192.168.0.99"])
    db_session.add_all([me, partner])
    db_session.add_all(
        [
            _kea(grp, "dhcp-a", "http://192.168.0.11:8000/"),
            _kea(grp, "dhcp-b", "http://192.168.0.12:8000/"),
        ]
    )
    await db_session.flush()
    assert await dhcp_ha_firewall_inputs(db_session, me) == (8000, ["192.168.0.12/32"])


@pytest.mark.asyncio
async def test_nothing_opens_outside_a_rendered_ha_group(db_session: AsyncSession) -> None:
    """Exactly when ``_resolve_failover`` renders the HA hook, and not
    otherwise — a port open with no listener, or to a group Kea is not
    pairing, is exposure for nothing."""
    grp = await _group(db_session)
    me = _appliance("dhcp-a", group_id=grp.id, node_ips=[])
    db_session.add(me)
    db_session.add(_kea(grp, "dhcp-a", "http://192.168.0.11:8000/"))
    await db_session.flush()
    assert await dhcp_ha_firewall_inputs(db_session, me) == (None, []), "one member"

    b = _kea(grp, "dhcp-b", "")
    db_session.add(b)
    await db_session.flush()
    await db_session.refresh(grp, ["servers"])
    assert await dhcp_ha_firewall_inputs(db_session, me) == (None, []), "a member without a URL"

    b.ha_peer_url = "http://192.168.0.12:8000/"
    await db_session.flush()
    await db_session.refresh(grp, ["servers"])
    stranger = _appliance("not-a-member", group_id=grp.id, node_ips=[])
    db_session.add(stranger)
    await db_session.flush()
    assert await dhcp_ha_firewall_inputs(db_session, stranger) == (None, []), "not a member"

    me.assigned_roles = ["dns-bind9"]
    assert await dhcp_ha_firewall_inputs(db_session, me) == (None, []), "no dhcp role"


# ── The rule the renderers emit ────────────────────────────────────────────


def test_the_rule_is_peer_scoped_and_needs_the_dhcp_role() -> None:
    ra = {"dhcp_ha_port": 8000, "dhcp_ha_peer_cidrs": ["192.168.0.12/32", "2001:db8::12/128"]}
    assert _dhcp_ha_rule(ra, ["dhcp"]) == (8000, ["192.168.0.12/32"], ["2001:db8::12/128"])
    # A stale value on a re-roled node must not keep the port open.
    assert _dhcp_ha_rule(ra, ["dns-bind9"]) is None
    assert _dhcp_ha_rule({**ra, "dhcp_ha_port": None}, ["dhcp"]) is None
    assert _dhcp_ha_rule({**ra, "dhcp_ha_port": 0}, ["dhcp"]) is None
    # No valid peer: nothing, never an unscoped accept.
    assert _dhcp_ha_rule({**ra, "dhcp_ha_peer_cidrs": []}, ["dhcp"]) is None
    injected = ["1.2.3.4 }, drop; tcp dport 22 accept; #"]
    assert _dhcp_ha_rule({**ra, "dhcp_ha_peer_cidrs": injected}, ["dhcp"]) is None
