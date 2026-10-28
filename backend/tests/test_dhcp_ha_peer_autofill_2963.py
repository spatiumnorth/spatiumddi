"""An appliance-hosted Kea HA pair no longer needs ha_peer_url by hand (#2963)."""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.appliance.dhcp_group_move import move_appliance_dhcp_servers
from app.services.dhcp.ha_peer_autofill import (
    appliance_ha_address,
    autofill_group_ha_peer_urls,
)


def _appliance(db: AsyncSession, ips: list[str], node_ip: str | None = None) -> Appliance:
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        assigned_roles=["dhcp"],
        node_ips=ips,
        node_ip=node_ip,
    )
    db.add(a)
    return a


def _kea(
    db: AsyncSession, group: DHCPServerGroup, ap: Appliance | None, url: str = ""
) -> DHCPServer:
    s = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host=ap.hostname if ap else "10.9.9.9",
        port=67,
        server_group_id=group.id,
        agent_id=uuid.uuid4(),
        appliance_id=ap.id if ap else None,
        ha_peer_url=url,
    )
    db.add(s)
    return s


async def _group(db: AsyncSession, mode: str = "host") -> DHCPServerGroup:
    g = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="", network_mode=mode)
    db.add(g)
    await db.flush()
    return g


def test_address_prefers_ipv4_then_v6_then_node_ip() -> None:
    a = Appliance(node_ips=["fd00::5", "10.0.0.5"], node_ip=None)
    assert appliance_ha_address(a) == "10.0.0.5"
    assert appliance_ha_address(Appliance(node_ips=["fd00::5"], node_ip=None)) == "[fd00::5]"
    assert appliance_ha_address(Appliance(node_ips=[], node_ip="10.1.1.1")) == "10.1.1.1"
    assert appliance_ha_address(Appliance(node_ips=["junk"], node_ip=None)) is None


@pytest.mark.asyncio
async def test_pair_gets_urls_from_node_addresses(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1, s2 = _kea(db_session, g, a1), _kea(db_session, g, a2)
    await db_session.flush()
    res = await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert len(res.filled) == 2
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == "http://10.0.0.6:8000/"


@pytest.mark.asyncio
async def test_operator_set_url_is_never_overwritten(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1 = _kea(db_session, g, a1, url="http://203.0.113.7:9000/")
    s2 = _kea(db_session, g, a2)
    await db_session.flush()
    await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert s1.ha_peer_url == "http://203.0.113.7:9000/"
    assert s2.ha_peer_url == "http://10.0.0.6:8000/"


@pytest.mark.asyncio
async def test_bridged_group_is_left_manual(db_session: AsyncSession) -> None:
    g = await _group(db_session, "bridged")
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1, s2 = _kea(db_session, g, a1), _kea(db_session, g, a2)
    await db_session.flush()
    res = await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert res.filled == [] and s1.ha_peer_url == "" and s2.ha_peer_url == ""


@pytest.mark.asyncio
async def test_lone_member_and_non_appliance_member_untouched(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    a1 = _appliance(db_session, ["10.0.0.5"])
    await db_session.flush()
    s1 = _kea(db_session, g, a1)
    await db_session.flush()
    assert (await autofill_group_ha_peer_urls(db_session, g.id, via="t")).filled == []
    assert s1.ha_peer_url == ""
    s2 = _kea(db_session, g, None)  # compose agent: no appliance
    await db_session.flush()
    await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == ""


@pytest.mark.asyncio
async def test_role_assignment_move_fills_urls(db_session: AsyncSession) -> None:
    from app.models.auth import User

    g = await _group(db_session)
    old = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1 = _kea(db_session, g, a1)
    s2 = _kea(db_session, old, a2)
    await db_session.flush()
    user = User(username="u2963", email="u@x.com", display_name="T", is_superadmin=True)
    await move_appliance_dhcp_servers(db_session, a2, g, user)
    assert s2.server_group_id == g.id
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == "http://10.0.0.6:8000/"


@pytest.mark.asyncio
async def test_group_reports_members_missing_a_peer_url(db_session: AsyncSession) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.api.v1.dhcp.server_groups import _group_to_response

    g = await _group(db_session)
    s1 = _kea(db_session, g, None, url="http://10.9.9.1:8000/")
    s2 = _kea(db_session, g, None)
    await db_session.commit()
    g2 = (
        await db_session.execute(
            select(DHCPServerGroup)
            .where(DHCPServerGroup.id == g.id)
            .options(selectinload(DHCPServerGroup.servers))
        )
    ).scalar_one()
    assert _group_to_response(g2).ha_peer_urls_missing == [s2.name]
    assert s1.name not in _group_to_response(g2).ha_peer_urls_missing
