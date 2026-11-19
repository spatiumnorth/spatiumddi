"""A third, URL-less Kea member no longer turns HA off for a working pair (#3151).

#2963 deliberately leaves a third appliance member's ``ha_peer_url`` empty
(roles follow server-id order, so a joiner could take ``primary`` from the live
pair). The bundle used to render no HA hook while ANY Kea member lacked a URL,
so the third member's arrival switched HA off for the pair too and left three
members serving the same pools with no lease sync.

Now the pair keeps its HA hook, the URL-less member is sidelined (no hook, no
scopes, so nothing serves the group's pools uncoordinated), and the group API
says so. One- and two-member groups are unchanged.
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.dhcp.server_groups import _group_to_response
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.ha_firewall import dhcp_ha_firewall_inputs


async def _group(db: AsyncSession, mode: str = "hot-standby") -> DHCPServerGroup:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="", mode=mode)
    db.add(grp)
    await db.flush()
    return grp


async def _kea(db: AsyncSession, grp: DHCPServerGroup, host: str, url: str) -> DHCPServer:
    s = DHCPServer(
        name=host,
        driver="kea",
        host=host,
        port=67,
        server_group_id=grp.id,
        ha_peer_url=url,
    )
    db.add(s)
    await db.flush()
    return s


async def _scope_with_pool(db: AsyncSession, grp: DHCPServerGroup) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.81.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.81.1.0/24", name="n")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    db.add(
        DHCPPool(
            scope_id=scope.id, start_ip="10.81.1.100", end_ip="10.81.1.200", pool_type="dynamic"
        )
    )
    await db.flush()


async def _trio(db: AsyncSession) -> tuple[DHCPServerGroup, list[DHCPServer], DHCPServer]:
    """A hot-standby pair with URLs, plus a third Kea member without one."""
    grp = await _group(db)
    pair = [
        await _kea(db, grp, "dhcp-a", "http://10.0.0.11:8000/"),
        await _kea(db, grp, "dhcp-b", "http://10.0.0.12:8000/"),
    ]
    third = await _kea(db, grp, "dhcp-c", "")
    await _scope_with_pool(db, grp)
    return grp, pair, third


@pytest.mark.asyncio
async def test_pair_keeps_ha_and_the_third_member_is_sidelined(db_session: AsyncSession) -> None:
    _grp, pair, third = await _trio(db_session)
    pair_names = {s.name for s in pair}

    for member in pair:
        bundle = await build_config_bundle(db_session, member)
        assert bundle.failover is not None, f"{member.name} lost its HA hook"
        assert {p["name"] for p in bundle.failover.peers} == pair_names
        assert sorted(p["role"] for p in bundle.failover.peers) == ["primary", "standby"]
        assert bundle.failover.this_server_name == member.name
        # The pair still serves the group's scopes.
        assert [s.subnet_cidr for s in bundle.scopes] == ["10.81.1.0/24"]
        assert bundle.scopes[0].pools

    sidelined = await build_config_bundle(db_session, third)
    assert sidelined.failover is None
    # No scopes, so no pool to hand out beside the pair with no lease sync.
    assert sidelined.scopes == ()
    assert sidelined.ra_configs == ()


@pytest.mark.asyncio
async def test_two_member_groups_are_unchanged(db_session: AsyncSession) -> None:
    # Both URLs: a pair, both serving.
    grp = await _group(db_session)
    a = await _kea(db_session, grp, "dhcp-a", "http://10.0.0.11:8000/")
    b = await _kea(db_session, grp, "dhcp-b", "http://10.0.0.12:8000/")
    await _scope_with_pool(db_session, grp)
    for m in (a, b):
        bundle = await build_config_bundle(db_session, m)
        assert bundle.failover is not None
        assert {p["name"] for p in bundle.failover.peers} == {a.name, b.name}
        assert len(bundle.scopes) == 1

    # One URL missing: no HA, and both still render the scopes, as before.
    b.ha_peer_url = ""
    await db_session.flush()
    await db_session.refresh(grp, ["servers"])
    for m in (a, b):
        bundle = await build_config_bundle(db_session, m)
        assert bundle.failover is None
        assert len(bundle.scopes) == 1


@pytest.mark.asyncio
async def test_three_members_with_urls_still_render_a_backup(db_session: AsyncSession) -> None:
    grp, pair, third = await _trio(db_session)
    third.ha_peer_url = "http://10.0.0.13:8000/"
    await db_session.flush()
    bundle = await build_config_bundle(db_session, third)
    assert bundle.failover is not None
    assert sorted(p["role"] for p in bundle.failover.peers) == ["backup", "primary", "standby"]
    assert len(bundle.scopes) == 1


@pytest.mark.asyncio
async def test_losing_a_pair_member_falls_back_to_no_ha(db_session: AsyncSession) -> None:
    """A pair member leaving leaves one URL — no HA renders, so nothing is
    sidelined: the group is a two-member group without a full set of URLs,
    reported as such (``ha_peer_urls_missing``), exactly as before."""
    grp, pair, third = await _trio(db_session)
    pair[1].server_group_id = None
    await db_session.flush()
    await db_session.refresh(grp, ["servers"])
    for m in (pair[0], third):
        bundle = await build_config_bundle(db_session, m)
        assert bundle.failover is None
        assert len(bundle.scopes) == 1


@pytest.mark.asyncio
async def test_group_api_reports_the_sidelined_member(db_session: AsyncSession) -> None:
    grp, _pair, third = await _trio(db_session)
    gid, third_name = grp.id, third.name
    await db_session.commit()
    g = (
        await db_session.execute(
            select(DHCPServerGroup)
            .where(DHCPServerGroup.id == gid)
            .options(selectinload(DHCPServerGroup.servers))
        )
    ).scalar_one()
    resp = _group_to_response(g)
    assert resp.kea_member_count == 3
    assert resp.ha_peer_urls_missing == [third_name]
    assert resp.ha_sidelined_members == [third_name]

    # Without a running pair there is nothing to sideline.
    for s in g.servers:
        s.ha_peer_url = ""
    assert _group_to_response(g).ha_sidelined_members == []


@pytest.mark.asyncio
async def test_firewall_opens_the_pair_to_each_other_only(db_session: AsyncSession) -> None:
    grp, _pair, _third = await _trio(db_session)

    def ap(host: str, ip: str) -> Appliance:
        der = os.urandom(32)
        return Appliance(
            id=uuid.uuid4(),
            hostname=host,
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            assigned_roles=["dhcp"],
            assigned_dhcp_group_id=grp.id,
            node_ips=[ip],
        )

    a, c = ap("dhcp-a", "10.0.0.11"), ap("dhcp-c", "10.0.0.13")
    db_session.add_all([a, c])
    await db_session.flush()
    assert await dhcp_ha_firewall_inputs(db_session, a) == (8000, ["10.0.0.12/32"])
    # The sidelined member has no HA listener to open.
    assert await dhcp_ha_firewall_inputs(db_session, c) == (None, [])


@pytest.mark.asyncio
async def test_a_third_member_joining_leaves_the_pairs_bundles_untouched(
    db_session: AsyncSession,
) -> None:
    """The pair's ETag does not move when a URL-less third member joins, so
    neither peer re-renders and Kea never reloads its HA hook; the joiner's
    bundle carries nothing to serve. Then a URL on the joiner makes it an HA
    peer and it serves the scopes again."""
    grp = await _group(db_session, mode="load-balancing")
    pair = [
        await _kea(db_session, grp, "dhcp-a", "http://10.0.0.11:8000/"),
        await _kea(db_session, grp, "dhcp-b", "http://10.0.0.12:8000/"),
    ]
    await _scope_with_pool(db_session, grp)
    before = {m.name: (await build_config_bundle(db_session, m)).etag for m in pair}

    third = await _kea(db_session, grp, "dhcp-c", "")
    await db_session.refresh(grp, ["servers"])
    after = {m.name: (await build_config_bundle(db_session, m)).etag for m in pair}
    assert after == before
    sidelined = await build_config_bundle(db_session, third)
    assert sidelined.failover is None and sidelined.scopes == ()

    third.ha_peer_url = "http://10.0.0.13:8000/"
    await db_session.flush()
    joined = await build_config_bundle(db_session, third)
    assert joined.failover is not None
    # Roles follow server-id order (#2963), so which one is ``backup`` depends
    # on the ids; what matters is that all three are now in the relationship.
    assert {p["name"] for p in joined.failover.peers} == {"dhcp-a", "dhcp-b", "dhcp-c"}
    assert len(joined.scopes) == 1


@pytest.mark.asyncio
async def test_standalone_group_never_sidelines(db_session: AsyncSession) -> None:
    """``standalone`` renders no HA (#2969), so nothing is sidelined there: a
    three-member standalone group with mixed URLs keeps every member serving."""
    grp = await _group(db_session, mode="standalone")
    members = [
        await _kea(db_session, grp, "dhcp-a", "http://10.0.0.11:8000/"),
        await _kea(db_session, grp, "dhcp-b", "http://10.0.0.12:8000/"),
        await _kea(db_session, grp, "dhcp-c", ""),
    ]
    await _scope_with_pool(db_session, grp)
    await db_session.refresh(grp, ["servers"])
    for m in members:
        bundle = await build_config_bundle(db_session, m)
        assert bundle.failover is None
        assert len(bundle.scopes) == 1
