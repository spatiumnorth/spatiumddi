"""Kea HA failover rendering in the DHCP ConfigBundle.

A DHCPServerGroup with >= 2 Kea members renders a ``FailoverConfig``.
Kea's ``libdhcp_ha.so`` requires ``this-server-name`` to match an entry
in the rendered ``peers`` array, so *every* Kea member must appear in
the peers list — the first sorted member is ``primary``, the second is
``secondary`` (load-balancing) / ``standby`` (hot-standby), and every
3rd+ member is ``backup`` (issue #332). Before the fix the renderer
capped the peers array at the first two sorted members, so the 3rd+
member's own name was absent from its own peers list and Kea refused to
load the rendered config.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.dhcp.config_bundle import _resolve_failover


async def _make_group(db: AsyncSession, mode: str = "load-balancing") -> DHCPServerGroup:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="", mode=mode)
    db.add(grp)
    await db.flush()
    return grp


async def _add_kea_server(
    db: AsyncSession,
    grp: DHCPServerGroup,
    name: str,
    ha_peer_url: str = "",
    driver: str = "kea",
) -> DHCPServer:
    srv = DHCPServer(
        name=f"{name}-{uuid.uuid4().hex[:6]}",
        driver=driver,
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
        ha_peer_url=ha_peer_url,
    )
    db.add(srv)
    await db.flush()
    return srv


@pytest.mark.asyncio
async def test_single_member_group_has_no_failover(db_session: AsyncSession) -> None:
    grp = await _make_group(db_session)
    srv = await _add_kea_server(db_session, grp, "solo", ha_peer_url="http://solo:8000/")
    await db_session.refresh(grp, ["servers"])
    assert await _resolve_failover(db_session, srv, grp) is None


@pytest.mark.asyncio
async def test_two_member_pair_renders_primary_and_secondary(
    db_session: AsyncSession,
) -> None:
    grp = await _make_group(db_session, mode="load-balancing")
    a = await _add_kea_server(db_session, grp, "a", ha_peer_url="http://a:8000/")
    b = await _add_kea_server(db_session, grp, "b", ha_peer_url="http://b:8000/")
    await db_session.refresh(grp, ["servers"])

    fo = await _resolve_failover(db_session, a, grp)
    assert fo is not None
    assert len(fo.peers) == 2
    roles = {p["name"]: p["role"] for p in fo.peers}
    assert set(roles.values()) == {"primary", "secondary"}
    # this-server-name must match a peer entry.
    assert fo.this_server_name in {p["name"] for p in fo.peers}
    assert fo.this_server_name == a.name

    # The other peer renders the same peers array, just a different
    # this-server-name — and it must also be present.
    fo_b = await _resolve_failover(db_session, b, grp)
    assert fo_b is not None
    assert {p["name"] for p in fo_b.peers} == {p["name"] for p in fo.peers}
    assert fo_b.this_server_name == b.name
    assert fo_b.this_server_name in {p["name"] for p in fo_b.peers}


@pytest.mark.asyncio
async def test_hot_standby_uses_standby_role(db_session: AsyncSession) -> None:
    grp = await _make_group(db_session, mode="hot-standby")
    await _add_kea_server(db_session, grp, "a", ha_peer_url="http://a:8000/")
    b = await _add_kea_server(db_session, grp, "b", ha_peer_url="http://b:8000/")
    await db_session.refresh(grp, ["servers"])

    fo = await _resolve_failover(db_session, b, grp)
    assert fo is not None
    roles = {p["role"] for p in fo.peers}
    assert roles == {"primary", "standby"}


@pytest.mark.asyncio
async def test_three_member_group_renders_every_member_and_self(
    db_session: AsyncSession,
) -> None:
    """Regression for #332 — every Kea member's own name must be in its
    rendered peers list, and 3rd+ members render as ``backup``."""
    grp = await _make_group(db_session, mode="load-balancing")
    servers = [
        await _add_kea_server(db_session, grp, f"node{i}", ha_peer_url=f"http://node{i}:8000/")
        for i in range(3)
    ]
    await db_session.refresh(grp, ["servers"])

    rendered = []
    for srv in servers:
        fo = await _resolve_failover(db_session, srv, grp)
        assert fo is not None, f"{srv.name} got no failover config"
        rendered.append(fo)
        # Every member must list all three peers.
        assert len(fo.peers) == 3
        peer_names = {p["name"] for p in fo.peers}
        # this-server-name must be present in the peers array — the
        # exact invariant Kea's HA hook enforces.
        assert (
            fo.this_server_name in peer_names
        ), f"{srv.name}: this-server-name absent from peers {peer_names}"
        assert fo.this_server_name == srv.name

    # Roles across the (stably sorted) group: exactly one primary, one
    # secondary, one backup.
    fo0 = rendered[0]
    roles = sorted(p["role"] for p in fo0.peers)
    assert roles == ["backup", "primary", "secondary"]
    # All members render the identical peers array (same names + roles).
    by_name = {p["name"]: p["role"] for p in fo0.peers}
    for fo in rendered[1:]:
        assert {p["name"]: p["role"] for p in fo.peers} == by_name


@pytest.mark.asyncio
async def test_five_member_group_has_three_backups(db_session: AsyncSession) -> None:
    grp = await _make_group(db_session, mode="load-balancing")
    servers = [
        await _add_kea_server(db_session, grp, f"n{i}", ha_peer_url=f"http://n{i}:8000/")
        for i in range(5)
    ]
    await db_session.refresh(grp, ["servers"])

    fo = await _resolve_failover(db_session, servers[0], grp)
    assert fo is not None
    assert len(fo.peers) == 5
    role_counts: dict[str, int] = {}
    for p in fo.peers:
        role_counts[p["role"]] = role_counts.get(p["role"], 0) + 1
    assert role_counts == {"primary": 1, "secondary": 1, "backup": 3}
    # Each member still sees itself in the list.
    for srv in servers:
        fo_i = await _resolve_failover(db_session, srv, grp)
        assert fo_i is not None
        assert fo_i.this_server_name in {p["name"] for p in fo_i.peers}


@pytest.mark.asyncio
async def test_missing_peer_url_leaves_that_member_out_not_the_pair(
    db_session: AsyncSession,
) -> None:
    """#3151: a third member with no HA URL is left out of the relationship;
    the two members that have one keep their HA hook."""
    grp = await _make_group(db_session)
    a = await _add_kea_server(db_session, grp, "a", ha_peer_url="http://a:8000/")
    b = await _add_kea_server(db_session, grp, "b", ha_peer_url="http://b:8000/")
    c = await _add_kea_server(db_session, grp, "c", ha_peer_url="")
    await db_session.refresh(grp, ["servers"])

    fo = await _resolve_failover(db_session, a, grp)
    assert fo is not None
    assert {p["name"] for p in fo.peers} == {a.name, b.name}
    assert await _resolve_failover(db_session, c, grp) is None


@pytest.mark.asyncio
async def test_fewer_than_two_peer_urls_suppresses_ha(db_session: AsyncSession) -> None:
    grp = await _make_group(db_session)
    a = await _add_kea_server(db_session, grp, "a", ha_peer_url="http://a:8000/")
    await _add_kea_server(db_session, grp, "b", ha_peer_url="")
    await _add_kea_server(db_session, grp, "c", ha_peer_url="")
    await db_session.refresh(grp, ["servers"])

    assert await _resolve_failover(db_session, a, grp) is None


@pytest.mark.asyncio
async def test_non_kea_members_are_ignored_for_ha(db_session: AsyncSession) -> None:
    grp = await _make_group(db_session)
    a = await _add_kea_server(db_session, grp, "a", ha_peer_url="http://a:8000/")
    b = await _add_kea_server(db_session, grp, "b", ha_peer_url="http://b:8000/")
    # A Windows read-only member shouldn't count toward HA peers.
    await _add_kea_server(db_session, grp, "win", ha_peer_url="", driver="windows-dhcp-ro")
    await db_session.refresh(grp, ["servers"])

    fo = await _resolve_failover(db_session, a, grp)
    assert fo is not None
    names = {p["name"] for p in fo.peers}
    assert names == {a.name, b.name}
    assert len(fo.peers) == 2
