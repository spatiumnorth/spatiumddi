"""Kea HA follows the group's ``mode`` (#2969).

Only ``hot-standby`` / ``load-balancing`` render HA — in the bundle, in the
appliance HA firewall rule and in the ``kea_ha_version_skew`` pre-flight. A
``standalone`` group never does, whatever peer URLs its members carry (Kea
refuses ``"mode": "standalone"`` and the whole config is rejected).
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.alerts import _matching_dhcp_scope_uncoordinated_subjects
from app.services.dhcp.config_bundle import _resolve_failover, build_config_bundle
from app.services.dhcp.ha_firewall import dhcp_ha_firewall_inputs
from app.services.upgrades.preflight import check_kea_ha_version_skew


async def _pair(db: AsyncSession, mode: str, urls: bool = True):
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="", mode=mode)
    db.add(grp)
    await db.flush()
    srvs = []
    for n, kv in (("a", "3.0.3"), ("b", "2.6.5")):
        s = DHCPServer(
            name=f"{n}-{uuid.uuid4().hex[:5]}",
            driver="kea",
            host=f"10.0.0.{1 if n == 'a' else 2}",
            port=67,
            server_group_id=grp.id,
            kea_version=kv,
            deployment_kind="appliance",
            ha_peer_url=f"http://{n}:8000/" if urls else "",
        )
        db.add(s)
        srvs.append(s)
    await db.flush()
    await db.refresh(grp, ["servers"])
    return grp, srvs


@pytest.mark.asyncio
async def test_standalone_with_urls_renders_no_ha(db_session: AsyncSession) -> None:
    grp, (a, b) = await _pair(db_session, "standalone")
    assert await _resolve_failover(db_session, a, grp) is None
    assert await _resolve_failover(db_session, b, grp) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["hot-standby", "load-balancing"])
async def test_ha_modes_with_urls_render_ha(db_session: AsyncSession, mode: str) -> None:
    grp, (a, _b) = await _pair(db_session, mode)
    fo = await _resolve_failover(db_session, a, grp)
    assert fo is not None and fo.mode == mode


@pytest.mark.asyncio
async def test_standalone_gets_no_ha_firewall_rule(db_session: AsyncSession) -> None:
    for mode, expect_port in (("standalone", None), ("hot-standby", 8000)):
        grp, (a, _b) = await _pair(db_session, mode)
        der = os.urandom(32)
        me = Appliance(
            id=uuid.uuid4(),
            hostname=a.host,
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            assigned_roles=["dhcp"],
            assigned_dhcp_group_id=grp.id,
            node_ips=[],
        )
        db_session.add(me)
        a.appliance_id = me.id
        await db_session.flush()
        port, _peers = await dhcp_ha_firewall_inputs(db_session, me)
        assert port == expect_port, mode


@pytest.mark.asyncio
async def test_preflight_counts_only_ha_mode_groups(db_session: AsyncSession) -> None:
    grp, _ = await _pair(db_session, "standalone")
    await db_session.commit()
    r = await check_kea_ha_version_skew()
    assert r.level == "ok" and r.detail.get("ha_groups") == 0
    # Positive control: the same members in a hot-standby group are a mixed pair.
    grp2, _ = await _pair(db_session, "hot-standby")
    await db_session.commit()
    r = await check_kea_ha_version_skew()
    assert grp2.name in r.detail.get("mixed_major", [])
    assert grp.name not in r.detail.get("mixed_major", [])


@pytest.mark.asyncio
async def test_bundle_etag_shifts_when_mode_changes(db_session: AsyncSession) -> None:
    grp, (a, _b) = await _pair(db_session, "hot-standby")
    before = (await build_config_bundle(db_session, a)).etag
    grp.mode = "standalone"
    await db_session.flush()
    bundle = await build_config_bundle(db_session, a)
    assert bundle.failover is None
    assert bundle.etag != before


async def _with_scope(db: AsyncSession, grp: DHCPServerGroup) -> None:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.80.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.80.1.0/24", name="n")
    db.add(subnet)
    await db.flush()
    db.add(DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True))
    await db.flush()


@pytest.mark.asyncio
async def test_standalone_with_two_kea_and_a_scope_is_flagged(db_session: AsyncSession) -> None:
    grp, _ = await _pair(db_session, "standalone", urls=False)
    # No scope yet: nothing is being served, nothing to flag.
    assert await _matching_dhcp_scope_uncoordinated_subjects(db_session, None) == []  # type: ignore[arg-type]
    await _with_scope(db_session, grp)
    hits = await _matching_dhcp_scope_uncoordinated_subjects(db_session, None)  # type: ignore[arg-type]
    assert [h[0] for h in hits] == [f"{grp.id}:standalone"]
    assert grp.name in hits[0][2]
    # Positive control: an HA-mode group is not flagged.
    grp.mode = "hot-standby"
    await db_session.flush()
    assert await _matching_dhcp_scope_uncoordinated_subjects(db_session, None) == []  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_inactive_scope_is_not_served_so_not_flagged(db_session: AsyncSession) -> None:
    grp, _ = await _pair(db_session, "standalone", urls=False)
    await _with_scope(db_session, grp)
    from sqlalchemy import update  # noqa: PLC0415

    await db_session.execute(
        update(DHCPScope).where(DHCPScope.group_id == grp.id).values(is_active=False)
    )
    await db_session.flush()
    # An inactive scope is in no bundle, so nothing is served uncoordinated.
    assert await _matching_dhcp_scope_uncoordinated_subjects(db_session, None) == []  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_windows_groups_get_no_standalone_event(db_session: AsyncSession) -> None:
    """The standalone match counts Kea members only, and leaves a group with a
    Windows member to the per-scope failover report (#1110), so one fault does
    not raise two events."""
    # Windows-only standalone group with two members: not a Kea concern.
    win_grp = DHCPServerGroup(name=f"w-{uuid.uuid4().hex[:8]}", description="", mode="standalone")
    db_session.add(win_grp)
    await db_session.flush()
    for i in (1, 2):
        db_session.add(
            DHCPServer(
                name=f"w{i}-{uuid.uuid4().hex[:5]}",
                driver="windows_dhcp",
                host=f"10.9.0.{i}",
                port=67,
                server_group_id=win_grp.id,
            )
        )
    await db_session.flush()
    await _with_scope(db_session, win_grp)
    # A pre-#1110 mixed group: two Kea + one Windows, standalone.
    mixed, _ = await _pair(db_session, "standalone", urls=False)
    db_session.add(
        DHCPServer(
            name=f"mw-{uuid.uuid4().hex[:5]}",
            driver="windows_dhcp",
            host="10.9.1.1",
            port=67,
            server_group_id=mixed.id,
        )
    )
    await db_session.flush()
    await _with_scope(db_session, mixed)
    hits = await _matching_dhcp_scope_uncoordinated_subjects(db_session, None)  # type: ignore[arg-type]
    subjects = [h[0] for h in hits]
    assert f"{win_grp.id}:standalone" not in subjects
    assert f"{mixed.id}:standalone" not in subjects


async def _token(db: AsyncSession) -> str:
    user = User(
        username=f"m-{uuid.uuid4().hex[:6]}",
        email=f"m-{uuid.uuid4().hex[:6]}@example.test",
        display_name="m",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_mode_change_into_or_out_of_ha_wakes_the_groups_appliances(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The HA firewall rule rides the supervisor heartbeat, so a mode change
    that flips HA on or off wakes each appliance serving the group."""
    from app.core import agent_wake  # noqa: PLC0415

    captured: list[str] = []

    async def _capture(*channels: str) -> None:
        captured.extend(channels)

    monkeypatch.setattr(agent_wake, "publish_wake", _capture)
    grp, _ = await _pair(db_session, "standalone")
    der = os.urandom(32)
    me = Appliance(
        id=uuid.uuid4(),
        hostname="10.0.0.1",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        assigned_roles=["dhcp"],
        assigned_dhcp_group_id=grp.id,
        node_ips=[],
    )
    db_session.add(me)
    headers = {"Authorization": f"Bearer {await _token(db_session)}"}
    await db_session.commit()
    want = agent_wake.appliance_channel(me.id)

    r = await client.put(
        f"/api/v1/dhcp/server-groups/{grp.id}", json={"mode": "hot-standby"}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert want in captured
    # hot-standby -> load-balancing stays HA: the firewall rule does not move.
    captured.clear()
    r = await client.put(
        f"/api/v1/dhcp/server-groups/{grp.id}", json={"mode": "load-balancing"}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert want not in captured
    captured.clear()
    r = await client.put(
        f"/api/v1/dhcp/server-groups/{grp.id}", json={"mode": "standalone"}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert want in captured
