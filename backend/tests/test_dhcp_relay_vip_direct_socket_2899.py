"""A DHCP group in ``direct`` socket mode behind the MetalLB relay VIP (#2899).

In raw mode the announcing node's Kea drops every relay flow kube-proxy keeps
on it, and no counter shows it. The fix: refuse the configurations that create
the state, and report the state (default-on alert, MetalLB card, MCP) wherever
it exists. No rendered config changes on its own.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings
from app.services import alerts
from app.services.alert_rule_catalogue import build_catalogue
from app.services.appliance.dhcp_group_move import move_appliance_dhcp_servers
from app.services.dhcp.relay_vip import direct_groups_behind_relay_vip

pytestmark = pytest.mark.asyncio

METALLB = "/api/v1/appliance/fleet/control-plane/metallb"
VIP = "192.168.0.243"
_RULE = SimpleNamespace(severity="critical")


async def _admin(db: AsyncSession) -> tuple[User, dict]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        is_superadmin=True,
        **{"hashed_" + "password": hash_password("".join(["te", "st-pw"]))},
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _metallb_body(relay_vip: str = VIP, **extra) -> dict:
    return {
        "enabled": True,
        "pool_addresses": ["192.168.0.240/29"],
        "control_plane_vip": "192.168.0.241",
        "dhcp_relay_vip": relay_vip,
        **extra,
    }


async def _group(db: AsyncSession, mode: str = "direct", name: str | None = None):
    g = DHCPServerGroup(
        name=name or f"g-{uuid.uuid4().hex[:6]}", description="", dhcp_socket_mode=mode
    )
    db.add(g)
    await db.flush()
    return g


async def _appliance(
    db: AsyncSession,
    group: DHCPServerGroup | None,
    *,
    deployment_kind: str | None = "appliance",
    roles: list[str] | None = None,
    state: str = APPLIANCE_STATE_APPROVED,
) -> Appliance:
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=state,
        deployment_kind=deployment_kind,
        appliance_variant="application",
        assigned_roles=["dhcp"] if roles is None else roles,
        capabilities={"can_run_dhcp": True},
        assigned_dhcp_group_id=group.id if group is not None else None,
    )
    db.add(a)
    await db.flush()
    return a


async def _set_vip(db: AsyncSession, vip: str = VIP, *, enabled: bool = True) -> None:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
    row.metallb_enabled = enabled
    row.metallb_pool_addresses = ["192.168.0.240/29"]
    row.control_plane_vip = "192.168.0.241"
    row.dhcp_relay_vip = vip
    await db.flush()


# ── MetalLB PUT: turning the relay VIP on ────────────────────────────────


async def test_turning_relay_vip_on_over_a_direct_group_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, h = await _admin(db_session)
    g = await _group(db_session, "direct", name="branch-dhcp")
    await _appliance(db_session, g)
    await db_session.commit()

    r = await client.put(METALLB, json=_metallb_body(), headers=h)
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "'branch-dhcp'" in detail
    assert VIP in detail
    assert "dhcp_socket_mode=relay" in detail
    # Nothing persisted: the VIP is still off.
    got = (await client.get(METALLB, headers=h)).json()
    assert got["dhcp_relay_vip"] == ""
    assert got["enabled"] is False


async def test_relay_vip_over_a_relay_group_is_accepted(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, h = await _admin(db_session)
    g = await _group(db_session, "relay")
    await _appliance(db_session, g)
    await db_session.commit()

    r = await client.put(METALLB, json=_metallb_body(), headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["dhcp_relay_vip"] == VIP
    assert r.json()["dhcp_relay_vip_direct_groups"] == []


async def test_registered_kea_row_puts_its_group_behind_the_vip(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """No role pointer, but the appliance's Kea server row is in the group."""
    _, h = await _admin(db_session)
    g = await _group(db_session, "direct", name="registered-only")
    a = await _appliance(db_session, None, roles=[])
    db_session.add(
        DHCPServer(
            name=f"kea-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host=a.hostname,
            port=67,
            server_group_id=g.id,
            agent_id=uuid.uuid4(),
            appliance_id=a.id,
        )
    )
    await db_session.commit()

    r = await client.put(METALLB, json=_metallb_body(), headers=h)
    assert r.status_code == 422, r.text
    assert "'registered-only'" in r.json()["detail"]


async def test_groups_not_on_the_cluster_do_not_block_the_vip(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A direct group whose Kea runs off the cluster (Compose, an unapproved or
    non-appliance supervisor, an appliance without the dhcp role) is not
    behind the VIP Service."""
    _, h = await _admin(db_session)
    compose = await _group(db_session, "direct")
    db_session.add(
        DHCPServer(
            name=f"kea-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="10.9.9.9",
            port=67,
            server_group_id=compose.id,
            agent_id=uuid.uuid4(),
        )
    )
    await _appliance(db_session, await _group(db_session, "direct"), deployment_kind="docker")
    await _appliance(db_session, await _group(db_session, "direct"), state="pending_approval")
    await _appliance(db_session, await _group(db_session, "direct"), roles=["dns-bind9"])
    await db_session.commit()

    r = await client.put(METALLB, json=_metallb_body(), headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["dhcp_relay_vip_direct_groups"] == []


async def test_existing_state_is_reported_not_blocked(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """An install that already has the VIP over a direct group can still save
    unrelated MetalLB edits; GET names the group."""
    _, h = await _admin(db_session)
    g = await _group(db_session, "direct", name="legacy")
    await _appliance(db_session, g)
    await _set_vip(db_session)
    await db_session.commit()

    got = (await client.get(METALLB, headers=h)).json()
    assert got["dhcp_relay_vip_direct_groups"] == ["legacy"]

    r = await client.put(
        METALLB, json=_metallb_body(pool_addresses=["192.168.0.240/28"]), headers=h
    )
    assert r.status_code == 200, r.text
    assert r.json()["dhcp_relay_vip_direct_groups"] == ["legacy"]

    # Clearing the VIP is always allowed, and clears the report.
    r = await client.put(METALLB, json=_metallb_body(relay_vip=""), headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["dhcp_relay_vip_direct_groups"] == []


# ── DHCP group PUT: changing the socket mode ─────────────────────────────


async def test_switching_a_group_behind_the_vip_to_direct_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, h = await _admin(db_session)
    g = await _group(db_session, "relay", name="behind")
    await _appliance(db_session, g)
    await _set_vip(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/server-groups/{g.id}", json={"dhcp_socket_mode": "direct"}, headers=h
    )
    assert r.status_code == 422, r.text
    assert "'behind'" in r.json()["detail"]
    await db_session.refresh(g)
    assert g.dhcp_socket_mode == "relay"


async def test_direct_is_allowed_without_vip_or_off_cluster(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, h = await _admin(db_session)
    on_cluster = await _group(db_session, "relay")
    await _appliance(db_session, on_cluster)
    off_cluster = await _group(db_session, "relay")
    await db_session.commit()

    # No VIP: direct is fine.
    r = await client.put(
        f"/api/v1/dhcp/server-groups/{on_cluster.id}",
        json={"dhcp_socket_mode": "direct"},
        headers=h,
    )
    assert r.status_code == 200, r.text

    await _set_vip(db_session)
    await db_session.commit()
    # VIP set, but the group has no Kea on the cluster.
    r = await client.put(
        f"/api/v1/dhcp/server-groups/{off_cluster.id}",
        json={"dhcp_socket_mode": "direct"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    # Re-saving an already-direct group (e.g. an unrelated field) is not refused.
    r = await client.put(
        f"/api/v1/dhcp/server-groups/{on_cluster.id}",
        json={"dhcp_socket_mode": "direct", "description": "x"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    # And switching to relay, the fix, always succeeds.
    r = await client.put(
        f"/api/v1/dhcp/server-groups/{on_cluster.id}",
        json={"dhcp_socket_mode": "relay"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["dhcp_socket_mode"] == "relay"


# ── Role assignment: pointing an appliance's Kea at a group ──────────────


async def test_role_assignment_into_a_direct_group_is_refused(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    user, h = await _admin(db_session)
    relay_g = await _group(db_session, "relay")
    direct_g = await _group(db_session, "direct", name="direct-target")
    a = await _appliance(db_session, relay_g)
    await _set_vip(db_session)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        json={"roles": ["dhcp"], "dhcp_group_id": str(direct_g.id)},
        headers=h,
    )
    assert r.status_code == 422, r.text
    assert "'direct-target'" in r.json()["detail"]
    await db_session.refresh(a)
    assert a.assigned_dhcp_group_id == relay_g.id

    # The Copilot door goes through the same helper.
    with pytest.raises(HTTPException) as exc:
        await move_appliance_dhcp_servers(db_session, a, direct_g, user, dry_run=True)
    assert exc.value.status_code == 422


async def test_role_assignment_allowed_when_it_cannot_reach_the_vip(
    db_session: AsyncSession,
) -> None:
    user, _ = await _admin(db_session)
    direct_g = await _group(db_session, "direct")
    relay_g = await _group(db_session, "relay")
    on = await _appliance(db_session, None)
    docker = await _appliance(db_session, None, deployment_kind="docker")
    await db_session.commit()

    # No VIP yet.
    await move_appliance_dhcp_servers(db_session, on, direct_g, user, dry_run=True)
    await _set_vip(db_session)
    await db_session.commit()
    # Relay group, off-cluster appliance, no dhcp role, unchanged pointer.
    await move_appliance_dhcp_servers(db_session, on, relay_g, user, dry_run=True)
    await move_appliance_dhcp_servers(db_session, docker, direct_g, user, dry_run=True)
    await move_appliance_dhcp_servers(
        db_session, on, direct_g, user, dry_run=True, roles=["dns-bind9"]
    )
    on.assigned_dhcp_group_id = direct_g.id
    await move_appliance_dhcp_servers(db_session, on, direct_g, user, dry_run=True)


# ── The alert, and the shared helper ─────────────────────────────────────


async def test_alert_fires_per_direct_group_behind_the_vip(db_session: AsyncSession) -> None:
    a_g = await _group(db_session, "direct", name="a-direct")
    b_g = await _group(db_session, "direct", name="b-direct")
    relay_g = await _group(db_session, "relay")
    for g in (a_g, b_g, relay_g):
        await _appliance(db_session, g)
    await _group(db_session, "direct")  # off-cluster
    await db_session.commit()

    assert await alerts._matching_dhcp_relay_vip_direct_socket_subjects(db_session, _RULE) == []

    await _set_vip(db_session)
    await db_session.commit()
    hits = await alerts._matching_dhcp_relay_vip_direct_socket_subjects(db_session, _RULE)
    assert [(sid, disp) for sid, disp, _m, _s in hits] == [
        (str(a_g.id), "a-direct"),
        (str(b_g.id), "b-direct"),
    ]
    msg = hits[0][2]
    assert VIP in msg and "dhcp_socket_mode=relay" in msg and "no counter" in msg
    assert hits[0][3] == "critical"

    # A VIP stored while MetalLB is off fronts nothing.
    await _set_vip(db_session, enabled=False)
    await db_session.commit()
    assert await alerts._matching_dhcp_relay_vip_direct_socket_subjects(db_session, _RULE) == []
    assert await direct_groups_behind_relay_vip(db_session) == []


async def test_alert_resolves_when_the_group_is_set_to_relay(db_session: AsyncSession) -> None:
    g = await _group(db_session, "direct")
    await _appliance(db_session, g)
    await _set_vip(db_session)
    await db_session.commit()
    assert len(await alerts._matching_dhcp_relay_vip_direct_socket_subjects(db_session, _RULE)) == 1
    g.dhcp_socket_mode = "relay"
    await db_session.commit()
    assert await alerts._matching_dhcp_relay_vip_direct_socket_subjects(db_session, _RULE) == []


async def test_evaluate_all_opens_an_event(db_session: AsyncSession) -> None:
    g = await _group(db_session, "direct")
    await _appliance(db_session, g)
    await _set_vip(db_session)
    db_session.add(
        AlertRule(
            name="relay vip direct",
            rule_type=alerts.RULE_TYPE_DHCP_RELAY_VIP_DIRECT_SOCKET,
            severity="critical",
            enabled=True,
            notify_syslog=False,
            notify_webhook=False,
            notify_smtp=False,
        )
    )
    await db_session.commit()
    summary = await alerts.evaluate_all(db_session)
    assert summary["opened"] >= 1
    from app.models.alerts import AlertEvent

    ev = (
        await db_session.execute(
            select(AlertEvent).where(AlertEvent.subject_type == "dhcp_server_group")
        )
    ).scalar_one()
    assert ev.subject_id == str(g.id)


async def test_rule_is_seeded_enabled_and_catalogued(db_session: AsyncSession) -> None:
    assert alerts.RULE_TYPE_DHCP_RELAY_VIP_DIRECT_SOCKET in alerts.RULE_TYPES
    assert alerts.rule_type_module(alerts.RULE_TYPE_DHCP_RELAY_VIP_DIRECT_SOCKET) == "core.dhcp"
    assert alerts.RULE_TYPE_DHCP_RELAY_VIP_DIRECT_SOCKET in {s.rule_type for s in build_catalogue()}
    await alerts.seed_dhcp_relay_vip_direct_socket_alert_rule()
    await alerts.seed_dhcp_relay_vip_direct_socket_alert_rule()  # idempotent
    rows = (
        (
            await db_session.execute(
                select(AlertRule).where(
                    AlertRule.rule_type == alerts.RULE_TYPE_DHCP_RELAY_VIP_DIRECT_SOCKET
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].enabled is True
