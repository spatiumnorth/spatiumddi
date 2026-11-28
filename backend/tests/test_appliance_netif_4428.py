"""Additional appliance network interfaces (#4428).

Three layers: the pure validation / bundle / state-join service, the REST
surface (permissions, refusals, audit, OpenAPI), and the copilot tools.

The cases that matter are the CUT-OFF ones. A node whose primary interface
is rewritten, or whose cluster addresses are shadowed by a new route, cannot
be told to undo it — so each of those is asserted both at the service layer
and as the 422 an operator would see, and a refused request is asserted to
leave the stored set and the audit log untouched.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.services.appliance import netif
from app.services.appliance.ca import generate_session_token
from app.services.appliance.netif import NetifError

BASE = "/api/v1/appliance/appliances"


# ── fixtures ─────────────────────────────────────────────────────────


def _nic(name: str, kind: str = "ethernet", **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": name,
        "kind": kind,
        "state": "up",
        "carrier": True,
        "mtu": 1500,
        "mac": "52:54:00:aa:bb:cc",
        "addresses": [],
    }
    row.update(over)
    return row


def _health(**over: Any) -> dict[str, Any]:
    """A node with a primary ens18, a spare ens19, and k3s's bridge."""
    inventory: dict[str, Any] = {
        "at_epoch": 1,
        "primary_interface": "ens18",
        "default_devs": ["ens18"],
        "interfaces": [
            _nic("ens18", addresses=["192.168.1.10/24"]),
            _nic("ens19"),
            _nic("ens20"),
            _nic("cni0", kind="bridge", addresses=["10.42.0.1/24"]),
        ],
        "routes": [
            {"dst": "default", "gateway": "192.168.1.1", "dev": "ens18", "metric": 100},
            {"dst": "192.168.1.0/24", "dev": "ens18", "protocol": "kernel"},
            {"dst": "10.42.0.0/24", "dev": "cni0", "protocol": "kernel"},
        ],
    }
    inventory.update(over.pop("inventory", {}))
    block: dict[str, Any] = {"inventory": inventory}
    block.update(over)
    return {"netif": block}


async def _appliance(
    db: AsyncSession,
    *,
    health: dict[str, Any] | None = None,
    desired: list[dict[str, Any]] | None = None,
    state: str = APPLIANCE_STATE_APPROVED,
    revoked: bool = False,
) -> Appliance:
    from datetime import UTC, datetime

    row = Appliance(
        hostname=f"ddi-{uuid.uuid4().hex[:6]}",
        public_key_der=b"x" * 32,
        public_key_fingerprint=uuid.uuid4().hex * 2,
        state=state,
        cluster_health=health if health is not None else _health(),
        desired_network_interfaces=desired or [],
        node_ips=["192.168.1.10"],
        pod_cidr="10.42.0.0/16",
        service_cidr="10.43.0.0/16",
        revoked_at=datetime.now(UTC) if revoked else None,
    )
    db.add(row)
    await db.flush()
    return row


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    await db.refresh(u, ["groups"])
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _user_with(db: AsyncSession, perm: dict[str, Any] | None) -> dict[str, str]:
    u = User(
        username=f"user-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="User",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(u)
    await db.flush()
    if perm is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=[perm])
        db.add(role)
        await db.flush()
        group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        group.roles = [role]
        group.users = [u]
        db.add(group)
        await db.flush()
    await db.refresh(u, ["groups"])
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


def _vlan(**over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": "vlan",
        "parent": "ens19",
        "vlan_id": 100,
        "addresses": ["10.9.0.2/24"],
    }
    row.update(over)
    return row


def _eth(name: str = "ens19", **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"kind": "ethernet", "name": name, "addresses": ["10.9.0.2/24"]}
    row.update(over)
    return row


def _ctx(block: dict[str, Any] | None = None, **over: Any) -> netif.NetifContext:
    health = _health()
    if block:
        health["netif"].update(block)
    return netif.build_context(
        health,
        node_ips=["192.168.1.10"],
        pod_cidr="10.42.0.0/16",
        service_cidr="10.43.0.0/16",
        **over,
    )


# ── service: structure ───────────────────────────────────────────────


def test_a_vlan_name_is_derived_from_parent_and_id() -> None:
    [row] = netif.normalise_desired([_vlan()])
    assert row["name"] == "ens19.100"
    assert row["up"] is True


def test_a_derived_name_over_fifteen_characters_asks_for_an_explicit_one() -> None:
    with pytest.raises(NetifError, match="15-character"):
        netif.normalise_desired([_vlan(parent="enx001122334455", vlan_id=4094)])
    [row] = netif.normalise_desired(
        [_vlan(parent="enx001122334455", vlan_id=4094, name="mgmt-dhcp")]
    )
    assert row["name"] == "mgmt-dhcp"


@pytest.mark.parametrize("dest", ["0.0.0.0/0", "::/0"])
def test_a_default_route_is_refused_outright(dest: str) -> None:
    addr = "10.9.0.2/24" if dest == "0.0.0.0/0" else "fd00:9::2/64"
    gw = "10.9.0.1" if dest == "0.0.0.0/0" else "fd00:9::1"
    with pytest.raises(NetifError, match="default route"):
        netif.normalise_desired(
            [_eth(addresses=[addr], routes=[{"destination": dest, "gateway": gw}])]
        )


@pytest.mark.parametrize(
    ("addr", "why"),
    [
        ("10.9.0.0/24", "network or broadcast"),
        ("10.9.0.255/24", "network or broadcast"),
        ("127.0.0.1/8", "unicast"),
        ("169.254.1.1/16", "link-local"),
        ("10.9.0.2", "prefix length"),
        ("224.0.0.1/24", "unicast"),
        ("10.9.0.2/4", "too wide"),
        ("not-an-ip/24", "not a valid"),
    ],
)
def test_unusable_addresses_are_refused(addr: str, why: str) -> None:
    with pytest.raises(NetifError, match=why):
        netif.normalise_desired([_eth(addresses=[addr])])


def test_a_gateway_outside_the_interface_subnets_is_refused() -> None:
    with pytest.raises(NetifError, match="not inside any subnet"):
        netif.normalise_desired(
            [_eth(routes=[{"destination": "10.20.0.0/16", "gateway": "10.77.0.1"}])]
        )


def test_a_gateway_that_is_the_interfaces_own_address_is_refused() -> None:
    with pytest.raises(NetifError, match="own address"):
        netif.normalise_desired(
            [_eth(routes=[{"destination": "10.20.0.0/16", "gateway": "10.9.0.2"}])]
        )


def test_a_route_on_a_down_interface_is_refused() -> None:
    with pytest.raises(NetifError, match="down"):
        netif.normalise_desired(
            [
                _eth(
                    up=False,
                    routes=[{"destination": "10.20.0.0/16", "gateway": "10.9.0.1"}],
                )
            ]
        )


def test_an_ipv6_address_needs_a_1280_mtu() -> None:
    with pytest.raises(NetifError, match="1280"):
        netif.normalise_desired([_eth(addresses=["fd00:9::2/64"], mtu=1000)])


@pytest.mark.parametrize("vid", [0, 4095, "100", True])
def test_vlan_ids_outside_1_4094_are_refused(vid: Any) -> None:
    with pytest.raises(NetifError, match="VLAN id"):
        netif.normalise_desired([_vlan(vlan_id=vid)])


def test_the_same_vlan_twice_and_stacked_vlans_are_refused() -> None:
    with pytest.raises(NetifError, match="twice"):
        netif.normalise_desired([_vlan(), _vlan(name="other")])
    with pytest.raises(NetifError, match="QinQ"):
        netif.normalise_desired([_vlan(), _vlan(parent="ens19.100", vlan_id=200)])


def test_limits_are_enforced() -> None:
    too_many = [_eth(f"ens{i}", addresses=[]) for i in range(netif.MAX_INTERFACES + 1)]
    with pytest.raises(NetifError, match="at most"):
        netif.normalise_desired(too_many)


# ── service: the cut-off protections ─────────────────────────────────


def test_the_primary_interface_cannot_be_managed() -> None:
    with pytest.raises(NetifError, match="primary interface") as exc:
        netif.validate_desired([_eth("ens18", addresses=["10.9.0.2/24"])], _ctx())
    assert "cut the node off" in str(exc.value)


def test_the_interface_carrying_the_default_route_is_protected_even_if_state_is_silent() -> None:
    ctx = _ctx(block={"inventory": {**_health()["netif"]["inventory"], "primary_interface": None}})
    with pytest.raises(NetifError, match="default route"):
        netif.validate_desired([_eth("ens18")], ctx)


def test_the_interface_carrying_the_cluster_address_is_protected() -> None:
    inv = _health()["netif"]["inventory"]
    inv = {**inv, "primary_interface": None, "default_devs": []}
    ctx = netif.build_context({"netif": {"inventory": inv}}, node_ips=["192.168.1.10"])
    with pytest.raises(NetifError, match="cluster address"):
        netif.validate_desired([_eth("ens18")], ctx)


def test_the_parent_of_a_protected_vlan_is_protected_too() -> None:
    inv = _health()["netif"]["inventory"]
    inv = {
        **inv,
        "primary_interface": "ens18.50",
        "default_devs": ["ens18.50"],
        "interfaces": [
            _nic("ens18"),
            _nic("ens18.50", kind="vlan", parent="ens18", vlan_id=50, addresses=["10.50.0.2/24"]),
            _nic("ens19"),
        ],
    }
    ctx = netif.build_context({"netif": {"inventory": inv}})
    with pytest.raises(NetifError, match="protected"):
        netif.validate_desired([_eth("ens18")], ctx)


def test_a_bond_members_are_protected_with_the_bond() -> None:
    inv = _health()["netif"]["inventory"]
    inv = {
        **inv,
        "primary_interface": "bond0",
        "default_devs": ["bond0"],
        "interfaces": [
            _nic("bond0", kind="bond", addresses=["192.168.1.10/24"]),
            _nic("ens18", master="bond0"),
            _nic("ens19", master="bond0"),
            _nic("ens20"),
        ],
    }
    ctx = netif.build_context({"netif": {"inventory": inv}})
    with pytest.raises(NetifError, match="member of bond0"):
        netif.validate_desired([_eth("ens19", addresses=["10.9.0.2/24"])], ctx)


def test_a_vlan_on_the_primary_nic_is_allowed() -> None:
    """A tagged sub-interface beside the untagged management one changes
    nothing about the management path."""
    [row] = netif.validate_desired([_vlan(parent="ens18", addresses=["10.9.0.2/24"])], _ctx())
    assert row["name"] == "ens18.100"


def test_a_vlan_on_a_missing_parent_is_refused() -> None:
    with pytest.raises(NetifError, match="does not exist"):
        netif.validate_desired([_vlan(parent="ens99")], _ctx())


def test_a_vlan_may_stack_on_a_port_configured_in_the_same_change() -> None:
    rows = netif.validate_desired(
        [
            _eth("ens19", addresses=["10.8.0.2/24"]),
            _vlan(parent="ens19", addresses=["10.9.0.2/24"]),
        ],
        _ctx(),
    )
    assert [r["name"] for r in rows] == ["ens19", "ens19.100"]


def test_a_vlan_cannot_sit_on_a_bridge_member_or_a_veth_kind() -> None:
    inv = _health()["netif"]["inventory"]
    inv = {**inv, "interfaces": [*inv["interfaces"], _nic("tun0", kind="tun")]}
    ctx = netif.build_context({"netif": {"inventory": inv}})
    with pytest.raises(NetifError, match="stacked on a tun"):
        netif.validate_desired([_vlan(parent="tun0")], ctx)


def test_a_physical_port_must_exist_and_must_be_a_port() -> None:
    with pytest.raises(NetifError, match="does not report"):
        netif.validate_desired([_eth("ens99")], _ctx())
    with pytest.raises(NetifError, match="not a physical NIC"):
        netif.validate_desired([_eth("cni0")], _ctx())


def test_an_address_overlapping_the_primary_subnet_is_refused() -> None:
    with pytest.raises(NetifError, match="overlaps 192.168.1.0/24 on ens18"):
        netif.validate_desired([_eth(addresses=["192.168.1.99/24"])], _ctx())


def test_an_address_overlapping_the_pod_or_service_cidr_is_refused() -> None:
    with pytest.raises(NetifError, match="overlaps"):
        netif.validate_desired([_eth(addresses=["10.42.5.2/24"])], _ctx())
    with pytest.raises(NetifError, match="service CIDR"):
        netif.validate_desired([_eth(addresses=["10.43.5.2/24"])], _ctx())


def test_two_interfaces_may_not_share_a_subnet() -> None:
    with pytest.raises(NetifError, match="overlapping"):
        netif.validate_desired(
            [_eth("ens19", addresses=["10.9.0.2/24"]), _eth("ens20", addresses=["10.9.0.3/24"])],
            _ctx(),
        )


def test_a_managed_interfaces_own_live_address_is_not_a_conflict() -> None:
    """Re-saving an unchanged config must not refuse itself."""
    inv = _health()["netif"]["inventory"]
    inv = {
        **inv,
        "interfaces": [
            _nic("ens18", addresses=["192.168.1.10/24"]),
            _nic("ens19", addresses=["10.9.0.2/24"]),
        ],
        "routes": [*inv["routes"], {"dst": "10.9.0.0/24", "dev": "ens19"}],
    }
    ctx = netif.build_context({"netif": {"inventory": inv}}, managed_names={"ens19"})
    [row] = netif.validate_desired([_eth("ens19")], ctx)
    assert row["addresses"] == ["10.9.0.2/24"]


@pytest.mark.parametrize(
    ("dest", "why"),
    [
        ("192.168.1.0/24", "management network|shadow|cluster"),
        ("192.168.0.0/16", "management network|cluster"),
        ("10.42.0.0/16", "pod CIDR"),
        ("10.43.0.0/24", "service CIDR"),
    ],
)
def test_a_route_may_not_take_over_a_path_the_node_depends_on(dest: str, why: str) -> None:
    with pytest.raises(NetifError, match=why):
        netif.validate_desired(
            [_eth(routes=[{"destination": dest, "gateway": "10.9.0.1"}])], _ctx()
        )


def test_a_relay_route_is_accepted() -> None:
    [row] = netif.validate_desired(
        [_eth(routes=[{"destination": "172.16.5.0/24", "gateway": "10.9.0.1", "metric": 50}])],
        _ctx(),
    )
    assert row["routes"] == [{"destination": "172.16.5.0/24", "gateway": "10.9.0.1", "metric": 50}]


def test_a_vlan_mtu_may_not_exceed_its_parents() -> None:
    with pytest.raises(NetifError, match="larger than its parent"):
        netif.validate_desired([_vlan(mtu=9000)], _ctx())


def test_a_vlan_name_already_used_for_another_vlan_is_refused() -> None:
    inv = _health()["netif"]["inventory"]
    inv = {
        **inv,
        "interfaces": [
            *inv["interfaces"],
            _nic("ens19.100", kind="vlan", parent="ens20", vlan_id=100),
        ],
    }
    ctx = netif.build_context({"netif": {"inventory": inv}}, managed_names=set())
    with pytest.raises(NetifError, match="already exists on this node as VLAN 100 on ens20"):
        netif.validate_desired([_vlan()], ctx)


# ── service: bundle + state join ─────────────────────────────────────


def test_the_bundle_hash_covers_what_the_runner_acts_on_only() -> None:
    a = netif.netif_bundle([_eth(description="uplink")])
    b = netif.netif_bundle([_eth(description="renamed note")])
    c = netif.netif_bundle([_eth(addresses=["10.9.0.3/24"])])
    assert a["config_hash"] == b["config_hash"] != c["config_hash"]
    assert a["enabled"] is True
    assert a["revert_seconds"] == netif.REVERT_SECONDS


def test_an_empty_set_hashes_to_a_real_digest_and_disables() -> None:
    b = netif.netif_bundle([])
    assert b["enabled"] is False
    assert b["interfaces"] == []
    assert b["config_hash"] == hashlib.sha256(b"[]").hexdigest()


def test_an_unvalidatable_stored_set_ships_no_instruction_not_teardown() -> None:
    b = netif.netif_bundle_safe([{"kind": "wormhole", "name": "x"}])
    assert b["interfaces"] is None
    assert b["config_hash"] == ""
    assert "error" in b


def _applied(rows: list[dict[str, Any]], state: str, **extra: Any) -> dict[str, Any]:
    h = _health()
    h["netif"]["apply_status"] = {"state": state, "hash": netif.desired_hash(rows), **extra}
    return h


def test_merge_state_covers_every_state() -> None:
    rows = netif.normalise_desired([_eth(), _eth("ens20", addresses=["10.8.0.2/24"], up=False)])
    live = _health(inventory={})["netif"]["inventory"]
    live["interfaces"] = [
        _nic("ens18", addresses=["192.168.1.10/24"]),
        _nic("ens19", addresses=["10.9.0.2/24"]),
        _nic("ens20", state="down"),
    ]

    def states(h: dict[str, Any]) -> dict[str, str]:
        return {r["name"]: r["state"] for r in netif.merge_state(rows, h)}

    assert states({}) == {"ens19": "unreported", "ens20": "unreported"}
    # Reported but never applied -> pending, never "active".
    assert states(_health()) == {"ens19": "pending", "ens20": "pending"}
    h = _applied(rows, "applied")
    h["netif"]["inventory"] = live
    assert states(h) == {"ens19": "active", "ens20": "inactive"}
    h = _applied(rows, "pending-confirm")
    assert set(states(h).values()) == {"confirming"}
    h = _applied(rows, "reverted", error="lost contact")
    merged = netif.merge_state(rows, h)
    assert {r["state"] for r in merged} == {"reverted"}
    assert merged[0]["detail"] == "lost contact"
    h = _applied(rows, "failed", error="nmcli failed")
    assert {r["state"] for r in netif.merge_state(rows, h)} == {"failed"}
    # A failure recorded against an OLDER hash is not this config's failure.
    h = _health()
    h["netif"]["apply_status"] = {"state": "failed", "hash": "old", "error": "x"}
    assert set(states(h).values()) == {"pending"}


def test_a_link_with_no_carrier_reports_inactive_with_the_reason() -> None:
    rows = netif.normalise_desired([_eth()])
    h = _applied(rows, "applied")
    h["netif"]["inventory"]["interfaces"] = [_nic("ens19", state="down", carrier=False)]
    [r] = netif.merge_state(rows, h)
    assert r["state"] == "inactive"
    assert "no cable" in r["detail"]


def test_garbage_in_the_reported_block_cannot_break_the_read() -> None:
    h = {
        "netif": {"inventory": {"interfaces": [None, {"name": 5, "mtu": "x", "addresses": 3}, "s"]}}
    }
    assert netif.has_inventory(h)
    [n] = [n for n in netif.inventory_nics(h) if n["name"]]
    assert n["mtu"] is None
    assert n["addresses"] == []


# ── REST: permissions + shape ────────────────────────────────────────


async def test_permissions(client: AsyncClient, db_session: AsyncSession) -> None:
    row = await _appliance(db_session)
    url = f"{BASE}/{row.id}/network-interfaces"
    body = {"interfaces": [_eth()]}

    assert (await client.get(url)).status_code == 401
    assert (await client.put(url, json=body)).status_code == 401

    nobody = await _user_with(db_session, None)
    assert (await client.get(url, headers=nobody)).status_code == 403
    assert (await client.put(url, json=body, headers=nobody)).status_code == 403

    reader = await _user_with(db_session, {"action": "read", "resource_type": "appliance"})
    assert (await client.get(url, headers=reader)).status_code == 200
    for r in (
        await client.put(url, json=body, headers=reader),
        await client.post(f"{url}/validate", json=body, headers=reader),
        await client.delete(f"{url}/ens19", headers=reader),
    ):
        assert r.status_code == 403, r.text

    admin = await _user_with(db_session, {"action": "admin", "resource_type": "appliance"})
    assert (await client.put(url, json=body, headers=admin)).status_code == 200


async def test_the_listing_joins_desired_with_the_reported_nics(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = netif.normalise_desired([_eth()])
    row = await _appliance(db_session, desired=rows)
    r = await client.get(
        f"{BASE}/{row.id}/network-interfaces", headers=await _superadmin(db_session)
    )
    assert r.status_code == 200
    body = r.json()
    assert body["reported"] is True
    assert [i["name"] for i in body["interfaces"]] == ["ens19"]
    assert body["interfaces"][0]["state"] == "pending"
    nics = {n["name"]: n for n in body["nics"]}
    assert nics["ens19"]["managed"] is True
    # The protected ones say WHY, so the UI can disable them with a reason.
    assert "primary interface" in nics["ens18"]["protected_reason"]
    assert nics["ens20"]["protected_reason"] is None


async def test_an_unreported_node_is_unknown_not_empty(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row = await _appliance(db_session, health={})
    r = await client.get(
        f"{BASE}/{row.id}/network-interfaces", headers=await _superadmin(db_session)
    )
    assert r.json()["reported"] is False
    assert r.json()["nics"] == []


async def test_unknown_unapproved_and_revoked_appliances(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _superadmin(db_session)
    r = await client.get(f"{BASE}/{uuid.uuid4()}/network-interfaces", headers=hdr)
    assert r.status_code == 404
    r = await client.put(
        f"{BASE}/{uuid.uuid4()}/network-interfaces", json={"interfaces": []}, headers=hdr
    )
    assert r.status_code == 404

    pending = await _appliance(db_session, state="pending_approval")
    r = await client.put(
        f"{BASE}/{pending.id}/network-interfaces", json={"interfaces": []}, headers=hdr
    )
    assert r.status_code == 409
    assert "not approved" in r.json()["detail"]

    # Trash analogue: a revoked appliance cannot be managed or read.
    revoked = await _appliance(db_session, revoked=True)
    for call in (
        client.get(f"{BASE}/{revoked.id}/network-interfaces", headers=hdr),
        client.put(f"{BASE}/{revoked.id}/network-interfaces", json={"interfaces": []}, headers=hdr),
        client.delete(f"{BASE}/{revoked.id}/network-interfaces/ens19", headers=hdr),
    ):
        r = await call
        assert r.status_code == 409, r.text
        assert "revoked" in r.json()["detail"]


async def test_a_write_to_a_node_that_has_not_reported_is_a_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row = await _appliance(db_session, health={})
    hdr = await _superadmin(db_session)
    r = await client.put(
        f"{BASE}/{row.id}/network-interfaces", json={"interfaces": [_eth()]}, headers=hdr
    )
    assert r.status_code == 409
    assert "not reported" in r.json()["detail"]
    # Removing configuration needs no inventory.
    r = await client.put(
        f"{BASE}/{row.id}/network-interfaces", json={"interfaces": []}, headers=hdr
    )
    assert r.status_code == 200


async def test_a_valid_put_stores_audits_and_reaches_the_heartbeat_bundle(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row = await _appliance(db_session)
    hdr = await _superadmin(db_session)
    body = {
        "interfaces": [
            {
                "kind": "ethernet",
                "name": "ens19",
                "addresses": ["10.9.0.2/24"],
                "routes": [{"destination": "172.16.5.0/24", "gateway": "10.9.0.1"}],
                "description": "dhcp vlan",
            },
            {"kind": "vlan", "parent": "ens19", "vlan_id": 200, "addresses": ["10.10.0.2/24"]},
        ]
    }
    r = await client.put(f"{BASE}/{row.id}/network-interfaces", json=body, headers=hdr)
    assert r.status_code == 200, r.text
    assert [i["name"] for i in r.json()["interfaces"]] == ["ens19", "ens19.200"]
    assert r.json()["revert_seconds"] == netif.REVERT_SECONDS

    db_session.expunge_all()
    stored = (await db_session.get(Appliance, row.id)).desired_network_interfaces
    assert [s["name"] for s in stored] == ["ens19", "ens19.200"]

    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "appliance.network.update")
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1
    assert audits[0].resource_id == str(row.id)
    assert audits[0].result == "ok"
    assert [i["name"] for i in audits[0].new_value["interfaces"]] == ["ens19", "ens19.200"]
    assert audits[0].old_value == {"interfaces": []}


async def test_the_heartbeat_ships_the_netif_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.settings import PlatformSettings

    s = await db_session.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db_session.add(s)
    s.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    desired = netif.normalise_desired([_eth()])
    row = Appliance(
        id=uuid.uuid4(),
        hostname="cp-1",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="control-plane",
        session_token_hash=token_hash,
        desired_network_interfaces=desired,
    )
    db_session.add(row)
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    block = r.json()["netif_settings"]
    assert block == netif.netif_bundle(desired)
    assert block["interfaces"][0]["name"] == "ens19"


@pytest.mark.parametrize(
    ("interfaces", "match"),
    [
        ([_eth("ens18")], "primary interface"),
        ([_eth(addresses=["192.168.1.50/24"])], "overlaps"),
        ([_eth(routes=[{"destination": "0.0.0.0/0", "gateway": "10.9.0.1"}])], "default route"),
        ([_vlan(parent="ens99")], "does not exist"),
        ([_eth(routes=[{"destination": "10.42.0.0/16", "gateway": "10.9.0.1"}])], "pod CIDR"),
        ([_eth(addresses=["10.9.0.2/24"], mtu=99999)], "MTU"),
        ([_eth("ens99")], "does not report"),
    ],
)
async def test_a_cut_off_change_is_refused_with_a_422_and_changes_nothing(
    client: AsyncClient, db_session: AsyncSession, interfaces: list[dict], match: str
) -> None:
    row = await _appliance(db_session)
    hdr = await _superadmin(db_session)
    for path in ("", "/validate"):
        r = await client.request(
            "PUT" if path == "" else "POST",
            f"{BASE}/{row.id}/network-interfaces{path}",
            json={"interfaces": interfaces},
            headers=hdr,
        )
        assert r.status_code == 422, r.text
        assert match in r.json()["detail"]

    db_session.expunge_all()
    assert (await db_session.get(Appliance, row.id)).desired_network_interfaces == []
    n = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action.like("appliance.network.%"))
            )
        )
        .scalars()
        .all()
    )
    assert n == []


async def test_validate_writes_nothing_and_returns_the_normalised_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row = await _appliance(db_session)
    hdr = await _superadmin(db_session)
    r = await client.post(
        f"{BASE}/{row.id}/network-interfaces/validate",
        json={"interfaces": [_vlan()]},
        headers=hdr,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["interfaces"][0]["name"] == "ens19.100"
    db_session.expunge_all()
    assert (await db_session.get(Appliance, row.id)).desired_network_interfaces == []


async def test_malformed_bodies_are_422s_not_500s(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    row = await _appliance(db_session)
    hdr = await _superadmin(db_session)
    url = f"{BASE}/{row.id}/network-interfaces"
    for body in ({}, {"interfaces": "x"}, {"interfaces": [{"kind": 5, "addresses": "x"}]}):
        r = await client.put(url, json=body, headers=hdr)
        assert r.status_code == 422, (body, r.text)
    r = await client.put(
        url, json={"interfaces": [{"kind": "ethernet", "name": "x y"}]}, headers=hdr
    )
    assert r.status_code == 422


async def test_delete_removes_audits_and_protects_a_vlan_parent(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = netif.normalise_desired(
        [_eth("ens19", addresses=["10.8.0.2/24"]), _vlan(parent="ens19", addresses=["10.9.0.2/24"])]
    )
    row = await _appliance(db_session, desired=rows)
    hdr = await _superadmin(db_session)
    url = f"{BASE}/{row.id}/network-interfaces"

    r = await client.delete(f"{url}/ens19", headers=hdr)
    assert r.status_code == 422
    assert "ens19.100" in r.json()["detail"]
    assert (await client.delete(f"{url}/nope", headers=hdr)).status_code == 404

    r = await client.delete(f"{url}/ens19.100", headers=hdr)
    assert r.status_code == 200
    assert [i["name"] for i in r.json()["interfaces"]] == ["ens19"]
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "appliance.network.remove")
            )
        )
        .scalars()
        .one()
    )
    assert audit.new_value["removed"] == "ens19.100"


async def test_resaving_an_applied_config_is_not_refused_by_its_own_live_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    rows = netif.normalise_desired([_eth()])
    health = _health(inventory={})
    health["netif"]["inventory"]["interfaces"][1] = _nic("ens19", addresses=["10.9.0.2/24"])
    health["netif"]["inventory"]["routes"].append({"dst": "10.9.0.0/24", "dev": "ens19"})
    row = await _appliance(db_session, health=health, desired=rows)
    r = await client.put(
        f"{BASE}/{row.id}/network-interfaces",
        json={"interfaces": [_eth(mtu=1400)]},
        headers=await _superadmin(db_session),
    )
    assert r.status_code == 200, r.text


# ── OpenAPI ──────────────────────────────────────────────────────────


def test_openapi_documents_the_surface() -> None:
    from app.main import app

    spec = app.openapi()
    p = spec["paths"]["/api/v1/appliance/appliances/{appliance_id}/network-interfaces"]
    assert {"get", "put"} <= set(p)
    assert (
        "post"
        in spec["paths"]["/api/v1/appliance/appliances/{appliance_id}/network-interfaces/validate"]
    )
    assert (
        "delete"
        in spec["paths"]["/api/v1/appliance/appliances/{appliance_id}/network-interfaces/{name}"]
    )
    schemas = spec["components"]["schemas"]
    resp = schemas["NetworkInterfacesResponse"]["properties"]
    assert {
        "reported",
        "interfaces",
        "nics",
        "apply_state",
        "apply_error",
        "revert_seconds",
    } <= set(resp)
    assert {"state", "detail", "live_addresses"} <= set(schemas["InterfaceOut"]["properties"])
    assert "netif_settings" in schemas["SupervisorHeartbeatResponse"]["properties"]


# ── MCP ──────────────────────────────────────────────────────────────


def test_tool_defaults_follow_the_rule() -> None:
    from app.services.ai.tools import REGISTRY

    find = REGISTRY.get("find_appliance_network_interfaces")
    propose = REGISTRY.get("propose_appliance_network_interfaces")
    assert find is not None and propose is not None
    # A read is discoverable; a write that edits host networking is opt-in.
    assert find.default_enabled is True
    assert propose.default_enabled is False
    # Neither writes: the propose tool stages a proposal a human applies.
    assert find.writes is False and propose.writes is False
    assert propose.module is None
    assert find.permission == propose.permission == "superadmin"


async def _tool_user(db: AsyncSession, *, superadmin: bool) -> User:
    u = User(
        username=f"t-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="t",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return u


async def test_find_tool_agrees_with_rest_and_skips_revoked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.ai.tools.appliance import (
        FindApplianceNetworkInterfacesArgs,
        find_appliance_network_interfaces,
    )

    rows = netif.normalise_desired([_eth()])
    live = await _appliance(db_session, desired=rows)
    await _appliance(db_session, desired=rows, revoked=True)
    silent = await _appliance(db_session, health={})
    user = await _tool_user(db_session, superadmin=True)

    out = await find_appliance_network_interfaces(
        db_session, user, FindApplianceNetworkInterfacesArgs(configured_only=False)
    )
    ids = {a["appliance_id"] for a in out["appliances"]}
    assert str(live.id) in ids
    assert len(ids) == 2  # the revoked one is not there
    assert silent.hostname in out["not_reporting"]  # unknown, not "none"

    mine = next(a for a in out["appliances"] if a["appliance_id"] == str(live.id))
    rest = (
        await client.get(
            f"{BASE}/{live.id}/network-interfaces", headers=await _superadmin(db_session)
        )
    ).json()
    assert [(i["name"], i["state"]) for i in mine["interfaces"]] == [
        (i["name"], i["state"]) for i in rest["interfaces"]
    ]
    assert {n["name"] for n in mine["nics"]} == {n["name"] for n in rest["nics"]}

    denied = await find_appliance_network_interfaces(
        db_session,
        await _tool_user(db_session, superadmin=False),
        FindApplianceNetworkInterfacesArgs(),
    )
    assert "superadmin" in denied["error"]


async def test_propose_tool_validates_like_rest_and_never_writes(db_session: AsyncSession) -> None:
    from app.services.ai.tools.appliance import (
        ProposeApplianceNetworkInterfacesArgs,
        propose_appliance_network_interfaces,
    )

    row = await _appliance(db_session)
    user = await _tool_user(db_session, superadmin=True)

    ok = await propose_appliance_network_interfaces(
        db_session,
        user,
        ProposeApplianceNetworkInterfacesArgs(appliance_id=str(row.id), interfaces=[_vlan()]),
    )
    assert ok["kind"] == "proposal"
    assert ok["interfaces"][0]["name"] == "ens19.100"

    for bad in (
        [_eth("ens18")],
        [_eth(routes=[{"destination": "0.0.0.0/0", "gateway": "10.9.0.1"}])],
    ):
        refused = await propose_appliance_network_interfaces(
            db_session,
            user,
            ProposeApplianceNetworkInterfacesArgs(appliance_id=str(row.id), interfaces=bad),
        )
        assert "error" in refused and "kind" not in refused

    unknown = await propose_appliance_network_interfaces(
        db_session,
        user,
        ProposeApplianceNetworkInterfacesArgs(appliance_id=str(uuid.uuid4()), interfaces=[]),
    )
    assert "error" in unknown

    denied = await propose_appliance_network_interfaces(
        db_session,
        await _tool_user(db_session, superadmin=False),
        ProposeApplianceNetworkInterfacesArgs(appliance_id=str(row.id), interfaces=[_vlan()]),
    )
    assert "superadmin" in denied["error"]

    await db_session.refresh(row)
    assert row.desired_network_interfaces == []
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action.like("appliance.network.%"))
            )
        )
        .scalars()
        .all()
    )
    assert audits == []
