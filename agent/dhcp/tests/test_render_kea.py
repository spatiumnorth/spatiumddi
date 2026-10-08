"""Golden-ish tests for the ConfigBundle → Kea JSON renderer.

Emphasis on non-negotiable: NTP servers MUST be emitted as DHCP option 42.
"""

from __future__ import annotations

import pytest

from spatium_dhcp_agent.render_kea import render


@pytest.fixture
def bundle() -> dict:
    return {
        "etag": "sha256:test",
        "schema_version": 1,
        "server": {"name": "dhcp1", "interfaces": ["eth0"]},
        "global_options": {
            "dns_servers": ["1.1.1.1", "9.9.9.9"],
            "ntp_servers": ["192.0.2.123", "192.0.2.124"],
            "domain_name": "example.com",
            "lease_time": 7200,
        },
        "subnets": [
            {
                "id": 1,
                "subnet": "192.0.2.0/24",
                "pools": [{"pool": "192.0.2.100 - 192.0.2.200"}],
                "options": {
                    "routers": ["192.0.2.1"],
                    "ntp_servers": ["192.0.2.5"],
                },
                "reservations": [
                    {
                        "hw_address": "aa:bb:cc:dd:ee:ff",
                        "ip_address": "192.0.2.50",
                        "hostname": "printer1",
                    }
                ],
                "valid_lifetime": 3600,
            }
        ],
        "client_classes": [
            {"name": "voip", "test": "substring(option[60].hex,0,12) == 'Cisco-Phone'"}
        ],
    }


def test_render_shape(bundle: dict) -> None:
    out = render(bundle)
    assert "Dhcp4" in out
    d = out["Dhcp4"]
    assert d["valid-lifetime"] == 7200
    assert d["subnet4"][0]["subnet"] == "192.0.2.0/24"
    assert d["subnet4"][0]["pools"] == [{"pool": "192.0.2.100 - 192.0.2.200"}]


def test_global_ntp_option_42_emitted(bundle: dict) -> None:
    """Non-negotiable: NTP via DHCP option 42 must be present."""
    out = render(bundle)
    opts = out["Dhcp4"]["option-data"]
    ntp = [o for o in opts if o["name"] == "ntp-servers"]
    assert len(ntp) == 1
    assert ntp[0]["code"] == 42
    assert "192.0.2.123" in ntp[0]["data"]
    assert "192.0.2.124" in ntp[0]["data"]


def test_per_subnet_ntp_option_42_emitted(bundle: dict) -> None:
    out = render(bundle)
    sub_opts = out["Dhcp4"]["subnet4"][0]["option-data"]
    ntp = [o for o in sub_opts if o["name"] == "ntp-servers"]
    assert len(ntp) == 1
    assert ntp[0]["code"] == 42
    assert ntp[0]["data"] == "192.0.2.5"


def test_reservations_rendered(bundle: dict) -> None:
    out = render(bundle)
    resv = out["Dhcp4"]["subnet4"][0]["reservations"]
    assert resv[0]["hw-address"] == "aa:bb:cc:dd:ee:ff"
    assert resv[0]["ip-address"] == "192.0.2.50"
    assert resv[0]["hostname"] == "printer1"


def _reservation_bundle(reservation: dict) -> dict:
    return {
        "etag": "sha256:test",
        "schema_version": 1,
        "server": {"name": "dhcp1", "interfaces": ["eth0"]},
        "global_options": {"lease_time": 7200},
        "subnets": [
            {
                "id": 1,
                "subnet": "192.0.2.0/24",
                "pools": [{"pool": "192.0.2.100 - 192.0.2.200"}],
                "reservations": [reservation],
                "valid_lifetime": 3600,
            }
        ],
    }


@pytest.mark.parametrize(
    "raw",
    [
        "aabb.ccdd.eeff",  # Cisco-dotted
        "aabbccddeeff",  # run-together
        "AA-BB-CC-DD-EE-FF",  # dashed + uppercase
        "AA:BB:CC:DD:EE:FF",  # colon but uppercase
    ],
)
def test_reservation_mac_normalized_to_kea_form(raw: str) -> None:
    # #476 — a reservation MAC entered non-canonically must be canonicalized to
    # Kea's lowercase colon form, else Kea rejects the whole subnet4 on reload
    # (or silently fails to match the client on-wire).
    out = render(_reservation_bundle({"hw_address": raw, "ip_address": "192.0.2.50"}))
    resv = out["Dhcp4"]["subnet4"][0]["reservations"]
    assert resv[0]["hw-address"] == "aa:bb:cc:dd:ee:ff"


def test_reservation_invalid_mac_dropped_not_emitted() -> None:
    # An unparseable MAC is dropped (with a warning) rather than emitted
    # malformed — a single bad row must not tank the whole Kea config. The
    # reservation still matches on client-id (#476).
    out = render(
        _reservation_bundle(
            {
                "hw_address": "not-a-mac",
                "ip_address": "192.0.2.50",
                "client_id": "01:02:03:04",
            }
        )
    )
    resv = out["Dhcp4"]["subnet4"][0]["reservations"]
    assert "hw-address" not in resv[0]
    assert resv[0]["client-id"] == "01:02:03:04"


def test_v6_reservation_mac_normalized() -> None:
    # #476 — the Dhcp6 reservation path (_reservation_v6) normalizes MACs too;
    # a non-canonical MAC would otherwise make Kea reject the whole subnet6.
    bundle = {
        "etag": "x",
        "server_name": "d",
        "driver": "kea",
        "roles": [],
        "scopes": [
            {
                "subnet_cidr": "2001:db8:0:1::/64",
                "lease_time": 4800,
                "address_family": "ipv6",
                "v6_address_mode": "stateful",
                "pools": [
                    {
                        "start_ip": "2001:db8:0:1::1000",
                        "end_ip": "2001:db8:0:1::2000",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [
                    {
                        "ip_address": "2001:db8:0:1::50",
                        "mac_address": "aabb.ccdd.eeff",  # Cisco-dotted
                        "hostname": "v6host",
                    }
                ],
                "ddns_enabled": False,
            }
        ],
    }
    out = render(bundle)
    resv = out["Dhcp6"]["subnet6"][0]["reservations"]
    assert resv[0]["hw-address"] == "aa:bb:cc:dd:ee:ff"


def test_client_classes_rendered(bundle: dict) -> None:
    out = render(bundle)
    cc = out["Dhcp4"]["client-classes"]
    assert cc[0]["name"] == "voip"
    assert "Cisco-Phone" in cc[0]["test"]


def test_control_socket_and_lease_paths_overrideable() -> None:
    out = render(
        {"server": {}, "subnets": []},
        control_socket="/tmp/sock",
        lease_file="/tmp/leases.csv",
    )
    assert out["Dhcp4"]["control-socket"]["socket-name"] == "/tmp/sock"
    assert out["Dhcp4"]["lease-database"]["name"] == "/tmp/leases.csv"


def test_lease_cmds_hook_enabled() -> None:
    out = render({"server": {}, "subnets": []})
    libs = [h["library"] for h in out["Dhcp4"]["hooks-libraries"]]
    assert any("libdhcp_lease_cmds.so" in lib for lib in libs)


# ── Canonical wire-shape (``scopes``) — the real payload agents receive ──


@pytest.fixture
def wire_bundle() -> dict:
    """Shape matches ``backend/app/api/v1/dhcp/agents.py`` serialization."""
    return {
        "etag": "sha256:test",
        "server_name": "dhcp-kea",
        "driver": "kea",
        "roles": [],
        "scopes": [
            {
                "subnet_cidr": "10.20.0.0/21",
                "lease_time": 3600,
                "options": {
                    "routers": ["10.20.0.1"],
                    "dns_servers": ["10.20.0.2"],
                },
                "pools": [
                    {
                        "start_ip": "10.20.0.10",
                        "end_ip": "10.20.7.254",
                        "pool_type": "dynamic",
                    },
                    {
                        "start_ip": "10.20.0.100",
                        "end_ip": "10.20.0.110",
                        "pool_type": "excluded",
                    },
                ],
                "statics": [
                    {
                        "ip_address": "10.20.0.50",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "hostname": "printer1",
                    }
                ],
                "ddns_enabled": False,
            }
        ],
        "client_classes": [
            {
                "name": "voip",
                "match_expression": "substring(option[60].hex,0,12) == 'Cisco-Phone'",
                "options": {},
            }
        ],
    }


def test_render_wire_shape_subnet_and_dynamic_pool(wire_bundle: dict) -> None:
    out = render(wire_bundle)
    subs = out["Dhcp4"]["subnet4"]
    assert len(subs) == 1
    assert subs[0]["subnet"] == "10.20.0.0/21"
    # id is a stable positive int derived from the CIDR
    assert isinstance(subs[0]["id"], int) and subs[0]["id"] > 0
    # Only the dynamic pool makes it through — excluded pools are
    # IPAM-level and must not become Kea lease pools.
    assert subs[0]["pools"] == [{"pool": "10.20.0.10 - 10.20.7.254"}]


def test_render_wire_shape_reservation_from_statics(wire_bundle: dict) -> None:
    out = render(wire_bundle)
    resv = out["Dhcp4"]["subnet4"][0]["reservations"]
    assert resv[0]["hw-address"] == "aa:bb:cc:dd:ee:ff"
    assert resv[0]["ip-address"] == "10.20.0.50"
    assert resv[0]["hostname"] == "printer1"


def test_reservation_omits_client_id_when_absent(wire_bundle: dict) -> None:
    # #537 — the wire ScopeDef path injects ``client_id: None`` for statics
    # with no client-id; the renderer must OMIT the key entirely rather than
    # emit ``"client-id": null``, which makes kea-dhcp4 reject the config on
    # reload ("unexpected null, expecting constant string").
    out = render(wire_bundle)
    resv = out["Dhcp4"]["subnet4"][0]["reservations"]
    assert "client-id" not in resv[0]


def test_reservation_emits_client_id_when_present(wire_bundle: dict) -> None:
    # A present client-id must still round-trip through the wire ScopeDef path.
    wire_bundle["scopes"][0]["statics"][0]["client_id"] = "01:aa:bb:cc:dd"
    out = render(wire_bundle)
    resv = out["Dhcp4"]["subnet4"][0]["reservations"]
    assert resv[0]["client-id"] == "01:aa:bb:cc:dd"


def test_render_wire_shape_client_class_match_expression(wire_bundle: dict) -> None:
    out = render(wire_bundle)
    cc = out["Dhcp4"]["client-classes"]
    assert cc[0]["name"] == "voip"
    assert "Cisco-Phone" in cc[0]["test"]


def test_render_wire_shape_subnet_id_is_stable() -> None:
    """Kea keys leases off subnet-id — the same CIDR must always hash
    to the same id across renders, otherwise a config reload would
    orphan every active lease."""
    bundle = {
        "scopes": [
            {
                "subnet_cidr": "192.0.2.0/24",
                "lease_time": 3600,
                "pools": [],
                "statics": [],
            }
        ]
    }
    out1 = render(bundle)
    out2 = render(bundle)
    assert out1["Dhcp4"]["subnet4"][0]["id"] == out2["Dhcp4"]["subnet4"][0]["id"]


# ── MAC blocklist → Kea DROP class ─────────────────────────────────


def test_mac_blocks_render_as_drop_class() -> None:
    """The wire carries ``mac_blocks``; the renderer must fold them into
    the reserved ``DROP`` client class as an OR-ed ``hexstring(pkt4.mac,
    ':')`` expression. That's the Kea-recommended way to drop a packet
    pre-allocation."""
    bundle = {
        "server": {"name": "t", "interfaces": ["eth0"]},
        "subnets": [{"id": 1, "subnet": "192.0.2.0/24", "pools": []}],
        "mac_blocks": [
            {"mac_address": "aa:bb:cc:dd:ee:ff", "reason": "rogue", "description": ""},
            {"mac_address": "11:22:33:44:55:66", "reason": "policy", "description": ""},
        ],
    }
    out = render(bundle)
    classes = out["Dhcp4"]["client-classes"]
    drop = [c for c in classes if c["name"] == "DROP"]
    assert len(drop) == 1, f"expected one DROP class, got {classes}"
    test_expr = drop[0]["test"]
    assert "aa:bb:cc:dd:ee:ff" in test_expr
    assert "11:22:33:44:55:66" in test_expr
    assert " or " in test_expr
    assert "hexstring(pkt4.mac, ':')" in test_expr


def test_no_drop_class_when_blocklist_empty() -> None:
    """An empty blocklist must not leak an empty DROP expression into
    Kea — that'd parse as "always false" but noise the config."""
    bundle = {
        "server": {"name": "t", "interfaces": ["eth0"]},
        "subnets": [{"id": 1, "subnet": "192.0.2.0/24", "pools": []}],
        "mac_blocks": [],
    }
    out = render(bundle)
    classes = out["Dhcp4"].get("client-classes", [])
    assert not any(c["name"] == "DROP" for c in classes)


def test_mac_blocklist_skips_invalid_entries() -> None:
    """A single malformed MAC shouldn't break rendering for the rest."""
    bundle = {
        "server": {"name": "t", "interfaces": ["eth0"]},
        "subnets": [{"id": 1, "subnet": "192.0.2.0/24", "pools": []}],
        "mac_blocks": [
            {"mac_address": "totally not a mac", "reason": "other", "description": ""},
            {"mac_address": "aa:bb:cc:dd:ee:ff", "reason": "rogue", "description": ""},
        ],
    }
    out = render(bundle)
    drop = next(c for c in out["Dhcp4"]["client-classes"] if c["name"] == "DROP")
    assert "aa:bb:cc:dd:ee:ff" in drop["test"]
    assert "totally" not in drop["test"]


def test_user_drop_class_not_clobbered() -> None:
    """If an operator manually defined a ``DROP`` client class, the
    renderer must not overwrite it with the blocklist-generated one."""
    bundle = {
        "server": {"name": "t", "interfaces": ["eth0"]},
        "subnets": [{"id": 1, "subnet": "192.0.2.0/24", "pools": []}],
        "client_classes": [
            {"name": "DROP", "match_expression": "option[60].hex == 'bad'"}
        ],
        "mac_blocks": [
            {"mac_address": "aa:bb:cc:dd:ee:ff", "reason": "rogue", "description": ""}
        ],
    }
    out = render(bundle)
    drops = [c for c in out["Dhcp4"]["client-classes"] if c["name"] == "DROP"]
    assert len(drops) == 1
    # The user's test expression wins; the blocklist is silently skipped.
    assert "option[60]" in drops[0]["test"]
    assert "aa:bb:cc:dd:ee:ff" not in drops[0]["test"]


# ── DHCPv6 — Dhcp6 / subnet6 render branch (issue #330) ────────────────


@pytest.fixture
def wire_bundle_v6() -> dict:
    """A v6 wire scope alongside a v4 scope — proves the renderer splits
    by ``address_family`` and emits a ``Dhcp6`` block with a ``subnet6``
    entry rather than folding the v6 prefixes into ``subnet4``."""
    return {
        "etag": "sha256:test-v6",
        "server_name": "dhcp-kea",
        "driver": "kea",
        "roles": [],
        "global_options": {"dns_servers": ["2001:db8::1"], "lease_time": 7200},
        "scopes": [
            {
                "subnet_cidr": "192.0.2.0/24",
                "lease_time": 3600,
                "address_family": "ipv4",
                "options": {"routers": ["192.0.2.1"]},
                "pools": [
                    {
                        "start_ip": "192.0.2.10",
                        "end_ip": "192.0.2.200",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
                "ddns_enabled": False,
            },
            {
                "subnet_cidr": "2001:db8:0:1::/64",
                "lease_time": 4800,
                "address_family": "ipv6",
                "v6_address_mode": "stateful",
                "options": {
                    "dns_servers": ["2001:db8::53"],
                    # v4-only option that must be dropped from the v6 scope.
                    "routers": ["2001:db8::1"],
                },
                "pools": [
                    {
                        "start_ip": "2001:db8:0:1::1000",
                        "end_ip": "2001:db8:0:1::2000",
                        "pool_type": "dynamic",
                    },
                    {
                        "start_ip": "2001:db8:0:1::ff00",
                        "end_ip": "2001:db8:0:1::ffff",
                        "pool_type": "excluded",
                    },
                ],
                "statics": [
                    {
                        "ip_address": "2001:db8:0:1::50",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "hostname": "v6host",
                    }
                ],
                "ddns_enabled": False,
            },
        ],
    }


def test_v6_scope_renders_dhcp6_not_subnet4(wire_bundle_v6: dict) -> None:
    out = render(wire_bundle_v6)
    # v4 scope stays in subnet4 …
    subs4 = out["Dhcp4"]["subnet4"]
    assert [s["subnet"] for s in subs4] == ["192.0.2.0/24"]
    # … and the v6 scope lands in a Dhcp6/subnet6 entry, NOT subnet4.
    assert "Dhcp6" in out
    subs6 = out["Dhcp6"]["subnet6"]
    assert [s["subnet"] for s in subs6] == ["2001:db8:0:1::/64"]
    # No v6 prefix leaked into the Dhcp4 block.
    assert all("2001:db8" not in s["subnet"] for s in subs4)


def test_v6_subnet6_pools_and_reservation_shape(wire_bundle_v6: dict) -> None:
    out = render(wire_bundle_v6)
    sub6 = out["Dhcp6"]["subnet6"][0]
    # Only the dynamic pool survives — the excluded range is IPAM-level.
    assert sub6["pools"] == [{"pool": "2001:db8:0:1::1000 - 2001:db8:0:1::2000"}]
    # Dhcp6 reservations use ``ip-addresses`` (plural list), not ip-address.
    resv = sub6["reservations"][0]
    assert resv["ip-addresses"] == ["2001:db8:0:1::50"]
    assert "ip-address" not in resv
    assert resv["hw-address"] == "aa:bb:cc:dd:ee:ff"
    assert resv["hostname"] == "v6host"
    # stable positive subnet id, same hashing as v4.
    assert isinstance(sub6["id"], int) and sub6["id"] > 0


def test_v6_options_use_v6_names_and_drop_v4_only(wire_bundle_v6: dict) -> None:
    out = render(wire_bundle_v6)
    opts = out["Dhcp6"]["subnet6"][0]["option-data"]
    names = {o["name"] for o in opts}
    # dns-servers maps to the Dhcp6 ``dns-servers`` name …
    assert "dns-servers" in names
    dns = next(o for o in opts if o["name"] == "dns-servers")
    assert dns["data"] == "2001:db8::53"
    # … and ``routers`` (no DHCPv6 equivalent) is dropped, not emitted.
    assert "routers" not in names
    # No v4 ``code``/``space`` shape leaked in (those are v4-only).
    assert all(o.get("space") != "dhcp4" for o in opts)


def test_v6_separate_socket_and_lease_paths(wire_bundle_v6: dict) -> None:
    """The Dhcp6 daemon must not share the Dhcp4 socket / lease store."""
    out = render(
        wire_bundle_v6,
        control_socket="/run/kea/kea4-ctrl-socket",
        lease_file="/var/lib/kea/kea-leases4.csv",
    )
    assert out["Dhcp4"]["control-socket"]["socket-name"] == "/run/kea/kea4-ctrl-socket"
    assert out["Dhcp6"]["control-socket"]["socket-name"] == "/run/kea/kea6-ctrl-socket"
    assert out["Dhcp4"]["lease-database"]["name"] == "/var/lib/kea/kea-leases4.csv"
    assert out["Dhcp6"]["lease-database"]["name"] == "/var/lib/kea/kea-leases6.csv"


def test_dhcp6_idle_skeleton_always_emitted(wire_bundle: dict) -> None:
    """The agent runs kea-dhcp6 always-on (dual-stack), so a pure-v4
    bundle must still render a VALID idle Dhcp6 skeleton — binds nothing
    (``interfaces: []``), empty ``subnet6``, its own v6 control socket +
    lease store, and no stray global option-data / client-classes that
    could make kea-dhcp6 -t reject."""
    out = render(wire_bundle)
    assert "Dhcp4" in out
    assert "Dhcp6" in out
    d6 = out["Dhcp6"]
    # Idle skeleton binds no interfaces — safe on IPv6-less hosts.
    assert d6["interfaces-config"]["interfaces"] == []
    assert d6["subnet6"] == []
    # Distinct v6 socket + lease store.
    assert d6["control-socket"]["socket-name"] == "/run/kea/kea6-ctrl-socket"
    assert d6["lease-database"]["name"] == "/var/lib/kea/kea-leases6.csv"
    # No global option-data / client-classes leaked onto the idle skeleton.
    assert "option-data" not in d6
    assert "client-classes" not in d6


def test_dhcp6_idle_skeleton_for_empty_bundle() -> None:
    """Even a totally empty bundle renders a valid idle Dhcp6 block."""
    out = render({"server": {}, "subnets": []})
    assert out["Dhcp6"]["subnet6"] == []
    assert out["Dhcp6"]["interfaces-config"]["interfaces"] == []
    # The lease_cmds hook is loaded so the daemon starts cleanly.
    libs = [h["library"] for h in out["Dhcp6"]["hooks-libraries"]]
    assert any("libdhcp_lease_cmds.so" in lib for lib in libs)


def test_dhcp6_control_socket_override_on_idle_skeleton() -> None:
    """The idle skeleton must honour the explicit v6 control-socket
    override (sync.py passes the configured path)."""
    out = render(
        {"server": {}, "subnets": []},
        control_socket="/run/kea/kea4-ctrl-socket",
        control_socket_v6="/custom/kea6.sock",
        lease_file_v6="/custom/leases6.csv",
    )
    assert out["Dhcp6"]["control-socket"]["socket-name"] == "/custom/kea6.sock"
    assert out["Dhcp6"]["lease-database"]["name"] == "/custom/leases6.csv"


def test_v6_slaac_mode_serves_no_pools_or_options() -> None:
    """A SLAAC v6 scope is a no-DHCP-role subnet: no pools, no
    option-data, no reservations (the router's RA does it all)."""
    bundle = {
        "scopes": [
            {
                "subnet_cidr": "2001:db8:0:2::/64",
                "lease_time": 3600,
                "address_family": "ipv6",
                "v6_address_mode": "slaac",
                "options": {"dns_servers": ["2001:db8::53"]},
                "pools": [
                    {
                        "start_ip": "2001:db8:0:2::10",
                        "end_ip": "2001:db8:0:2::20",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [
                    {
                        "ip_address": "2001:db8:0:2::5",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "hostname": "x",
                    }
                ],
            }
        ],
    }
    sub6 = render(bundle)["Dhcp6"]["subnet6"][0]
    assert "pools" not in sub6
    assert "option-data" not in sub6
    assert "reservations" not in sub6


def test_v6_stateless_mode_serves_options_only() -> None:
    """A stateless v6 scope serves option-data (Information-Request) but
    no address pools."""
    bundle = {
        "scopes": [
            {
                "subnet_cidr": "2001:db8:0:3::/64",
                "lease_time": 3600,
                "address_family": "ipv6",
                "v6_address_mode": "stateless",
                "options": {"dns_servers": ["2001:db8::53"]},
                "pools": [
                    {
                        "start_ip": "2001:db8:0:3::10",
                        "end_ip": "2001:db8:0:3::20",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
            }
        ],
    }
    sub6 = render(bundle)["Dhcp6"]["subnet6"][0]
    assert "pools" not in sub6
    assert sub6["option-data"][0]["name"] == "dns-servers"


# ── DHCP relay-agent matching (issue #337) ─────────────────────────────


def test_v4_scope_emits_relay_ip_addresses() -> None:
    """A v4 scope with ``relay_addresses`` renders Kea's
    ``relay: {"ip-addresses": [...]}`` so a centralized server selects
    the subnet for relayed (giaddr-stamped) traffic."""
    bundle = {
        "scopes": [
            {
                "subnet_cidr": "10.50.0.0/24",
                "lease_time": 3600,
                "pools": [
                    {
                        "start_ip": "10.50.0.10",
                        "end_ip": "10.50.0.50",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
                "relay_addresses": ["10.50.0.1", "192.0.2.250"],
            }
        ],
    }
    sub4 = render(bundle)["Dhcp4"]["subnet4"][0]
    assert sub4["relay"] == {"ip-addresses": ["10.50.0.1", "192.0.2.250"]}


def test_v6_scope_emits_relay_ip_addresses() -> None:
    bundle = {
        "scopes": [
            {
                "subnet_cidr": "2001:db8:337::/64",
                "lease_time": 3600,
                "address_family": "ipv6",
                "v6_address_mode": "stateful",
                "pools": [
                    {
                        "start_ip": "2001:db8:337::10",
                        "end_ip": "2001:db8:337::20",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
                "relay_addresses": ["2001:db8:337::1"],
            }
        ],
    }
    sub6 = render(bundle)["Dhcp6"]["subnet6"][0]
    assert sub6["relay"] == {"ip-addresses": ["2001:db8:337::1"]}


def test_no_relay_block_when_unset() -> None:
    bundle = {
        "scopes": [
            {
                "subnet_cidr": "10.50.0.0/24",
                "lease_time": 3600,
                "pools": [],
                "statics": [],
            }
        ],
    }
    assert "relay" not in render(bundle)["Dhcp4"]["subnet4"][0]


def test_legacy_subnets_relay_ips_still_render() -> None:
    """The pre-canonical ``subnets`` wire shape carries ``relay_ips`` —
    keep that path working for hand-crafted bundles / fixtures."""
    bundle = {
        "server": {"name": "t", "interfaces": ["eth0"]},
        "subnets": [
            {"id": 1, "subnet": "10.60.0.0/24", "pools": [], "relay_ips": ["10.60.0.1"]}
        ],
    }
    assert render(bundle)["Dhcp4"]["subnet4"][0]["relay"] == {
        "ip-addresses": ["10.60.0.1"]
    }


# ── Kea lease cache (#637) ─────────────────────────────────────────────


def _lc_bundle(
    *,
    group_threshold: float | None = None,
    group_max_age: int | None = None,
    scope_threshold: float | None = None,
    scope_max_age: int | None = None,
) -> dict:
    """Wire bundle carrying the lease-cache keys agents.py now serializes."""
    server: dict = {"interfaces": ["*"], "dhcp_socket_type": "raw"}
    if group_threshold is not None:
        server["lease_cache_threshold"] = group_threshold
    if group_max_age is not None:
        server["lease_cache_max_age"] = group_max_age
    return {
        "server": server,
        "scopes": [
            {
                "subnet_cidr": "10.37.0.0/24",
                "lease_time": 3600,
                "pools": [
                    {
                        "start_ip": "10.37.0.10",
                        "end_ip": "10.37.0.99",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
                "lease_cache_threshold": scope_threshold,
                "lease_cache_max_age": scope_max_age,
            }
        ],
    }


def test_lease_cache_defaults_to_explicit_zero() -> None:
    """Kea 3.0 defaults cache-threshold to 0.25. The renderer must emit an
    explicit 0.0 rather than omitting the key, or upgrading installs silently
    start caching leases — which suppresses the memfile writes that drive
    lease-events → DDNS + the IPAM lease mirror."""
    out = render(_lc_bundle())
    assert out["Dhcp4"]["cache-threshold"] == 0.0
    assert out["Dhcp6"]["cache-threshold"] == 0.0


def test_lease_cache_group_threshold_renders() -> None:
    out = render(_lc_bundle(group_threshold=0.25))
    assert out["Dhcp4"]["cache-threshold"] == 0.25


def test_lease_cache_group_max_age_renders_when_set() -> None:
    out = render(_lc_bundle(group_threshold=0.25, group_max_age=900))
    assert out["Dhcp4"]["cache-max-age"] == 900
    assert out["Dhcp6"]["cache-max-age"] == 900


def test_lease_cache_group_max_age_absent_when_unset() -> None:
    out = render(_lc_bundle(group_threshold=0.25))
    assert "cache-max-age" not in out["Dhcp4"]


def test_lease_cache_scope_without_override_inherits_group() -> None:
    out = render(_lc_bundle(group_threshold=0.25))
    assert "cache-threshold" not in out["Dhcp4"]["subnet4"][0]


def test_lease_cache_scope_override_renders() -> None:
    out = render(_lc_bundle(group_threshold=0.25, scope_threshold=0.5))
    assert out["Dhcp4"]["subnet4"][0]["cache-threshold"] == 0.5


def test_lease_cache_scope_override_of_zero_survives() -> None:
    """0.0 is a REAL value (caching explicitly off for this scope) while the
    group has it on. ``if scope.get(...)`` truthiness would drop it and the
    scope would silently inherit the group's 0.25 — the exact bug this guards."""
    out = render(_lc_bundle(group_threshold=0.25, scope_threshold=0.0))
    assert out["Dhcp4"]["subnet4"][0]["cache-threshold"] == 0.0


def test_lease_cache_scope_max_age_override_renders() -> None:
    out = render(_lc_bundle(group_threshold=0.25, scope_threshold=0.5, scope_max_age=120))
    assert out["Dhcp4"]["subnet4"][0]["cache-max-age"] == 120


# ── Renew / rebind timers (#1259) ──────────────────────────────────────


def _keys(node: object) -> set[str]:
    """Every dict key anywhere in a rendered document."""
    if isinstance(node, dict):
        return set(node) | {k for v in node.values() for k in _keys(v)}
    if isinstance(node, list):
        return {k for v in node for k in _keys(v)}
    return set()


def _dual_stack_bundle() -> dict:
    return {
        "server": {"interfaces": ["*"], "dhcp_socket_type": "raw"},
        "global_options": {"lease_time": 86400},
        "scopes": [
            {
                "subnet_cidr": "10.38.0.0/24",
                "lease_time": 86400,
                "pools": [
                    {"start_ip": "10.38.0.10", "end_ip": "10.38.0.99", "pool_type": "dynamic"}
                ],
                "statics": [],
            },
            {
                "subnet_cidr": "2001:db8:38::/64",
                "lease_time": 86400,
                "address_family": "ipv6",
                "v6_address_mode": "stateful",
                "pools": [
                    {
                        "start_ip": "2001:db8:38::100",
                        "end_ip": "2001:db8:38::1ff",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
            },
        ],
    }


def test_no_fixed_renew_or_rebind_timer_is_rendered() -> None:
    """The roots used to pin T1/T2 to 900/1800 s whatever the lease time,
    so a 1-day lease renewed every 15 minutes. Kea prefers explicit timers
    over calculated ones and subnets inherit them, so ANY renew/rebind timer
    above the subnet level would switch the calculation off again."""
    out = render(_dual_stack_bundle())
    for family in ("Dhcp4", "Dhcp6"):
        keys = _keys(out[family])
        assert "renew-timer" not in keys, family
        assert "rebind-timer" not in keys, family


def test_v4_tee_times_are_calculated_from_the_lease() -> None:
    """kea-dhcp4 defaults ``calculate-tee-times`` to false and then sends no
    T1/T2 options at all, so it has to be switched on. RFC 2131 §4.4.5."""
    d4 = render(_dual_stack_bundle())["Dhcp4"]
    assert d4["calculate-tee-times"] is True
    assert d4["t1-percent"] == 0.5
    assert d4["t2-percent"] == 0.875


def test_v6_tee_times_are_calculated_from_the_lease() -> None:
    """RFC 8415 recommends 0.5 / 0.8 (also Kea's own v6 default)."""
    d6 = render(_dual_stack_bundle())["Dhcp6"]
    assert d6["calculate-tee-times"] is True
    assert d6["t1-percent"] == 0.5
    assert d6["t2-percent"] == 0.8


def test_idle_v6_skeleton_also_has_no_fixed_timers() -> None:
    out = render(_lc_bundle())
    assert out["Dhcp6"]["subnet6"] == []
    assert "renew-timer" not in out["Dhcp6"]
    assert out["Dhcp6"]["calculate-tee-times"] is True


def test_explicit_per_subnet_timers_still_render(bundle: dict) -> None:
    """The legacy subnet shape can carry explicit timers. They stay on the
    subnet (where Kea lets them win over the calculation for that subnet
    only) and never leak onto the root."""
    bundle["subnets"][0]["renew_timer"] = 600
    bundle["subnets"][0]["rebind_timer"] = 1050
    d4 = render(bundle)["Dhcp4"]
    assert d4["subnet4"][0]["renew-timer"] == 600
    assert d4["subnet4"][0]["rebind-timer"] == 1050
    assert "renew-timer" not in d4
    assert "rebind-timer" not in d4
    assert d4["calculate-tee-times"] is True
