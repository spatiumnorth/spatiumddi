"""#858 — things the control plane models but the agent never rendered.

Pool option overrides, pool class restrictions, PXE classes and phone-profile
classes were all assembled into the ConfigBundle and rendered by the
control-plane driver, but either never reached the wire payload or were never
read here. Every one failed silently: the UI showed the value, the ETag moved
when it changed so agents even re-synced, and the rendered config came out
identical.

Kea behaviour asserted below was measured against kea-dhcp4 3.0.3, not
assumed — in particular that a raw ``code:NN`` option is typed BINARY, so a
string value fails the WHOLE config without a matching ``option-def``.
"""

from __future__ import annotations

from spatium_dhcp_agent.render_kea import (
    _dynamic_pool,
    _options_from_mapping,
    _phone_class,
    _pxe_class,
    render,
)


def _bundle(**over: object) -> dict:
    base: dict = {
        "server": {"dhcp_socket_type": "raw"},
        "global_options": {"lease_time": 3600},
        "scopes": [
            {
                "subnet_cidr": "192.168.20.0/24",
                "address_family": "ipv4",
                "is_active": True,
                "lease_time": 3600,
                "options": {"routers": ["192.168.20.254"]},
                "pools": [
                    {
                        "start_ip": "192.168.20.100",
                        "end_ip": "192.168.20.200",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
            }
        ],
    }
    base.update(over)  # type: ignore[arg-type]
    return base


# ── Pool-level overrides ────────────────────────────────────────────────────


def test_pool_options_override_renders() -> None:
    p = _dynamic_pool(
        {
            "start_ip": "10.0.0.10",
            "end_ip": "10.0.0.20",
            "options_override": {"dns-servers": ["10.9.9.9"]},
        },
        address_family="ipv4",
    )
    assert p["option-data"] == [
        {"name": "domain-name-servers", "data": "10.9.9.9", "code": 6, "space": "dhcp4"}
    ]


def test_pool_class_restriction_renders() -> None:
    """Shipped on the wire since #368 but only honoured for v6 PD pools, so a
    class-restricted address pool served EVERY client."""
    p = _dynamic_pool(
        {"start_ip": "10.0.0.10", "end_ip": "10.0.0.20", "class_restriction": "pxe-uefi"},
        address_family="ipv4",
    )
    assert p["client-class"] == "pxe-uefi"


def test_plain_pool_is_unchanged() -> None:
    """A pool with neither override still renders exactly as before."""
    assert _dynamic_pool(
        {"start_ip": "10.0.0.10", "end_ip": "10.0.0.20"}, address_family="ipv4"
    ) == {"pool": "10.0.0.10 - 10.0.0.20"}


# ── PXE + phone classes ─────────────────────────────────────────────────────


def test_pxe_class_renders_boot_fields() -> None:
    c = _pxe_class(
        {
            "name": "pxe-uefi",
            "match_expression": "option[93].hex == 0x0007",
            "next_server": "10.0.0.5",
            "boot_file_name": "ipxe.efi",
        }
    )
    assert c == {
        "name": "pxe-uefi",
        "next-server": "10.0.0.5",
        "boot-file-name": "ipxe.efi",
        "test": "option[93].hex == 0x0007",
    }


def test_pxe_class_without_match_omits_test() -> None:
    """An empty match means 'always match'; Kea rejects an empty ``test``."""
    assert "test" not in _pxe_class(
        {"name": "fallback", "match_expression": "", "next_server": "", "boot_file_name": "x"}
    )


def test_phone_class_renders_vendor_codes() -> None:
    c = _phone_class(
        {
            "name": "voip-abc",
            "match_expression": "substring(option[60].hex,0,5) == 'Cisco'",
            "options": {"code:160": "http://prov/cfg"},
        }
    )
    assert c["option-data"] == [{"code": 160, "data": "http://prov/cfg"}]


def test_classes_render_in_driver_order() -> None:
    """Kea evaluates client-classes in declaration order, so this is
    behaviour: operator classes, then PXE, then phone."""
    doc = render(
        _bundle(
            client_classes=[{"name": "op", "match_expression": "x"}],
            pxe_classes=[
                {"name": "pxe", "match_expression": "y", "next_server": "", "boot_file_name": "b"}
            ],
            phone_classes=[{"name": "voip", "match_expression": "z", "options": {}}],
        )
    )["Dhcp4"]
    assert [c["name"] for c in doc["client-classes"]] == ["op", "pxe", "voip"]


# ── Raw code options + the definitions they need ────────────────────────────


def test_code_keyed_option_renders_by_code() -> None:
    assert _options_from_mapping({"code:242": "MCIPADD=10.0.0.1"}) == [
        {"code": 242, "data": "MCIPADD=10.0.0.1"}
    ]


def test_code_keyed_list_value_is_joined() -> None:
    assert _options_from_mapping({"code:150": ["10.0.0.1", "10.0.0.2"]}) == [
        {"code": 150, "data": "10.0.0.1, 10.0.0.2"}
    ]


def test_malformed_code_key_is_skipped() -> None:
    assert _options_from_mapping({"code:abc": "x"}) == []


def test_control_plane_option_defs_are_emitted() -> None:
    """The agent cannot type a raw code itself — the catalogues live in the
    backend — so it emits what the control plane resolved."""
    doc = render(
        _bundle(
            option_defs=[
                {"name": "spatium-opt-242", "code": 242, "space": "dhcp4", "type": "string"}
            ],
            phone_classes=[
                {"name": "voip", "match_expression": "z", "options": {"code:242": "MCIPADD=1"}}
            ],
        )
    )["Dhcp4"]
    assert doc["option-def"] == [
        {"name": "spatium-opt-242", "code": 242, "space": "dhcp4", "type": "string"}
    ]


def test_option_defs_are_deduplicated_by_code() -> None:
    """Kea rejects two definitions for one code, so a def supplied both by the
    agent's own table and by the control plane must be emitted once."""
    doc = render(
        _bundle(
            option_defs=[
                {
                    "name": "tftp-server-address",
                    "code": 150,
                    "space": "dhcp4",
                    "type": "ipv4-address",
                    "array": True,
                }
            ],
            scopes=[
                {
                    "subnet_cidr": "192.168.20.0/24",
                    "address_family": "ipv4",
                    "is_active": True,
                    "lease_time": 3600,
                    "options": {"tftp-server-address": ["10.0.0.5"]},
                    "pools": [],
                    "statics": [],
                }
            ],
        )
    )["Dhcp4"]
    assert [d["code"] for d in doc["option-def"]] == [150]


def test_no_option_def_key_when_none_needed() -> None:
    assert "option-def" not in render(_bundle())["Dhcp4"]


# ── Review fixes: an undefined raw code must never reach Kea ────────────────


def test_undefined_code_is_stripped_not_emitted() -> None:
    """Emitting a code with no definition fails the WHOLE config — Kea types it
    BINARY and rejects a non-hex value. Dropping one option is survivable; a
    rejected config is not, and sync.py writes the file before kea-dhcp4 -t, so
    a bad render outlives the process that made it."""
    doc = render(
        _bundle(
            phone_classes=[
                {"name": "voip", "match_expression": "z", "options": {"code:242": "MCIPADD=1"}}
            ]
        )
    )["Dhcp4"]
    assert doc["client-classes"][0]["option-data"] == []
    assert "option-def" not in doc


def test_defined_code_survives_the_strip() -> None:
    doc = render(
        _bundle(
            option_defs=[
                {"name": "spatium-opt-242", "code": 242, "space": "dhcp4", "type": "string"}
            ],
            phone_classes=[
                {"name": "voip", "match_expression": "z", "options": {"code:242": "MCIPADD=1"}}
            ],
        )
    )["Dhcp4"]
    assert doc["client-classes"][0]["option-data"] == [{"code": 242, "data": "MCIPADD=1"}]


def test_named_options_are_never_stripped() -> None:
    """Named entries reference Kea built-ins and carry a code for resilience;
    the strip must not mistake them for undefined raw codes."""
    doc = render(
        _bundle(
            scopes=[
                {
                    "subnet_cidr": "192.168.20.0/24",
                    "address_family": "ipv4",
                    "is_active": True,
                    "lease_time": 3600,
                    "options": {"dns-servers": ["1.1.1.1"], "routers": ["1.1.1.254"]},
                    "pools": [],
                    "statics": [],
                }
            ]
        )
    )["Dhcp4"]
    names = {e["name"] for e in doc["subnet4"][0]["option-data"]}
    assert names == {"domain-name-servers", "routers"}


def test_cached_bundle_without_defs_degrades_safely() -> None:
    """A last-known-good bundle written before #858 carries no option_defs.
    The agent must keep serving (non-negotiable #5), not render a config Kea
    refuses."""
    doc = render(
        _bundle(
            phone_classes=[
                {"name": "voip", "match_expression": "z", "options": {"code:160": "http://x"}}
            ]
        )
    )["Dhcp4"]
    assert doc["client-classes"][0]["option-data"] == []


# ── Review fixes: PXE next-server validation ────────────────────────────────


def test_pxe_next_server_hostname_is_omitted() -> None:
    """Kea rejects the whole config on a non-IP next-server; falling back to
    the scope value serves a lease with a wrong boot server rather than no
    DHCP at all."""
    c = _pxe_class(
        {
            "name": "pxe",
            "match_expression": "",
            "next_server": "tftp.example.com",
            "boot_file_name": "b",
        }
    )
    assert "next-server" not in c


def test_pxe_next_server_ip_is_kept() -> None:
    c = _pxe_class(
        {"name": "pxe", "match_expression": "", "next_server": "10.0.0.5", "boot_file_name": "b"}
    )
    assert c["next-server"] == "10.0.0.5"


# ── #700 device-policy classes ────────────────────────────────────


def test_device_policy_class_renders_with_lease_time() -> None:
    """The per-class ``valid-lifetime`` is the "short leases for unknown
    devices" half of #700's NAC-lite outcome. Kea honours it per class —
    checked against kea-dhcp4 3.0.3, because a silently-ignored lease time
    is the difference between a quarantine that expires and one that does
    not."""
    out = render(
        _bundle(
            device_policy_classes=[
                {
                    "name": "spatium-device-IoT",
                    "match_expression": "option[55].hex == 0x010306",
                    "options": {"dns-servers": "10.0.0.53"},
                    "lease_time": 600,
                }
            ]
        )
    )
    classes = out["Dhcp4"]["client-classes"]
    cls = next(c for c in classes if c["name"] == "spatium-device-IoT")
    assert cls["test"] == "option[55].hex == 0x010306"
    assert cls["valid-lifetime"] == 600
    assert cls["option-data"]


def test_device_policy_class_without_test_is_dropped_not_rendered() -> None:
    """A Kea client-class with no ``test`` matches EVERY packet.

    The control plane already drops these, so arriving here means a
    hand-crafted or truncated bundle. Rendering it would hand a quarantine
    option set and lease time to the whole network, so the only safe
    reading is to fail closed."""
    out = render(
        _bundle(
            device_policy_classes=[
                {"name": "no-test", "match_expression": "", "lease_time": 300}
            ]
        )
    )
    names = [c["name"] for c in out["Dhcp4"].get("client-classes", [])]
    assert "no-test" not in names


def test_device_policy_classes_do_not_leak_into_dhcp6() -> None:
    """Options 55 and 60 are DHCPv4 option codes; under Dhcp6 those numbers
    address entirely different options. The v6 branch builds its class list
    from the generic ``client_classes`` alone — same as the v4-only DROP
    class."""
    bundle = _bundle(
        device_policy_classes=[
            {
                "name": "spatium-device-IoT",
                "match_expression": "option[55].hex == 0x010306",
                "lease_time": 600,
            }
        ]
    )
    bundle["scopes"] = list(bundle["scopes"]) + [
        {
            "subnet_cidr": "2001:db8::/64",
            "address_family": "ipv6",
            "is_active": True,
            "lease_time": 3600,
            "options": {},
            "pools": [],
            "statics": [],
        }
    ]
    out = render(bundle)
    v6_classes = out.get("Dhcp6", {}).get("client-classes", [])
    assert "spatium-device-IoT" not in [c["name"] for c in v6_classes]
