"""#1229 / #1295 — a client class renders only into its family's daemon.

A ``pkt4`` / ``relay4`` test makes kea-dhcp6 reject the whole config (and
``pkt6`` / ``relay6`` does the same to kea-dhcp4), and the agent then reverts
the bundle for BOTH daemons. A ``dual`` class's options arrive split per
family, because ``dns-servers`` is an IPv4 list in Dhcp4 and IPv6 in Dhcp6.
"""

from __future__ import annotations

from spatium_dhcp_agent.render_kea import render


def _bundle(classes: list[dict]) -> dict:
    return {
        "server": {"dhcp_socket_type": "raw"},
        "global_options": {"lease_time": 3600},
        "scopes": [
            {
                "subnet_cidr": "10.29.0.0/24",
                "address_family": "ipv4",
                "is_active": True,
                "lease_time": 3600,
                "options": {},
                "pools": [
                    {"start_ip": "10.29.0.100", "end_ip": "10.29.0.200", "pool_type": "dynamic"}
                ],
                "statics": [],
            },
            {
                "subnet_cidr": "2001:db8:1229::/64",
                "address_family": "ipv6",
                "is_active": True,
                "lease_time": 3600,
                "options": {},
                "pools": [
                    {
                        "start_ip": "2001:db8:1229::10",
                        "end_ip": "2001:db8:1229::20",
                        "pool_type": "dynamic",
                    }
                ],
                "statics": [],
            },
        ],
        "client_classes": classes,
    }


def _names(out: dict, block: str) -> set[str]:
    return {c["name"] for c in out[block].get("client-classes", [])}


def test_each_daemon_gets_only_its_family() -> None:
    out = render(
        _bundle(
            [
                {
                    "name": "relay82",
                    "match_expression": "relay4[1].hex == 'sw1'",
                    "address_family": "ipv4",
                    "options": {"routers": ["10.29.0.1"]},
                    "options_v4": {"routers": ["10.29.0.1"]},
                    "options_v6": {},
                },
                {
                    "name": "v6only",
                    "match_expression": "pkt6.msgtype == 1",
                    "address_family": "ipv6",
                    "options": {"dns-servers": ["2001:db8::53"]},
                    "options_v4": {},
                    "options_v6": {"dns-servers": ["2001:db8::53"]},
                },
                {
                    "name": "known",
                    "match_expression": "member('KNOWN')",
                    "address_family": "dual",
                    "options": {"dns-servers": ["10.29.0.53"], "domain-search": ["corp.example"]},
                    "options_v4": {
                        "dns-servers": ["10.29.0.53"],
                        "domain-search": ["corp.example"],
                    },
                    "options_v6": {"domain-search": ["corp.example"]},
                },
            ]
        )
    )
    assert _names(out, "Dhcp4") == {"relay82", "known"}
    assert _names(out, "Dhcp6") == {"v6only", "known"}
    known6 = next(c for c in out["Dhcp6"]["client-classes"] if c["name"] == "known")
    # The IPv4 DNS server never reaches Dhcp6 (#1295).
    assert [o["name"] for o in known6["option-data"]] == ["domain-search"]


def test_a_bundle_from_an_older_control_plane_renders_as_before() -> None:
    """No ``address_family`` on the wire: the class goes into both daemons with
    one options map, which is what every agent did before #1229."""
    out = render(
        _bundle(
            [
                {
                    "name": "legacy",
                    "match_expression": "member('KNOWN')",
                    "options": {"domain-search": ["corp.example"]},
                }
            ]
        )
    )
    assert _names(out, "Dhcp4") == {"legacy"}
    assert _names(out, "Dhcp6") == {"legacy"}


def test_a_family_with_no_classes_emits_no_empty_list() -> None:
    out = render(
        _bundle(
            [
                {
                    "name": "v4",
                    "match_expression": "pkt4.mac == 0x01",
                    "address_family": "ipv4",
                    "options": {},
                    "options_v4": {},
                    "options_v6": {},
                }
            ]
        )
    )
    assert "client-classes" not in out["Dhcp6"]
