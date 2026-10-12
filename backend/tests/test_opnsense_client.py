"""Unit tests for the OPNsense client's parse helpers + HTTP behaviour.

The pure-function helpers (``_unwrap_rows`` / ``_network_cidr`` /
``_normalise_mac``) are tested directly; the HTTP surface is exercised
through ``httpx.MockTransport``.

**Every JSON fixture below is a real response shape**, not an assumed
one. That distinction is the whole point of this file's rewrite in
#797: the previous version documented its shapes as "assumed ... because
we can't hit a real box", and the assumption was wrong. The interface
fixture in particular described a flat ``{"lan": {"ipaddr": "10.0.0.1",
"subnet": "24"}}`` that ``getInterfaceConfig`` has never returned, so
the parser and its tests agreed with each other and disagreed with every
OPNsense firewall in existence — a green test suite over an integration
that mirrored nothing.

Sources for the shapes used here:

* ``interfaces/overview/export`` — OPNsense/Interfaces OverviewController
* ``diagnostics/interface/getInterfaceConfig`` — passthrough of configd
  ``interface list ifconfig``; the sample is the one captured from
  OPNsense 26.1.11 in the #797 report
* ``kea/leases4/search`` — Kea Leases4Controller
* ``kea/dhcpv4/searchReservation`` — KeaDhcpv4 model
* ``dnsmasq/leases/search`` + ``dnsmasq/settings/searchHost`` — Dnsmasq
  LeasesController / SettingsController
* ``dhcpv4/*`` — legacy ISC dhcpd (core ≤25.1, plugin on 25.7+)
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.services.opnsense.client import (
    OPNsenseClient,
    OPNsenseClientError,
    _interfaces_from_ifconfig,
    _interfaces_from_overview,
    _network_cidr,
    _normalise_mac,
    _unwrap_rows,
)

# ── _unwrap_rows ──────────────────────────────────────────────────────


def test_unwrap_rows_envelope() -> None:
    assert _unwrap_rows({"rows": [{"a": 1}, {"b": 2}], "total": 2}) == [{"a": 1}, {"b": 2}]


def test_unwrap_rows_bare_list() -> None:
    assert _unwrap_rows([{"a": 1}]) == [{"a": 1}]


def test_unwrap_rows_keyed_dict() -> None:
    out = _unwrap_rows({"0": {"a": 1}, "1": {"b": 2}})
    assert {"a": 1} in out and {"b": 2} in out


def test_unwrap_rows_drops_non_dict_members() -> None:
    assert _unwrap_rows({"rows": [{"a": 1}, "junk", 7]}) == [{"a": 1}]


def test_unwrap_rows_garbage_returns_empty() -> None:
    assert _unwrap_rows(None) == []
    assert _unwrap_rows("nope") == []


# ── _network_cidr ─────────────────────────────────────────────────────


def test_network_cidr_basic() -> None:
    assert _network_cidr("10.0.0.1", 24) == "10.0.0.0/24"


def test_network_cidr_string_prefix() -> None:
    assert _network_cidr("192.168.5.1", "25") == "192.168.5.0/25"


def test_network_cidr_bad_prefix_returns_none() -> None:
    assert _network_cidr("10.0.0.1", "dhcp") is None
    assert _network_cidr("10.0.0.1", None) is None


def test_network_cidr_bad_address_returns_none() -> None:
    assert _network_cidr("not-an-ip", 24) is None


# ── _normalise_mac ────────────────────────────────────────────────────


def test_normalise_mac_lowercases_and_dashes() -> None:
    assert _normalise_mac("BC-24-11-E8-4A-3F") == "bc:24:11:e8:4a:3f"


def test_normalise_mac_drops_placeholders() -> None:
    assert _normalise_mac("(incomplete)") is None
    assert _normalise_mac("00:00:00:00:00:00") is None
    assert _normalise_mac("") is None
    assert _normalise_mac(None) is None


# ── Interface parsing — the #797 regression surface ───────────────────

# Captured from OPNsense 26.1.11_10-amd64 (the #797 report). Keyed by OS
# device, addresses in ipv4[]/ipv6[] arrays of {ipaddr, subnetbits}.
_IFCONFIG_26_1 = {
    "igc0": {
        "flags": ["up", "broadcast", "running", "simplex", "multicast", "lower_up"],
        "macaddr": "60:be:b4:11:22:33",
        "ipv4": [{"ipaddr": "172.20.1.1", "subnetbits": 24, "tunnel": False}],
        "ipv6": [],
        "is_physical": True,
        "device": "igc0",
        "mtu": "1500",
        "status": "active",
    },
    "igc1": {
        "macaddr": "60:be:b4:11:22:34",
        "ipv4": [{"ipaddr": "198.51.100.2", "subnetbits": 29, "tunnel": False}],
        "ipv6": [],
        "is_physical": True,
        "device": "igc1",
        "status": "active",
    },
    "lo0": {
        "ipv4": [{"ipaddr": "127.0.0.1", "subnetbits": 8, "tunnel": False}],
        "ipv6": [{"ipaddr": "fe80::1", "subnetbits": 64}],
        "device": "lo0",
        "status": "active",
    },
}


def test_ifconfig_parses_the_real_26_1_shape() -> None:
    """The exact payload #797 reported, which used to yield zero."""
    ifaces = _interfaces_from_ifconfig(_IFCONFIG_26_1)
    cidrs = {i.cidr for i in ifaces}
    assert "172.20.1.0/24" in cidrs
    assert "198.51.100.0/29" in cidrs
    # Link-local is skipped — it isn't a routable subnet and would
    # collide across every interface.
    assert not any(i.address.startswith("fe80:") for i in ifaces)


def test_ifconfig_uses_device_as_name_having_no_logical_one() -> None:
    ifaces = _interfaces_from_ifconfig(_IFCONFIG_26_1)
    igc0 = next(i for i in ifaces if i.cidr == "172.20.1.0/24")
    assert igc0.name == "igc0"
    assert igc0.device == "igc0"
    assert igc0.description == ""
    assert igc0.vlan_tag is None


def test_ifconfig_skips_tunnel_addresses() -> None:
    """A tunnel's peer address is not a LAN; mirroring it invents a subnet."""
    ifaces = _interfaces_from_ifconfig(
        {
            "wg0": {
                "device": "wg0",
                "ipv4": [{"ipaddr": "10.9.0.1", "subnetbits": 32, "tunnel": True}],
            }
        }
    )
    assert ifaces == []


def test_ifconfig_shape_drift_raises_rather_than_reporting_zero() -> None:
    """The #797 failure mode, asserted directly.

    A non-empty payload whose entries carry no ipv4/ipv6 list means the
    shape isn't the one we parse. Returning [] would report a clean sync
    with zero interfaces forever; raising routes it into degraded-read
    handling so the operator sees an error.
    """
    with pytest.raises(OPNsenseClientError, match="not the one this client parses"):
        _interfaces_from_ifconfig({"lan": {"ipaddr": "10.0.0.1", "subnet": "24"}})


def test_ifconfig_legitimately_empty_addresses_is_not_an_error() -> None:
    """Entries WITH address arrays that are simply empty are a real zero."""
    assert _interfaces_from_ifconfig({"igc0": {"device": "igc0", "ipv4": [], "ipv6": []}}) == []


# ``interfaces/overview/export`` — the richer primary source.
_OVERVIEW_EXPORT = [
    {
        "identifier": "lan",
        "description": "LAN",
        "device": "igc0",
        "enabled": True,
        "status": "up",
        "link_type": "static",
        "vlan_tag": None,
        "ipv4": [{"ipaddr": "172.20.1.1", "subnetbits": 24}],
        "ipv6": [],
    },
    {
        "identifier": "wan",
        "description": "WAN",
        "device": "igc1",
        "enabled": True,
        "link_type": "dhcp",
        "ipv4": [{"ipaddr": "198.51.100.2", "subnetbits": 29}],
        "ipv6": [],
    },
    {
        "identifier": "opt1",
        "description": "IoT",
        "device": "igc0_vlan20",
        "enabled": True,
        "link_type": "static",
        "vlan_tag": "20",
        "ipv4": [{"ipaddr": "192.168.20.1", "subnetbits": 24}],
        "ipv6": [],
    },
    {
        "identifier": "opt2",
        "description": "Disabled spare",
        "device": "igc2",
        "enabled": False,
        "link_type": "static",
        "ipv4": [{"ipaddr": "10.99.0.1", "subnetbits": 24}],
        "ipv6": [],
    },
]


def test_overview_carries_logical_name_description_and_vlan_tag() -> None:
    ifaces = _interfaces_from_overview(_OVERVIEW_EXPORT)
    by_cidr = {i.cidr: i for i in ifaces}
    assert by_cidr["172.20.1.0/24"].name == "lan"
    assert by_cidr["172.20.1.0/24"].description == "LAN"
    iot = by_cidr["192.168.20.0/24"]
    assert iot.name == "opt1"
    assert iot.vlan_tag == 20  # coerced from the string the API returns


def test_overview_skips_dhcp_and_disabled_interfaces() -> None:
    cidrs = {i.cidr for i in _interfaces_from_overview(_OVERVIEW_EXPORT)}
    # WAN is link_type=dhcp — dynamic, not a subnet this IPAM owns.
    assert "198.51.100.0/29" not in cidrs
    # opt2 is administratively disabled.
    assert "10.99.0.0/24" not in cidrs
    assert cidrs == {"172.20.1.0/24", "192.168.20.0/24"}


def test_overview_takes_only_the_primary_address_per_family() -> None:
    """Secondaries / VIPs would otherwise mirror as extra subnets."""
    ifaces = _interfaces_from_overview(
        [
            {
                "identifier": "lan",
                "device": "igc0",
                "ipv4": [
                    {"ipaddr": "10.0.0.1", "subnetbits": 24},
                    {"ipaddr": "10.0.1.1", "subnetbits": 24},
                ],
            }
        ]
    )
    assert [i.cidr for i in ifaces] == ["10.0.0.0/24"]


def test_overview_shape_drift_raises() -> None:
    with pytest.raises(OPNsenseClientError, match="not the one this client parses"):
        _interfaces_from_overview([{"identifier": "lan", "ipaddr": "10.0.0.1", "subnet": "24"}])


# ── HTTP surface via MockTransport ────────────────────────────────────


def _client_with_handler(handler) -> OPNsenseClient:
    client = OPNsenseClient(
        host="fw.example.test",
        port=443,
        api_key="KEY",
        api_secret="SECRET",
        verify_tls=False,
    )
    # Inject a MockTransport-backed httpx client, bypassing __aenter__'s
    # TLS context construction. The auth + base_url still apply.
    client._client = httpx.AsyncClient(
        base_url="https://fw.example.test:443",
        auth=("KEY", "SECRET"),
        headers={"Accept": "application/json"},
        transport=httpx.MockTransport(handler),
    )
    return client


def _routes(mapping: dict[str, Any], *, status: dict[str, int] | None = None):
    """Build a handler that answers only the given paths.

    Anything unmapped 404s with OPNsense's own body, which is what a
    firewall does for a module that isn't installed — the condition the
    whole backend-union design turns on.
    """
    codes = status or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in mapping:
            return httpx.Response(codes.get(path, 200), json=mapping[path])
        if path in codes:
            return httpx.Response(codes[path], json={"errorMessage": "Endpoint not found"})
        return httpx.Response(404, json={"errorMessage": "Endpoint not found"})

    return handler


async def _run(client: OPNsenseClient, coro_name: str) -> Any:
    try:
        return await getattr(client, coro_name)()
    finally:
        await client._client.aclose()  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_basic_auth_header_is_sent() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization", "")
        return httpx.Response(200, json={"product_version": "OPNsense 26.1"})

    client = _client_with_handler(handler)
    fw = await _run(client, "get_firmware")
    assert fw.version == "OPNsense 26.1"
    # KEY:SECRET base64 == S0VZOlNFQ1JFVA==
    assert seen["auth"] == "Basic S0VZOlNFQ1JFVA=="


@pytest.mark.asyncio
async def test_401_raises_client_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    client = _client_with_handler(handler)
    with pytest.raises(OPNsenseClientError, match="401"):
        await _run(client, "get_firmware")


@pytest.mark.asyncio
async def test_interfaces_prefer_overview_export() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/api/interfaces/overview/export":
            return httpx.Response(200, json=_OVERVIEW_EXPORT)
        return httpx.Response(404, json={"errorMessage": "Endpoint not found"})

    client = _client_with_handler(handler)
    ifaces = await _run(client, "list_interfaces")
    assert {i.cidr for i in ifaces} == {"172.20.1.0/24", "192.168.20.0/24"}
    # The diagnostics fallback must not be called when the overview answers.
    assert "/api/diagnostics/interface/getInterfaceConfig" not in seen


@pytest.mark.asyncio
async def test_interfaces_fall_back_to_ifconfig_on_404() -> None:
    client = _client_with_handler(
        _routes({"/api/diagnostics/interface/getInterfaceConfig": _IFCONFIG_26_1})
    )
    ifaces = await _run(client, "list_interfaces")
    # lo0 is in the payload and deliberately not mirrored.
    assert {i.cidr for i in ifaces} == {"172.20.1.0/24", "198.51.100.0/29"}


# ── DHCP backend matrix (#797 cause 2) ────────────────────────────────

_KEA_LEASES = {
    "rows": [
        {
            "address": "172.20.1.50",
            "hwaddr": "BC:24:11:E8:4A:3F",
            "hostname": "laptop",
            "state": "0",
            "if_name": "lan",
        },
        {"address": "172.20.1.51", "hwaddr": "aa:bb:cc:00:11:22", "state": "2"},
    ],
    "total": 2,
}

_DNSMASQ_LEASES = {
    "rows": [{"address": "172.20.1.80", "hwaddr": "de:ad:be:ef:00:01", "hostname": "tv"}],
    "total": 1,
}

_ISC_LEASES = {
    "rows": [{"address": "172.20.1.90", "mac": "11:22:33:44:55:66", "status": "active"}],
    "total": 1,
}


@pytest.mark.asyncio
async def test_leases_kea_only_firmware() -> None:
    """25.7+ with Kea — the ISC paths 404 and must not fail the read."""
    client = _client_with_handler(_routes({"/api/kea/leases4/search": _KEA_LEASES}))
    result = await _run(client, "list_leases")
    assert result.sources_found == ["kea"]
    assert {lease.address for lease in result.leases} == {"172.20.1.50", "172.20.1.51"}
    active = next(x for x in result.leases if x.address == "172.20.1.50")
    assert active.mac == "bc:24:11:e8:4a:3f"
    assert active.state == "active"  # Kea's numeric 0 mapped, not passed through
    assert next(x for x in result.leases if x.address == "172.20.1.51").state == "expired"


@pytest.mark.asyncio
async def test_leases_dnsmasq_only_firmware() -> None:
    client = _client_with_handler(_routes({"/api/dnsmasq/leases/search": _DNSMASQ_LEASES}))
    result = await _run(client, "list_leases")
    assert result.sources_found == ["dnsmasq"]
    assert result.leases[0].address == "172.20.1.80"
    # Dnsmasq reports no state; a row in the lease file IS a live lease.
    assert result.leases[0].state == "active"


@pytest.mark.asyncio
async def test_leases_legacy_isc_firmware_still_works() -> None:
    """≤25.1, or 25.7+ with the ISC plugin — must not regress."""
    client = _client_with_handler(_routes({"/api/dhcpv4/leases/searchLease": _ISC_LEASES}))
    result = await _run(client, "list_leases")
    assert result.sources_found == ["isc"]
    assert result.leases[0].address == "172.20.1.90"


@pytest.mark.asyncio
async def test_leases_kea_and_dnsmasq_side_by_side_are_unioned() -> None:
    """25.7+ can run both on different interfaces — union, not first-wins."""
    client = _client_with_handler(
        _routes(
            {
                "/api/kea/leases4/search": _KEA_LEASES,
                "/api/dnsmasq/leases/search": _DNSMASQ_LEASES,
            }
        )
    )
    result = await _run(client, "list_leases")
    assert result.sources_found == ["kea", "dnsmasq"]
    assert {lease.address for lease in result.leases} == {
        "172.20.1.50",
        "172.20.1.51",
        "172.20.1.80",
    }


@pytest.mark.asyncio
async def test_leases_duplicate_address_across_backends_keeps_first() -> None:
    client = _client_with_handler(
        _routes(
            {
                "/api/kea/leases4/search": {
                    "rows": [
                        {"address": "172.20.1.50", "hwaddr": "aa:aa:aa:aa:aa:aa", "state": "0"}
                    ]
                },
                "/api/dnsmasq/leases/search": {
                    "rows": [{"address": "172.20.1.50", "hwaddr": "bb:bb:bb:bb:bb:bb"}]
                },
            }
        )
    )
    result = await _run(client, "list_leases")
    assert len(result.leases) == 1
    assert result.leases[0].mac == "aa:aa:aa:aa:aa:aa"  # Kea queried first


@pytest.mark.asyncio
async def test_leases_no_backend_at_all_reports_no_sources() -> None:
    """The #797 headline: every endpoint 404s.

    The list is empty either way, but ``sources_found`` being empty is
    what lets the reconciler tell "DHCP is off" from "we asked a
    firmware that doesn't have these endpoints" and warn accordingly.
    """
    client = _client_with_handler(_routes({}))
    result = await _run(client, "list_leases")
    assert result.leases == []
    assert result.sources_found == []


@pytest.mark.asyncio
async def test_leases_403_records_forbidden_and_keeps_going() -> None:
    """Kea's lease endpoints have their own ACL (opnsense/core#7770).

    An under-privileged API user must not abort the whole pass — the
    interface mirror still works — but the gap has to be reported so the
    operator can fix the privilege rather than wonder why leases are
    missing.
    """
    client = _client_with_handler(
        _routes(
            {"/api/dnsmasq/leases/search": _DNSMASQ_LEASES},
            status={"/api/kea/leases4/search": 403},
        )
    )
    result = await _run(client, "list_leases")
    assert result.sources_found == ["dnsmasq"]
    assert result.sources_forbidden == ["kea leases"]
    assert len(result.leases) == 1


@pytest.mark.asyncio
async def test_leases_5xx_still_aborts_rather_than_emptying_the_mirror() -> None:
    """A transient failure must propagate (#5) — diffing against an
    empty desired set would absence-delete every mirrored row."""
    client = _client_with_handler(_routes({}, status={"/api/kea/leases4/search": 502}))
    with pytest.raises(OPNsenseClientError, match="502"):
        await _run(client, "list_leases")


@pytest.mark.asyncio
async def test_reservations_kea() -> None:
    client = _client_with_handler(
        _routes(
            {
                "/api/kea/dhcpv4/searchReservation": {
                    "rows": [
                        {
                            "ip_address": "172.20.1.10",
                            "hw_address": "AA:BB:CC:DD:EE:FF",
                            "hostname": "printer",
                            "description": "office printer",
                        }
                    ]
                }
            }
        )
    )
    result = await _run(client, "list_reservations")
    assert result.sources_found == ["kea"]
    assert result.reservations[0].address == "172.20.1.10"
    assert result.reservations[0].mac == "aa:bb:cc:dd:ee:ff"
    assert result.reservations[0].description == "office printer"


@pytest.mark.asyncio
async def test_reservations_dnsmasq_requires_a_mac() -> None:
    """Dnsmasq hosts double as static DNS entries; only a row with a MAC
    is a DHCP reservation."""
    client = _client_with_handler(
        _routes(
            {
                "/api/dnsmasq/settings/searchHost": {
                    "rows": [
                        {
                            "host": "nas",
                            "domain": "lan",
                            "ip": "172.20.1.20",
                            "hwaddr": "11:22:33:44:55:66",
                            "descr": "storage",
                        },
                        {"host": "dns-only", "domain": "lan", "ip": "172.20.1.21", "hwaddr": ""},
                    ]
                }
            }
        )
    )
    result = await _run(client, "list_reservations")
    assert len(result.reservations) == 1
    assert result.reservations[0].address == "172.20.1.20"
    # #1557: host label only — the domain is not appended (IPAM
    # publishing appends the zone itself).
    assert result.reservations[0].hostname == "nas"


@pytest.mark.asyncio
async def test_reservations_legacy_isc_tree_shape() -> None:
    client = _client_with_handler(
        _routes(
            {
                "/api/dhcpv4/settings/getReservation": {
                    "dhcpd": {
                        "lan": {
                            "staticmap": {
                                "uuid-1": {
                                    "ipaddr": "10.0.0.10",
                                    "mac": "AA:BB:CC:DD:EE:FF",
                                    "hostname": "printer",
                                    "descr": "office printer",
                                }
                            }
                        }
                    }
                }
            }
        )
    )
    result = await _run(client, "list_reservations")
    assert result.sources_found == ["isc"]
    assert result.reservations[0].address == "10.0.0.10"
    assert result.reservations[0].hostname == "printer"


@pytest.mark.asyncio
async def test_reservations_no_backend_reports_no_sources() -> None:
    client = _client_with_handler(_routes({}))
    result = await _run(client, "list_reservations")
    assert result.reservations == []
    assert result.sources_found == []


# ── Unchanged surfaces (regression guards) ────────────────────────────


@pytest.mark.asyncio
async def test_vlans_parsed_from_nested_shape() -> None:
    client = _client_with_handler(
        _routes(
            {
                "/api/interfaces/vlan_settings/get": {
                    "vlan": {
                        "vlan": {
                            "uuid-1": {
                                "vlanif": "vlan0.20",
                                "if": "igb1",
                                "tag": "20",
                                "descr": "IoT",
                            }
                        }
                    }
                }
            }
        )
    )
    vlans = await _run(client, "list_vlans")
    assert len(vlans) == 1
    assert vlans[0].device == "vlan0.20"
    assert vlans[0].parent == "igb1"
    assert vlans[0].tag == 20
    assert vlans[0].description == "IoT"


@pytest.mark.asyncio
async def test_arp_parsed_from_bare_list() -> None:
    client = _client_with_handler(
        _routes(
            {
                "/api/diagnostics/interface/getArp": [
                    {"ip": "10.0.0.50", "mac": "bc:24:11:e8:4a:3f", "intf": "igb1"},
                    {"ip": "10.0.0.99", "mac": "(incomplete)", "intf": "igb1"},
                ]
            }
        )
    )
    arp = await _run(client, "list_arp")
    assert len(arp) == 2
    assert arp[0].address == "10.0.0.50"
    assert arp[0].mac == "bc:24:11:e8:4a:3f"
    assert arp[1].mac is None


# ── Code-review follow-ups on the #797 fix ────────────────────────────


def test_ifconfig_skips_loopback() -> None:
    """``ifconfig`` reports every kernel interface, ``lo0`` included.

    Without a filter the fallback parser mirrors 127.0.0.0/8 — a
    16.7-million-address subnet, an auto-created wrapper block for it, and
    a "gateway" reservation for 127.0.0.1 — on every firewall, and every
    firewall would collide on the same CIDR.
    """
    cidrs = {i.cidr for i in _interfaces_from_ifconfig(_IFCONFIG_26_1)}
    assert "127.0.0.0/8" not in cidrs
    assert cidrs == {"172.20.1.0/24", "198.51.100.0/29"}


def test_addresses_skip_ipv4_link_local_too() -> None:
    """169.254/16 is as per-link as fe80::/10 and equally uninteresting."""
    ifaces = _interfaces_from_ifconfig(
        {"igc9": {"device": "igc9", "ipv4": [{"ipaddr": "169.254.1.5", "subnetbits": 16}]}}
    )
    assert ifaces == []


def test_addresses_skip_unspecified() -> None:
    ifaces = _interfaces_from_ifconfig(
        {"igc9": {"device": "igc9", "ipv4": [{"ipaddr": "0.0.0.0", "subnetbits": 0}]}}
    )
    assert ifaces == []


def test_overview_all_rows_filtered_is_a_clean_zero_not_a_shape_error() -> None:
    """A WAN-only DHCP box parses to zero for a reason we understand.

    Shape detection must therefore run before the enabled/link_type
    filters — otherwise this raises the degraded-read error and aborts
    the pass, instead of reaching the zero-interface warning that exists
    for exactly this case.
    """
    rows = [
        {
            "identifier": "wan",
            "device": "igc0",
            "link_type": "dhcp",
            "ipv4": [{"ipaddr": "198.51.100.2", "subnetbits": 29}],
            "ipv6": [],
        },
        {
            "identifier": "opt1",
            "device": "igc1",
            "enabled": False,
            "ipv4": [{"ipaddr": "10.0.0.1", "subnetbits": 24}],
            "ipv6": [],
        },
    ]
    assert _interfaces_from_overview(rows) == []


def test_overview_unknown_link_type_vocabulary_does_not_raise() -> None:
    """An unrecognised link_type is skipped, not treated as shape drift."""
    rows = [
        {
            "identifier": "opt9",
            "device": "igc9",
            "link_type": "some-future-mode",
            "ipv4": [],
            "ipv6": [],
        }
    ]
    assert _interfaces_from_overview(rows) == []


@pytest.mark.asyncio
async def test_interfaces_fall_back_to_ifconfig_on_403_not_just_404() -> None:
    """An API user provisioned against the OLD docs has no Interfaces:
    Overview privilege. Upgrading must degrade to the fallback, not turn
    a working mirror into a hard failure."""
    client = _client_with_handler(
        _routes(
            {"/api/diagnostics/interface/getInterfaceConfig": _IFCONFIG_26_1},
            status={"/api/interfaces/overview/export": 403},
        )
    )
    ifaces = await _run(client, "list_interfaces")
    assert {i.cidr for i in ifaces} == {"172.20.1.0/24", "198.51.100.0/29"}


@pytest.mark.asyncio
async def test_interfaces_5xx_on_overview_still_aborts() -> None:
    """Only 404/403 fall back; a transient failure must propagate."""
    client = _client_with_handler(_routes({}, status={"/api/interfaces/overview/export": 503}))
    with pytest.raises(OPNsenseClientError, match="503"):
        await _run(client, "list_interfaces")


@pytest.mark.asyncio
async def test_isc_lease_403_degrades_like_the_other_backends() -> None:
    """The ISC reader is a POST so it can't use ``_get_optional``, but it
    must not be stricter than the readers that can."""
    client = _client_with_handler(
        _routes(
            {"/api/dnsmasq/leases/search": _DNSMASQ_LEASES},
            status={"/api/dhcpv4/leases/searchLease": 403},
        )
    )
    result = await _run(client, "list_leases")
    assert result.sources_found == ["dnsmasq"]
    assert "isc leases" in result.sources_forbidden


@pytest.mark.asyncio
async def test_isc_reservation_403_degrades_too() -> None:
    client = _client_with_handler(_routes({}, status={"/api/dhcpv4/settings/getReservation": 403}))
    result = await _run(client, "list_reservations")
    assert result.reservations == []
    assert "isc reservations" in result.sources_forbidden


@pytest.mark.asyncio
async def test_kea_numeric_zero_state_is_active_not_unknown() -> None:
    """``str(0 or "")`` is ``""`` — so an integer 0, which is Kea's ACTIVE
    state, would collapse to "unknown" and mark every live lease stale."""
    client = _client_with_handler(
        _routes(
            {
                "/api/kea/leases4/search": {
                    "rows": [
                        {"address": "172.20.1.50", "hwaddr": "aa:bb:cc:dd:ee:ff", "state": 0},
                        {"address": "172.20.1.51", "hwaddr": "aa:bb:cc:dd:ee:01", "state": 2},
                    ]
                }
            }
        )
    )
    result = await _run(client, "list_leases")
    by_addr = {x.address: x for x in result.leases}
    assert by_addr["172.20.1.50"].state == "active"
    assert by_addr["172.20.1.51"].state == "expired"


@pytest.mark.asyncio
async def test_kea_missing_state_is_unknown() -> None:
    client = _client_with_handler(
        _routes({"/api/kea/leases4/search": {"rows": [{"address": "172.20.1.52"}]}})
    )
    result = await _run(client, "list_leases")
    assert result.leases[0].state == "unknown"
