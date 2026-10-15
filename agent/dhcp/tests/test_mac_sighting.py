"""Tests for the arpwatch-style L2 sniffer's packet parser (#459 Phase 3).

We don't run AsyncSniffer in the test env (no CAP_NET_RAW, no traffic).
Instead we build ARP + IPv6-ND packets in-memory via scapy's layers and
assert the parser extracts the ``(MAC, IP)`` pairings we expect.

If scapy isn't installed (running unit tests without the agent's
optional dep), the entire module is skipped.
"""

from __future__ import annotations

import pytest

scapy = pytest.importorskip("scapy")

from scapy.layers.inet6 import (  # noqa: E402
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
)
from scapy.layers.l2 import ARP, Ether  # noqa: E402

from spatium_dhcp_agent.mac_sighting import (  # noqa: E402
    MacSighting,
    _normalize_ip,
    _normalize_mac,
    parse_sighting_packet,
)


def test_parse_arp_reply() -> None:
    pkt = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(
        op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="10.0.0.5"
    )
    obs = parse_sighting_packet(pkt)
    assert obs is not None
    assert obs.mac_address == "aa:bb:cc:dd:ee:ff"
    assert obs.ip_address == "10.0.0.5"


def test_parse_arp_request_carries_sender_pairing() -> None:
    # Even a request (op=1) carries the sender's MAC + IP.
    pkt = Ether(src="52:54:00:ab:cd:ef") / ARP(
        op=1, hwsrc="52:54:00:ab:cd:ef", psrc="192.168.1.20", pdst="192.168.1.1"
    )
    obs = parse_sighting_packet(pkt)
    assert obs is not None
    assert obs.mac_address == "52:54:00:ab:cd:ef"
    assert obs.ip_address == "192.168.1.20"


def test_parse_arp_probe_zero_sender_ip_dropped() -> None:
    # ARP probes use 0.0.0.0 as the sender protocol address.
    pkt = Ether(src="52:54:00:ab:cd:ef") / ARP(
        op=1, hwsrc="52:54:00:ab:cd:ef", psrc="0.0.0.0", pdst="192.168.1.50"
    )
    assert parse_sighting_packet(pkt) is None


def test_parse_ipv6_nd_neighbor_solicitation() -> None:
    pkt = (
        Ether(src="aa:bb:cc:11:22:33")
        / IPv6(src="fe80::1")
        / ICMPv6ND_NS(tgt="fe80::2")
        / ICMPv6NDOptSrcLLAddr(lladdr="aa:bb:cc:11:22:33")
    )
    obs = parse_sighting_packet(pkt)
    assert obs is not None
    assert obs.mac_address == "aa:bb:cc:11:22:33"
    assert obs.ip_address == "fe80::1"


def test_parse_ipv6_nd_advertisement_falls_back_to_ether_src() -> None:
    # An NA without a tgt-LLA option still yields a pairing from Ether.src.
    pkt = (
        Ether(src="aa:bb:cc:44:55:66")
        / IPv6(src="2001:db8::10")
        / ICMPv6ND_NA(tgt="2001:db8::10")
    )
    obs = parse_sighting_packet(pkt)
    assert obs is not None
    assert obs.mac_address == "aa:bb:cc:44:55:66"
    assert obs.ip_address == "2001:db8::10"


def test_parse_non_arp_non_nd_returns_none() -> None:
    pkt = Ether(src="aa:bb:cc:dd:ee:ff")
    assert parse_sighting_packet(pkt) is None


def test_normalize_mac_rejects_broadcast_zero_multicast() -> None:
    assert _normalize_mac("ff:ff:ff:ff:ff:ff") is None
    assert _normalize_mac("00:00:00:00:00:00") is None
    # Multicast/group bit set (low bit of first octet).
    assert _normalize_mac("01:00:5e:00:00:01") is None
    assert _normalize_mac("33:33:00:00:00:01") is None
    # A normal unicast MAC normalises to lower-case.
    assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert _normalize_mac("not-a-mac") is None


def test_normalize_ip_rejects_unspecified() -> None:
    assert _normalize_ip("0.0.0.0") is None
    assert _normalize_ip("::") is None
    assert _normalize_ip("") is None
    assert _normalize_ip("fe80::1") == "fe80::1"
    assert _normalize_ip("10.0.0.5") == "10.0.0.5"


def test_sighting_payload_round_trips() -> None:
    obs = MacSighting(mac_address="aa:bb:cc:dd:ee:ff", ip_address="10.0.0.5")
    payload = obs.to_payload()
    assert payload == {"mac_address": "aa:bb:cc:dd:ee:ff", "ip_address": "10.0.0.5"}


# --- #1109 Part 4: no per-packet imports / layer-chain re-walks ----------


def test_parse_does_not_import_scapy_per_packet(monkeypatch):
    import builtins

    parse_sighting_packet(Ether(src="aa:bb:cc:00:00:01") / ARP(psrc="10.0.0.1"))  # warm
    real = builtins.__import__
    seen: list[str] = []

    def spy(name, *a, **kw):
        if name.startswith("scapy"):
            seen.append(name)
        return real(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", spy)
    for _ in range(5):
        obs = parse_sighting_packet(Ether(src="aa:bb:cc:00:00:01") / ARP(psrc="10.0.0.1"))
        assert obs is not None and obs.ip_address == "10.0.0.1"
    assert seen == []


def test_parse_walks_layer_chain_once(monkeypatch):
    from scapy.packet import Packet

    calls = {"n": 0}
    real = Packet.haslayer

    def counting(self, *a, **kw):
        calls["n"] += 1
        return real(self, *a, **kw)

    monkeypatch.setattr(Packet, "haslayer", counting)
    pkt = (
        Ether(src="aa:bb:cc:00:00:02")
        / IPv6(src="fe80::2")
        / ICMPv6ND_NS(tgt="fe80::2")
        / ICMPv6NDOptSrcLLAddr(lladdr="aa:bb:cc:00:00:02")
    )
    assert parse_sighting_packet(pkt) is not None
    assert calls["n"] == 0
