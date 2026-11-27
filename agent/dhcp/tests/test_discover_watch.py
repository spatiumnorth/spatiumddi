"""DISCOVER-rate watch (#4737): the window arithmetic and the packet parser.

The sniffer itself needs CAP_NET_RAW and is not run here; the window and the
parser are the logic worth pinning.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from spatium_dhcp_agent import discover_watch as dw
from spatium_dhcp_agent.discover_watch import DiscoverWindow, parse_discover

NOW = datetime(2026, 11, 27, 9, 0, tzinfo=UTC)


def test_only_sources_above_the_floors_are_shipped() -> None:
    w = DiscoverWindow(client_floor=5, relay_floor=3)
    for _ in range(4):
        w.add("aa:aa:aa:aa:aa:01", None)  # below the client floor
    for _ in range(6):
        w.add("aa:aa:aa:aa:aa:02", "10.0.0.1")
    body = w.payload(60, NOW)
    assert body is not None
    assert [c["mac"] for c in body["clients"]] == ["aa:aa:aa:aa:aa:02"]
    assert body["clients"][0] == {
        "mac": "aa:aa:aa:aa:aa:02",
        "discovers": 6,
        "giaddr": "10.0.0.1",
    }
    # One MAC through the relay: under the relay floor of 3.
    assert body["relays"] == []
    assert body["window_seconds"] == 60
    assert body["window_end"] == NOW.isoformat()


def test_a_relay_is_counted_in_distinct_macs() -> None:
    w = DiscoverWindow(client_floor=1000, relay_floor=3)
    for i in range(10):
        w.add(f"aa:aa:aa:aa:00:{i:02x}", "10.9.9.1")
    w.add("aa:aa:aa:aa:00:00", "10.9.9.1")  # a repeat is not a new MAC
    body = w.payload(60, NOW)
    assert body is not None and body["clients"] == []
    assert body["relays"] == [
        {"giaddr": "10.9.9.1", "discovers": 11, "distinct_macs": 10}
    ]


def test_a_quiet_window_ships_nothing_and_reset_clears_it() -> None:
    w = DiscoverWindow()
    assert w.payload(60, NOW) is None
    for _ in range(50):
        w.add("aa:aa:aa:aa:aa:01", None)
    assert w.payload(60, NOW) is not None
    w.reset()
    assert w.payload(60, NOW) is None


def test_memory_is_bounded_under_a_mac_rotating_flood(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dw, "MAX_MACS", 100)
    monkeypatch.setattr(dw, "MAX_RELAY_MACS", 50)
    w = DiscoverWindow(client_floor=1, relay_floor=1)
    for i in range(10_000):
        w.add(f"02:00:00:00:{i >> 8:02x}:{i & 255:02x}", "10.1.1.1")
    assert len(w.per_mac) == 100
    assert len(w.relay_macs["10.1.1.1"]) == 50
    # Still counted in the relay's total.
    assert w.relay_discovers["10.1.1.1"] == 10_000
    # A MAC already tracked keeps counting past the cap.
    first = next(iter(w.per_mac))
    w.add(first, None)
    assert w.per_mac[first] == 2


def test_payload_respects_the_server_side_caps() -> None:
    w = DiscoverWindow(client_floor=1, relay_floor=1)
    for i in range(dw.MAX_CLIENTS + 50):
        w.add(f"02:00:00:01:{i >> 8:02x}:{i & 255:02x}", f"10.2.{i >> 8}.{i & 255}")
    body = w.payload(60, NOW)
    assert body is not None
    assert len(body["clients"]) == dw.MAX_CLIENTS
    assert len(body["relays"]) == dw.MAX_RELAYS


scapy = pytest.importorskip("scapy")
from scapy.layers.dhcp import BOOTP, DHCP


def _pkt(msg_type: int, giaddr: str = "0.0.0.0") -> BOOTP:
    mac = b"\x52\x54\x00\xab\xcd\xef"
    return BOOTP(chaddr=mac + b"\x00" * 10, giaddr=giaddr) / DHCP(
        options=[("message-type", msg_type), "end"]
    )


def test_parse_discover_direct_and_relayed() -> None:
    assert parse_discover(_pkt(1)) == ("52:54:00:ab:cd:ef", None)
    assert parse_discover(_pkt(1, "10.0.5.1")) == ("52:54:00:ab:cd:ef", "10.0.5.1")


def test_parse_ignores_everything_but_a_discover() -> None:
    for t in (2, 3, 4, 5, 6, 7, 8):
        assert parse_discover(_pkt(t)) is None
