"""#5001 -- the fingerprint / MAC-sighting / RA sniffers must load scapy's
layers before their socket opens, or every frame decodes as ``Raw``."""

from __future__ import annotations

import subprocess
import sys
import types
from typing import Any

import pytest

from spatium_dhcp_agent import dhcp_fingerprint, mac_sighting, ra_sniffer
from spatium_dhcp_agent import scapy_sniff as ss


def test_any_names_the_interfaces(monkeypatch) -> None:
    monkeypatch.setattr(ss.os, "listdir", lambda _p: ["lo", "eth1", "eth0"])
    assert ss.sniff_interfaces("any") == ["eth0", "eth1"]
    assert ss.sniff_interfaces("br0") == "br0"


def test_any_with_no_interfaces_falls_back_to_scapy_default(monkeypatch) -> None:
    monkeypatch.setattr(ss.os, "listdir", lambda _p: ["lo"])
    assert ss.sniff_interfaces("any") is None

    def boom(_p: str) -> list[str]:
        raise OSError("no /sys")

    monkeypatch.setattr(ss.os, "listdir", boom)
    assert ss.sniff_interfaces("any") is None


def test_load_layers_registers_ethernet_in_a_fresh_interpreter() -> None:
    # The mechanism, in a clean process: scapy.sendrecv alone leaves no link
    # layer registered; load_layers() registers Ethernet (type 1) and DHCP.
    code = (
        "import scapy.sendrecv\n"
        "from scapy.config import conf\n"
        "before = conf.l2types.num2layer.get(1)\n"
        "from spatium_dhcp_agent.scapy_sniff import load_layers\n"
        "load_layers()\n"
        "after = conf.l2types.num2layer.get(1)\n"
        "print(before is None, after is not None)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout.split()
    assert out == ["True", "True"]


@pytest.mark.parametrize(
    "cls,env",
    [
        (dhcp_fingerprint.DhcpFingerprintShipper, "DHCP_FINGERPRINT_IFACE"),
        (mac_sighting.MacSightingShipper, "DHCP_MAC_SIGHTING_IFACE"),
        (ra_sniffer.RASnifferShipper, "DHCP_RA_SNIFFER_IFACE"),
    ],
)
def test_each_sniffer_loads_layers_before_opening_its_socket(monkeypatch, cls, env) -> None:
    order: list[str] = []
    seen: dict[str, Any] = {}

    class FakeSniffer:
        def __init__(self, **kw: Any) -> None:
            order.append("sniffer")
            seen.update(kw)

        def start(self) -> None:
            pass

    mod = types.ModuleType("scapy.sendrecv")
    mod.AsyncSniffer = FakeSniffer  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.sendrecv", mod)
    mod_under_test = sys.modules[cls.__module__]
    monkeypatch.setattr(mod_under_test, "load_layers", lambda: order.append("layers"))
    monkeypatch.setattr(ss.os, "listdir", lambda _p: ["lo", "eth0"])
    monkeypatch.delenv(env, raising=False)
    monkeypatch.delenv("DHCP_FINGERPRINT_IFACE", raising=False)
    shipper = cls(object(), ["tok"])  # type: ignore[arg-type]
    assert shipper._start_sniffer() is True
    assert order == ["layers", "sniffer"]
    assert seen["iface"] == ["eth0"]
