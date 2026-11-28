"""#5028 — the rogue-DHCP probe must not send its DISCOVER before the sniffer
is capturing.

scapy's AsyncSniffer.start() only starts a thread; the sockets open later. A
server with no ping check answers in the same millisecond, so an OFFER that
arrives before the sockets are open was never seen, and the first probe after
every agent start missed it.

These tests swap in fake scapy modules: the fake sniffer becomes ready only
after a delay (calling ``started_callback`` then), and the fake ``sendp`` makes
an instant answer that only a ready sniffer captures — exactly the race.
"""

from __future__ import annotations

import sys
import threading
import time
import types
from typing import Any

import pytest

from spatium_dhcp_agent import rogue_probe
from spatium_dhcp_agent.rogue_probe import RogueProbeShipper


class _Layer:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)

    def __truediv__(self, other: Any) -> _Layer:
        # Packet stacking: keep the BOOTP layer (it carries xid).
        return (
            other
            if isinstance(other, _BOOTP)
            else self if isinstance(self, _BOOTP) else other
        )


class _Ether(_Layer):
    pass


class _IP(_Layer):
    pass


class _UDP(_Layer):
    pass


class _BOOTP(_Layer):
    pass


class _DHCP(_Layer):
    pass


class _Offer:
    """A captured OFFER: what _on_pkt reads from a scapy packet."""

    def __init__(self, xid: int) -> None:
        self._layers = {
            _BOOTP: _BOOTP(xid=xid, giaddr="", yiaddr="192.0.2.50"),
            _DHCP: _DHCP(
                options=[("message-type", 2), ("server_id", "192.0.2.2"), "end"]
            ),
            _IP: _IP(src="192.0.2.2"),
            _Ether: _Ether(src="02:00:00:00:00:02"),
        }

    def haslayer(self, cls: Any) -> bool:
        return cls in self._layers

    def __getitem__(self, cls: Any) -> Any:
        return self._layers[cls]


class _World:
    """Shared state for one probe: the live sniffer and when it became ready."""

    def __init__(self, ready_delay: float, call_started_callback: bool = True) -> None:
        self.ready_delay = ready_delay
        self.call_started_callback = call_started_callback
        self.sniffer: Any = None
        self.ready_at: float | None = None
        self.sent_at: float | None = None


def _install_fake_scapy(monkeypatch: pytest.MonkeyPatch, world: _World) -> None:
    class AsyncSniffer:
        def __init__(
            self, prn: Any = None, started_callback: Any = None, **_: Any
        ) -> None:
            self.prn = prn
            self.started_callback = started_callback
            self.capturing = False
            world.sniffer = self

        def start(self) -> None:
            def _open_sockets() -> None:
                time.sleep(world.ready_delay)
                self.capturing = True
                world.ready_at = time.monotonic()
                if world.call_started_callback and self.started_callback:
                    self.started_callback()

            threading.Thread(target=_open_sockets, daemon=True).start()

        def stop(self) -> None:
            self.capturing = False

    def sendp(pkt: Any, **_: Any) -> None:
        world.sent_at = time.monotonic()
        sniffer = world.sniffer
        # The server answers at once; only a sniffer already capturing sees it.
        if sniffer is not None and sniffer.capturing and sniffer.prn:
            sniffer.prn(_Offer(pkt.xid))

    mods = {
        "scapy": types.ModuleType("scapy"),
        "scapy.layers": types.ModuleType("scapy.layers"),
        "scapy.layers.dhcp": types.ModuleType("scapy.layers.dhcp"),
        "scapy.layers.inet": types.ModuleType("scapy.layers.inet"),
        "scapy.layers.l2": types.ModuleType("scapy.layers.l2"),
        "scapy.sendrecv": types.ModuleType("scapy.sendrecv"),
    }
    mods["scapy.layers.dhcp"].BOOTP = _BOOTP  # type: ignore[attr-defined]
    mods["scapy.layers.dhcp"].DHCP = _DHCP  # type: ignore[attr-defined]
    mods["scapy.layers.inet"].IP = _IP  # type: ignore[attr-defined]
    mods["scapy.layers.inet"].UDP = _UDP  # type: ignore[attr-defined]
    mods["scapy.layers.l2"].Ether = _Ether  # type: ignore[attr-defined]
    mods["scapy.sendrecv"].AsyncSniffer = AsyncSniffer  # type: ignore[attr-defined]
    mods["scapy.sendrecv"].sendp = sendp  # type: ignore[attr-defined]
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)


def _shipper(monkeypatch: pytest.MonkeyPatch) -> RogueProbeShipper:
    monkeypatch.setattr(rogue_probe, "COLLECT_WINDOW", 0.05)
    cfg = types.SimpleNamespace(
        control_plane_url="http://cp.invalid", httpx_verify=lambda: True
    )
    return RogueProbeShipper(cfg, ["token"], iface="eth0")  # type: ignore[arg-type]


def test_instant_offer_is_seen_when_the_sniffer_opens_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _World(ready_delay=0.3)
    _install_fake_scapy(monkeypatch, world)

    offers = _shipper(monkeypatch)._probe_once()

    assert world.ready_at is not None and world.sent_at is not None
    assert (
        world.sent_at >= world.ready_at
    ), "DISCOVER went out before the sniffer was capturing"
    assert [o["source_ip"] for o in offers] == ["192.0.2.2"]
    assert offers[0]["server_identifier"] == "192.0.2.2"


def test_a_sniffer_that_never_reports_ready_still_sends_after_the_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A scapy that never calls started_callback must not hang the probe loop.
    world = _World(ready_delay=0.0, call_started_callback=False)
    _install_fake_scapy(monkeypatch, world)
    monkeypatch.setattr(rogue_probe, "SNIFFER_READY_TIMEOUT", 0.2)

    t0 = time.monotonic()
    offers = _shipper(monkeypatch)._probe_once()

    assert world.sent_at is not None, "the DISCOVER was never sent"
    assert world.sent_at - t0 >= 0.2
    assert time.monotonic() - t0 < 2.0
    assert [o["source_ip"] for o in offers] == ["192.0.2.2"]
