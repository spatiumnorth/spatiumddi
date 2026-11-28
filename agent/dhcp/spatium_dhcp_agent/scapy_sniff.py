"""Shared setup for the agent's scapy ``AsyncSniffer`` users (#5001).

The passive fingerprint, L2 MAC-sighting and Router-Advertisement sniffers all
open an ``AsyncSniffer`` and decode what it reads. Two things have to be right
before the socket opens, and neither shows in the sniffer's own "started" log.
"""

from __future__ import annotations

import os


def load_layers() -> None:
    """Register scapy's Ethernet, DHCP and IPv6 layers before a socket opens.

    ``AsyncSniffer`` fixes the link layer it decodes with when its socket is
    opened, from the layers registered *at that moment*. ``scapy.sendrecv``
    alone registers none, so a sniffer opened before something imports
    ``scapy.layers.l2`` types every frame ``Raw`` ("Unable to guess type ...
    Using Raw") and every ``haslayer`` check afterwards is false. The parsers
    import their layers lazily, but only after a first packet they can never
    read, so the sniffer reports "started" and records nothing -- unless some
    other thread happened to import the layers first.
    """
    import scapy.layers.dhcp  # noqa: F401, PLC0415
    import scapy.layers.inet  # noqa: F401, PLC0415
    import scapy.layers.inet6  # noqa: F401, PLC0415
    import scapy.layers.l2  # noqa: F401, PLC0415


def sniff_interfaces(iface: str) -> list[str] | str | None:
    """What to hand ``AsyncSniffer(iface=...)`` for the configured ``iface``.

    ``"any"`` is turned into the non-loopback interface names rather than
    ``iface=None`` (scapy's "every interface" socket, whose frames scapy 2.8
    types by a link layer of its own guessing). Loopback is left out: no
    client frame arrives there. An interface that appears after start is not
    watched until the agent restarts; ``None`` means the host has no interface
    to name, and lets scapy pick its default.
    """
    if iface != "any":
        return iface
    try:
        names = sorted(n for n in os.listdir("/sys/class/net") if n != "lo")
    except OSError:
        return None
    return names or None
