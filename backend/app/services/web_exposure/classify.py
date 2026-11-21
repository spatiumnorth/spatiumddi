"""Classify a client address against the operator's networks (#3651).

``internal`` is private address space only: RFC 1918, CGNAT 100.64/10, ULA
fc00::/7, loopback and link-local. The list is spelled out here rather than
read from ``ipaddress.is_private``, which also covers the documentation,
benchmarking and reserved ranges and would call a source in 203.0.113.0/24
"internal". It is NOT inferred from IPAM containment. An operator who numbers their LAN from public
space lists it in ``trusted_networks``, the explicit escape hatch (empty by
default). Anything else is ``external``.
"""

from __future__ import annotations

import ipaddress
from typing import Literal

SourceClass = Literal["trusted", "internal", "external"]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: What "internal" means: the whole definition, also written into the appliance
#: Web UI allow-list by tier 3a.
INTERNAL_RANGES: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "::1/128",
    "fe80::/10",
)
_INTERNAL: tuple[IPNetwork, ...] = tuple(ipaddress.ip_network(n) for n in INTERNAL_RANGES)


def _is_internal(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr.version == n.version and addr in n for n in _INTERNAL)


def parse_networks(cidrs: list[str]) -> tuple[IPNetwork, ...]:
    out: list[IPNetwork] = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(c.strip(), strict=False))
        except ValueError:
            continue
    return tuple(out)


def _normalise(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def classify(value: str | None, trusted: tuple[IPNetwork, ...] = ()) -> SourceClass | None:
    """``None`` for a value that is not an address (nothing is recorded for it)."""
    if not value:
        return None
    addr = _normalise(value)
    if addr is None:
        return None
    if any(addr.version == n.version and addr in n for n in trusted):
        return "trusted"
    if _is_internal(addr):
        return "internal"
    return "external"


def is_private_fast(value: str | None) -> bool:
    """True for an address that is internal by construction, with no config."""
    if not value:
        return False
    addr = _normalise(value)
    return addr is not None and _is_internal(addr)


def bucket_of(value: str) -> str | None:
    """IPv4 -> its /24, IPv6 -> its /48, so a scanner walking one /24 reads as
    one source and the stored data is coarse by construction."""
    addr = _normalise(value)
    if addr is None:
        return None
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network((addr, prefix), strict=False))
