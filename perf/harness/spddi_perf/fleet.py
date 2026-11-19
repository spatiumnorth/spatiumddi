"""Deterministic device-fleet identity (docs §3.2 identity generation, §4.5 correlation).

Both the DHCP orchestrator (which leases) and the DNS query-set generator (which
queries names) derive device identity from the SAME deterministic functions here, so
"a device that got a lease then gets queried by name" works *by construction* without
scraping the live zone (§4.5). MACs come from a locally-administered OUI
(``02:00:00:xx:xx:xx``) partitioned so shards never collide.

Note: the *leased IP* is assigned by Kea at runtime and is NOT predictable here — so
the computable forward/PTR query set targets (a) per-device client-hostnames (when
the subnet uses ``client_or_generated``) and (b) PTRs across the known pool ranges.
The IP-derived ``dhcp-<a>-<b>-<c>-<d>`` names (``always_generate``) are queried by the
orchestrator's own per-device streams at runtime, which know the actual lease.
"""

from __future__ import annotations

import ipaddress

LAA_OUI = (0x02, 0x00, 0x00)   # locally-administered OUI base; 24-bit device index follows


def device_mac(index: int) -> str:
    """Deterministic unique MAC for a global device index (0 .. 16,777,215)."""
    if not 0 <= index < (1 << 24):
        raise ValueError(f"device index {index} out of 24-bit range")
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        *LAA_OUI, (index >> 16) & 0xFF, (index >> 8) & 0xFF, index & 0xFF)


def shard_indices(total: int, shard: int, shards: int):
    """Yield the device indices owned by ``shard`` of ``shards`` (disjoint partition)."""
    if not 0 <= shard < shards:
        raise ValueError(f"shard {shard} out of range 0..{shards - 1}")
    return range(shard, total, shards)


def client_id_for_mac(mac: str) -> str:
    """DHCP option-61 client-id derived from the MAC (stable across re-arrivals)."""
    return "01:" + mac  # RFC 2132 type 0x01 (ethernet) + the MAC


def client_hostname(index: int) -> str:
    """Deterministic client hostname (option-12) for a device index."""
    return f"dev-{index:07d}"


def assign_subnet(index: int, n_subnets: int) -> int:
    """Which subnet (0..n_subnets-1) a device belongs to — even round-robin spread."""
    return index % max(1, n_subnets)


def forward_fqdn(hostname: str, zone: str) -> str:
    return f"{hostname}.{zone.rstrip('.')}".lower()


def generated_forward_name(ip: str) -> str:
    """The ``always_generate`` forward label for a leased IPv4: the whole address,
    ``dhcp-<a>-<b>-<c>-<d>`` (ddns.py ``_generate_hostname``, #3364)."""
    return "dhcp-" + ip.replace(".", "-")


def ptr_qname(ip: str) -> str:
    """Reverse-DNS PTR qname for an address (e.g. 10.1.20.5 -> 5.20.1.10.in-addr.arpa)."""
    addr = ipaddress.ip_address(ip)
    return addr.reverse_pointer
