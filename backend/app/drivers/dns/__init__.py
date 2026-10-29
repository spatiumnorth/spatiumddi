"""DNS driver registry.

Per CLAUDE.md non-negotiable #10, the service layer obtains a driver via
``get_driver(server_type)`` and speaks only to the abstract interface.

SpatiumDDI ships five authoritative DNS drivers: BIND9 (default), PowerDNS
(issue #127, Phase 1 — agent-managed alongside BIND9), Technitium
(agent-managed, REST-API driven), Technitium over its remote API (issue
#810 — agentless, for a server the operator already runs), and Windows DNS
(WinRM-driven, agentless). New drivers register here without touching the
service layer.
"""

from __future__ import annotations

from app.drivers.dns.azuredns import AzureDNSDriver
from app.drivers.dns.base import (
    ConfigBundle,
    DNSDriver,
    EffectiveBlocklistData,
    RecordChange,
    RecordChangeResult,
    RecordData,
    ServerOptions,
    ZoneData,
)
from app.drivers.dns.bind9 import BIND9Driver
from app.drivers.dns.cloudflare import CloudflareDNSDriver
from app.drivers.dns.digitalocean import DigitalOceanDNSDriver
from app.drivers.dns.googledns import GoogleCloudDNSDriver
from app.drivers.dns.hetzner import HetznerDNSDriver
from app.drivers.dns.linode import LinodeDNSDriver
from app.drivers.dns.powerdns import PowerDNSDriver
from app.drivers.dns.route53 import Route53DNSDriver
from app.drivers.dns.technitium import TechnitiumDriver
from app.drivers.dns.technitium_api import TechnitiumAPIDriver
from app.drivers.dns.vultr import VultrDNSDriver
from app.drivers.dns.windows import WindowsDNSDriver

_DRIVERS: dict[str, type[DNSDriver]] = {
    "bind9": BIND9Driver,
    "powerdns": PowerDNSDriver,
    "technitium": TechnitiumDriver,
    # Agentless Technitium (#810) — an install the operator already runs,
    # driven over its HTTP API from the control plane. Distinct from
    # ``technitium`` above, which is the container we deploy with an agent
    # beside it; the two coexist, one group each.
    "technitium_api": TechnitiumAPIDriver,
    "windows_dns": WindowsDNSDriver,
    # Agentless cloud-hosted DNS providers (issue #37, Part B). The
    # control plane calls the provider REST/SDK API directly — same
    # shape as windows_dns Path B. Their modules lazy-import their heavy
    # SDKs inside methods, so importing them here is cheap + safe.
    "cloudflare": CloudflareDNSDriver,
    "route53": Route53DNSDriver,
    "azure_dns": AzureDNSDriver,
    "google_dns": GoogleCloudDNSDriver,
    # Token-only providers (issue #327) — single API token, plain JSON
    # over httpx, same agentless CloudDNSDriverBase shape.
    "digitalocean": DigitalOceanDNSDriver,
    "hetzner": HetznerDNSDriver,
    "linode": LinodeDNSDriver,
    "vultr": VultrDNSDriver,
}

# Drivers whose record ops run from the control plane directly, with no
# agent co-located with the daemon. The record_ops service short-circuits
# the queue for these — applying the change synchronously and writing a
# DNSRecordOp row as ``applied`` / ``failed`` for audit purposes.
AGENTLESS_DRIVERS: frozenset[str] = frozenset(
    {
        "windows_dns",
        "technitium_api",
        "cloudflare",
        "route53",
        "azure_dns",
        "google_dns",
        "digitalocean",
        "hetzner",
        "linode",
        "vultr",
    }
)

# Agentless cloud-hosted DNS drivers (subset of AGENTLESS_DRIVERS).
# Used by the DNS server create/update path + the cloud import + the
# sync-from-server widening to recognise a cloud DNS server (credentials
# live in DNSServer.credentials_encrypted as a provider-specific dict).
CLOUD_DNS_DRIVERS: frozenset[str] = frozenset(
    {
        "cloudflare",
        "route53",
        "azure_dns",
        "google_dns",
        "digitalocean",
        "hetzner",
        "linode",
        "vultr",
    }
)


# Agentless drivers that keep an operator-supplied credential dict in
# ``DNSServer.credentials_encrypted``. Superset of CLOUD_DNS_DRIVERS: the
# cloud providers plus ``technitium_api`` (#810), which is operator-hosted
# and so is NOT a cloud driver, but has exactly the same credential
# lifecycle on create / update / clear. Used by the DNS server CRUD path so
# adding another self-hosted agentless driver doesn't mean widening a
# `driver in CLOUD_DNS_DRIVERS` test that then reads as a lie.
CREDENTIALED_DNS_DRIVERS: frozenset[str] = CLOUD_DNS_DRIVERS | {"technitium_api"}

# Drivers implementing ``pull_zones_from_server`` — i.e. able to enumerate
# zones from the authoritative side, which is what the "import existing
# zones" and sync-from-server paths need. Windows DNS does it over WinRM
# (Path B), the cloud drivers over the provider API, technitium_api over
# Technitium's own REST API. Agent-managed drivers are absent: the control
# plane has no channel to their daemon.
TOPOLOGY_PULL_DRIVERS: frozenset[str] = CREDENTIALED_DNS_DRIVERS | {"windows_dns"}

# Drivers whose *agent* grants ``allow-transfer`` to the group's TSIG **key**
# rather than to a source address (#734), so the control plane must sign to
# read a live zone.
#
# NECESSARY BUT NOT SUFFICIENT — always test with
# ``app.services.dns.tsig.transfer_needs_tsig``, never with this set alone.
# A ``bind9`` row can equally be an operator's own BIND9 that SpatiumDDI
# never deployed to, authorised the ordinary way by address; that server has
# no group key, so signing it would turn a working unsigned pull into
# NOTAUTH. ``agent_id`` is what separates the two.
#
# ``windows_dns`` also AXFRs on Path A but is deliberately absent: Windows
# authorises by address and knows nothing of our group key.
AXFR_TSIG_DRIVERS: frozenset[str] = frozenset({"bind9", "technitium"})


# #2942 — the record TTLs a hosted provider can hold EXACTLY, as an inclusive
# ``(min, max)`` (``max=None``: no bound beyond the record API's own). A
# driver absent from this table publishes any 0..DNS_TTL_MAX value as stored
# (BIND9, PowerDNS, Technitium, Route 53, Google Cloud DNS, Windows).
#
# The record API refuses a TTL outside the range with a 422 rather than
# letting the driver coerce it, because both alternatives are worse: the
# provider refusing the write leaves a stored record that never publishes,
# and clamping publishes a TTL the database does not hold. ``None`` (inherit)
# is never refused — every provider has its own default for it.
#
# Several of these minimums are a SENTINEL rather than a floor, which is why
# 0 cannot be passed through: Vultr and Linode read 0 as "automatic / zone
# default", and Cloudflare reads 1 as "automatic". Sources (checked
# 2026-10-28): Cloudflare 60-86400, 30 on Enterprise (the gate uses 30 so an
# Enterprise account is not refused — below 60 on another plan the provider
# still refuses); Azure 1-2147483647; DigitalOcean 30 minimum; Hetzner 60
# minimum. Linode also ROUNDS any value outside its fixed set (300, 3600, ...)
# to the nearest one, which this range does not express.
PROVIDER_TTL_RANGES: dict[str, tuple[int, int | None]] = {
    "cloudflare": (30, 86400),
    "azure_dns": (1, None),
    "digitalocean": (30, None),
    "hetzner": (60, None),
    "linode": (1, None),
    "vultr": (1, None),
}


def ttl_refusal(driver_name: str, ttl: int | None) -> str | None:
    """Why ``driver_name`` cannot publish ``ttl`` exactly, or None if it can."""
    if ttl is None:
        return None
    bounds = PROVIDER_TTL_RANGES.get(driver_name)
    if bounds is None:
        return None
    lo, hi = bounds
    if ttl >= lo and (hi is None or ttl <= hi):
        return None
    span = f"{lo}-{hi}" if hi is not None else f"{lo} or more"
    return (
        f"TTL {ttl} cannot be published on {driver_name}: it accepts {span} seconds. "
        "Choose a TTL in that range, or leave the TTL empty to use the provider's default."
    )


def is_agentless(driver_name: str) -> bool:
    """True if the driver runs from the control plane without an agent."""
    return driver_name in AGENTLESS_DRIVERS


def supports_topology_pull(driver_name: str) -> bool:
    """True if the driver can list zones from the authoritative side.

    Consults :data:`TOPOLOGY_PULL_DRIVERS`, which two call sites in the DNS
    router previously spelled out inline as ``driver == "windows_dns" or
    driver in CLOUD_DNS_DRIVERS``. Every new agentless driver had to
    remember to appear in both, and #810 would have made it three.

    Note this answers "can this driver read zone topology at all", not "can
    this *server*" — the callers additionally require stored credentials,
    which is a per-row fact rather than a per-driver one.
    """
    return driver_name in TOPOLOGY_PULL_DRIVERS


def get_driver(server_type: str) -> DNSDriver:
    """Return a driver instance for the given server type string."""
    cls = _DRIVERS.get(server_type)
    if cls is None:
        raise ValueError(f"Unknown DNS driver: {server_type!r}")
    return cls()


def register_driver(name: str, driver_cls: type[DNSDriver]) -> None:
    """Register (or override) a driver class by name. Useful for tests."""
    _DRIVERS[name] = driver_cls


__all__ = [
    "AGENTLESS_DRIVERS",
    "AXFR_TSIG_DRIVERS",
    "CLOUD_DNS_DRIVERS",
    "CREDENTIALED_DNS_DRIVERS",
    "TOPOLOGY_PULL_DRIVERS",
    "ConfigBundle",
    "DNSDriver",
    "EffectiveBlocklistData",
    "RecordChange",
    "RecordChangeResult",
    "RecordData",
    "ServerOptions",
    "ZoneData",
    "get_driver",
    "is_agentless",
    "register_driver",
    "supports_topology_pull",
]
