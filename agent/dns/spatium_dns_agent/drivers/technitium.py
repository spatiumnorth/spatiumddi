"""Technitium DNS Server agent driver.

Runs alongside the Technitium ``DnsServerApp`` process inside the
dns-technitium container. Unlike BIND9 (named.conf + RFC 1035 zone files +
``rndc``) or PowerDNS (``pdns.conf`` + REST reconcile), Technitium has **no
on-disk config file this driver manages at all** — the daemon persists its
own config under ``/etc/dns`` and is configured entirely over its HTTP API
(``http://127.0.0.1:5380/api/...``). So this driver:

* Provisions a permanent API token on first-ever boot. The container image
  bakes ``DNS_SERVER_ADMIN_PASSWORD`` with a value this driver generates,
  which Technitium consumes to set the ``admin`` user's password the very
  first time ``/etc/dns`` is empty. The driver then calls
  ``/api/user/createToken`` ONCE and persists the resulting bearer token —
  calling ``createToken`` again would mint a second, orphaned token on the
  server (confirmed empirically: the endpoint is not idempotent), so the
  local token file is the source of truth once it exists.
* Applies zone + record state via the REST API. ``render()``/``validate()``/
  ``swap_and_reload()`` collapse into: stash the desired-state JSON, then
  reconcile it against the live API in ``swap_and_reload()`` (same split as
  PowerDNS, for symmetry with the rest of the codebase, even though there's
  no config file being swapped here).
* Zone apex NS/SOA are created by the daemon on ``/api/zones/create`` (one
  NS and an SOA MNAME naming its own host name, which in a pod is the pod
  name). They are not reconciled record by record with the rest of the
  zone: ``_reconcile_zone_apex`` rewrites the SOA fields the zone sets
  (Primary NS, Admin Email, and with them the timers) and replaces the apex
  NS set as a whole, each only when it differs, and leaves a zone that sets
  neither Primary NS nor Admin Email nor apex NS alone.

Zone types (issue #743): primary, secondary, stub and forward, plus
catalog-zone membership for the primaries this server owns. Only a
*primary's* records are reconciled — a secondary and a stub fill
themselves from the zone transfer and a forwarder holds none, so diffing
them would delete whatever the daemon just pulled down.

Record types: A, AAAA, CNAME, MX, TXT, NS (zone-referral records off-apex
only — apex NS is daemon-managed), PTR, SRV, CAA, TLSA, SSHFP, NAPTR, URI,
DNAME, SVCB, HTTPS.

Two Technitium behaviours this driver exists to paper over, both verified
against a live daemon and both silent if you get them wrong:

* Record GET does not echo the params record ADD takes — see
  ``_normalize_rdata``.
* ``zones/options/set`` answers ``ok`` for a value it does not recognise
  and keeps the old one — see ``_ZONE_TRANSFER_VALUES``.

Encrypted transports (issue #741): native DoT / DoH / DoQ listeners and
encrypted *upstream* forwarding. Both are Technitium capabilities the
other agent-managed drivers lack — BIND9 has no client-side HTTP or QUIC
transport at all, and pdns-auth speaks none of them.

Deferred to fast-follow phases: query-log shipping (#742), ``dns_import``
live-pull + blocklist wiring (#744).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
import structlog

from ..secure_io import write_private
from ._forwarders import zone_forward_transport as _zone_forward_transport
from ._process import find_running_daemon, is_zombie
from ._txt import txt_strings
from .base import RRSET_OP_KINDS, DriverBase

log = structlog.get_logger(__name__)


_API_BASE = "http://127.0.0.1:5380/api"
_API_TIMEOUT = 10.0
_ADMIN_PASSWORD_FILE = "technitium-admin-password"
_API_TOKEN_FILE = "technitium-api.token"
_TOKEN_NAME = "spatiumddi-agent"
# #1772: set after Technitium REFUSES the bootstrap credentials, so the agent
# stops presenting them. ``AuthManager.cs`` counts failed logins per client
# address (the agent's is loopback) with NO time window: the count only resets
# on a successful login or when a block expires, and every 5th failure blocks
# that address for 5 minutes (MAX_LOGIN_ATTEMPTS / BLOCK_NETWORK_INTERVAL).
# Without this marker the apply loop and every record op re-presented the
# dead password, keeping the agent's address blocked almost continuously.
_CREDS_REJECTED_FILE = "technitium-credentials-rejected.json"
# One attempt per window: at most one 5-minute loopback block per ~75 minutes
# while the credentials stay wrong, and never a standing one.
_CREDS_RETRY_SECONDS = 15 * 60
# Zones this agent created from a bundle — the only ones it may delete when
# the bundle drops them (see ``_retire_dropped_zones``).
_MANAGED_ZONES_FILE = "technitium-managed-zones.json"

# Record types whose zone-apex form is daemon-managed (SOA always; NS only
# at the apex — an off-apex NS is a legitimate delegation record and IS
# reconciled normally).
_DAEMON_MANAGED_APEX_TYPES = frozenset({"SOA"})

# ── Zone types (issue #743) ─────────────────────────────────────────────
#
# SpatiumDDI's neutral ``zone_type`` → Technitium's ``/api/zones/create``
# ``type`` param. Verified against a live technitium/dns-server:15.4.0.
_ZONE_TYPE_MAP = {
    "primary": "Primary",
    "master": "Primary",  # legacy alias used in a few older bundles
    "secondary": "Secondary",
    "slave": "Secondary",
    "stub": "Stub",
    "forward": "Forwarder",
}

# Only a primary's records are ours to manage. A secondary's and a stub's
# come from the transfer, and a forwarder has none — reconciling any of
# them would fight the daemon and delete records it just pulled.
_RECORD_MANAGED_ZONE_TYPES = frozenset({"Primary"})

# Zone types that pull a transfer and so can sign it (APIDOCS "Create Zone" /
# "Set Zone Options": ``tsigKeyName`` / ``primaryZoneTransferTsigKeyName`` are
# for Secondary, SecondaryForwarder and SecondaryCatalog; a Stub takes neither).
_TSIG_SECONDARY_ZONE_TYPES = frozenset({"Secondary", "SecondaryCatalog"})

# ``zones/options/set`` SILENTLY IGNORES a value it does not recognise —
# verified live: setting zoneTransfer="Bogus" returns {"status":"ok"} and
# leaves the previous value in place. So an unvalidated typo here would
# not fail loudly, it would leave zone transfer at whatever it was before
# (quite possibly wide open). Validate driver-side against these sets and
# refuse to send anything else.
_ZONE_TRANSFER_VALUES = frozenset(
    {
        "Deny",
        "Allow",
        "AllowOnlyZoneNameServers",
        "UseSpecifiedNetworkACL",
        # Upstream spells the combined variant WITHOUT "Only" (verified
        # against DnsServer.cs's ``AuthZoneTransfer`` switch), unlike the
        # name-servers-only variant above. The list is an allow-list of
        # values we are willing to send, and Technitium silently ignores an
        # unrecognised one, so a misspelling here would have been a value
        # that could never be set and never report why.
        "AllowZoneNameServersAndUseSpecifiedNetworkACL",
    }
)

# ── DNSSEC (issue #740) ─────────────────────────────────────────────────
#
# Signing artefacts the daemon owns. They show up in ``zones/records/get``
# the moment a zone is signed, so the reconciler MUST filter them: they
# are not in the bundle, so every pass would otherwise try to delete the
# zone's own signatures.
_DNSSEC_RECORD_TYPES = frozenset(
    {"DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DS"}
)

# Defaults for ``zones/dnssec/sign``. The neutral op carries no algorithm
# (it is a bare "sign this zone" from the UI), and BIND expresses the
# choice through a dnssec-policy name that means nothing here — so pick
# the same modern default PowerDNS's one-toggle story lands on.
# Verified live: ECDSA/P256/RSA/EDDSA and NSEC/NSEC3 all sign successfully.
_DNSSEC_SIGN_DEFAULTS = {"algorithm": "ECDSA", "curve": "P256", "nxProof": "NSEC"}

# DS digest-type name → the number that goes in a DS record's presentation
# form (RFC 4034 §5.1.3 / RFC 8624).
_DS_DIGEST_TYPES = {"SHA1": 1, "SHA256": 2, "GOST": 3, "SHA384": 4}

# Technitium key-type names → the ksk/zsk/csk vocabulary DNSKeyReport uses.
_DNSSEC_KEY_TYPES = {"KeySigningKey": "ksk", "ZoneSigningKey": "zsk"}

# ── Encrypted transports (issue #741) ───────────────────────────────────
#
# Technitium wants the TLS cert as a FILE PATH, and specifically as
# PKCS #12 — feeding it PEM fails with "DNS Server TLS certificate file
# must be PKCS #12 formatted". The bundle ships PEM (that is what BIND9
# and the ApplianceCertificate store use), so the agent converts and
# writes a .pfx into its own state dir.
_TLS_CERT_FILE = "technitium-tls.pfx"

# Zones created this pass and still held at ``queryAccess=Deny`` (#1758),
# so a pass that dies before the release is finished by the next one.
_HELD_ZONES_FILE = "technitium-zones-held.json"

# Catalog-zone state (issue #1519). The catalog zone is not in the
# bundle's zone list, so when catalog is turned off the bundle carries
# no name for the zone that has to go — the previously applied
# (zone_name, mode) pair is tracked in agent state instead, the same
# approach #1497 takes for retired zones.
_CATALOG_STATE_FILE = "technitium-catalog-state.json"
_CATALOG_ZONE_TYPES = {"producer": "Catalog", "consumer": "SecondaryCatalog"}

# Neutral forward_transport → Technitium's ``forwarderProtocol``.
_FORWARDER_PROTOCOLS = {
    "do53": "Udp",
    "tls": "Tls",
    "https": "Https",
    "quic": "Quic",
}

# Scheme of a forwarder address -> the protocol Technitium must be told to use.
# ``zones/create`` and the FWD record both default ``protocol`` to ``Udp`` and
# *re-derive the address from it*: ``NameServerAddress.Clone(Udp)`` of an
# ``https://`` address keeps the host and takes port 53, so a DoH URL silently
# became cleartext UDP to ``host:53`` (#1764; APIDOCS.md "Create Zone" /
# "Add Record", Technitium DnsServer v15.4.0). ``h3://`` and ``http://`` are
# parsed as DoH endpoints by ``NameServerAddress``.
_FORWARDER_SCHEMES = {
    "https": "Https",
    "h3": "Https",
    "http": "Https",
    "tls": "Tls",
    "quic": "Quic",
    "tcp": "Tcp",
    "udp": "Udp",
}
_DOT_PORT = "853"


def _split_host_port(text: str) -> tuple[str, str | None]:
    """``host``, ``host:port``, ``host@port``, ``[v6]``, ``[v6]:port`` or a
    bare v6 -> (host, port).

    ``ip@port`` is SpatiumDDI's neutral spelling (the group forwarder
    validator stores it, BIND's ``ip port n``); Technitium has no ``@`` form.
    """
    text = text.strip()
    if "@" in text and "://" not in text:
        host, _, port = text.rpartition("@")
        host = host.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return host, port.strip() or None
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            rest = text[end + 1 :]
            return text[1:end], (rest[1:] or None) if rest.startswith(":") else None
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, port or None
    return text, None


def _forwarder_protocol(address: str) -> str:
    """The Technitium ``protocol`` an upstream address implies (#1764).

    Scheme first (``https://`` Https, ``tls://`` Tls, ``quic://`` Quic, ...),
    then the well-known DoT port (``host:853`` Tls), otherwise plain ``Udp``.
    An optional ``name (ip)`` suffix is ignored. ``:853`` is read as DoT, not
    DoQ: only an explicit ``quic://`` selects Quic.
    """
    head = address.split(" (", 1)[0].strip()
    scheme, sep, _rest = head.partition("://")
    if sep and scheme.lower() in _FORWARDER_SCHEMES:
        return _FORWARDER_SCHEMES[scheme.lower()]
    if _split_host_port(head)[1] == _DOT_PORT:
        return "Tls"
    return "Udp"


def _forwarder_specs(forwarders: list[str]) -> list[tuple[str, str, int]]:
    """``(address, protocol, priority)`` per upstream of a forward zone.

    Priority is the list position, so the operator's order is kept: Technitium
    queries a lower value first and queries equal priorities concurrently
    (APIDOCS.md "Add Record", ``forwarderPriority``; a ``byte``, hence the cap).
    """
    out: list[tuple[str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    for address in forwarders:
        protocol = _forwarder_protocol(address)
        key = (_norm_forwarder(address), protocol)
        # A repeated upstream is one record on the daemon (identity is
        # protocol + forwarder): keeping both would update its priority back
        # and forth on every pass.
        if key in seen:
            continue
        seen.add(key)
        out.append((address, protocol, min(len(out), 255)))
    return out


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _ip_port(host: str, port: str | None) -> str:
    """``ip`` / ``ip:port`` / ``[v6]:port`` in Technitium's address format."""
    if not port:
        return host
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _technitium_forwarder(entry: str) -> str:
    """A neutral ``ip@port`` forwarder in Technitium's ``ip:port`` form.

    Anything else (a hostname, a DoH URL, ``name (ip)``) is passed on as
    written. Technitium reads ``@`` as part of a domain name, so an
    ``ip@port`` sent verbatim was never the address the operator meant.
    """
    text = str(entry).strip()
    if "@" not in text or "://" in text or "(" in text:
        return text
    host, port = _split_host_port(text)
    return _ip_port(host, port) if _is_ip(host) else text


def _norm_forwarder(address: str) -> str:
    """Comparison key for an upstream address as stored vs as sent."""
    return " ".join(str(address).lower().split()).rstrip(".")


def _address_with_ip(host_part: str, ip: str) -> str:
    """``"<host_part> (<ip>)"`` in Technitium's Name Server Address Format.

    A bare IPv6 is bracketed (APIDOCS.md "Name Server Address Format");
    ``ip:port`` and ``[v6]:port`` are passed on as written.
    """
    ip = ip.strip()
    if ip.count(":") > 1 and not ip.startswith("["):
        ip = f"[{ip}]"
    return f"{host_part} ({ip})"


def _encrypted_forwarders(forwarders: list[str], hostname: str, transport: str) -> list[str]:
    """One ``name (ip)`` entry per upstream IP for DoT / DoH / DoQ (#1764).

    The name is what the certificate is checked against; the IP in brackets
    is what Technitium dials, "instead of trying to resolve it separately"
    (APIDOCS.md "Name Server Address Format"). Sending the name alone made
    the daemon bootstrap it by plaintext recursion from the root, which
    defeats the point of encrypting and SERVFAILs where egress is limited to
    853/443. An entry that is not an IP literal cannot be paired; with none
    pairable the bare name is sent.
    """
    out: list[str] = []
    for fwd in forwarders:
        paired = _paired_address(fwd, hostname, transport, scheme=False)
        if paired is not None:
            out.append(paired)
    if out:
        return out
    return [f"https://{hostname}/dns-query" if transport == "https" else hostname]


def _paired_address(
    fwd: str, hostname: str, transport: str, *, scheme: bool
) -> str | None:
    """``fwd`` (``ip``, ``ip@port``, ``ip:port``, ``[v6]:port``) paired with
    the certificate name, or None when ``fwd`` is not an IP literal.

    The port goes on the NAME part: Technitium refuses a name and an IP
    whose ports disagree, and a DoH URL's port must be the one in the URL
    (``NameServerAddress.InternalParse``). ``scheme`` prefixes ``tls://`` /
    ``quic://`` so the address carries its own protocol, which a zone's
    FWD record needs and the server setting (``forwarderProtocol``) does not.
    """
    host, port = _split_host_port(fwd)
    if not _is_ip(host):
        return None
    if transport == "https":
        name = f"{hostname}:{port}" if port and port != "443" else hostname
        return _address_with_ip(f"https://{name}/dns-query", host)
    name = f"{hostname}:{port}" if port else hostname
    if scheme:
        name = f"{transport}://{name}"
    return _address_with_ip(name, host)


def _zone_forwarder(entry: str, zone: dict[str, Any]) -> str:
    """A forward zone's upstream as its FWD record should carry it.

    The transport is the ZONE's own ``forward_transport`` (#2121), not the
    group's: the group's applies to its resolver forwarders only. A plain IP
    with no scheme and no port, in a zone forwarding over tls/https/quic with
    a ``forward_tls_hostname``, becomes ``tls://<name> (<ip>)`` (or the DoH /
    DoQ equivalent) instead of going out as cleartext UDP. An address that
    names its own scheme or port is the operator's choice and kept, and that
    includes an explicit ``@53``: it says "this one is plain DNS", and was
    upgraded to DoT before #2121.

    A zone from a control plane older than #2121 carries no transport and
    reads as plain DNS (``_forwarders.zone_forward_transport``).
    """
    text = _technitium_forwarder(entry)
    transport, hostname = _zone_forward_transport(zone)
    if transport not in ("tls", "https", "quic") or not hostname:
        return text
    if "://" in text or "(" in text or _forwarder_protocol(text) != "Udp":
        return text
    host, port = _split_host_port(text)
    if port:
        # An explicit port on a plain address is a deliberate target; keep
        # it rather than guess what it speaks.
        return text
    paired = _paired_address(host, hostname, transport, scheme=True)
    return paired if paired is not None else text


def _dnssec_flag(raw: Any) -> bool | None:
    """Group ``dnssec_validation`` (``auto|yes|no``) -> Technitium's boolean.

    ``None`` when the bundle carries no usable value (old bundle): the
    daemon's own default then stands.
    """
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if value not in ("auto", "yes", "no"):
        return None
    return value != "no"

# ── Recursion + rate limiting (issue #1761) ─────────────────────────────
#
# ``settings/set`` silently ignores an unrecognised ``recursion`` value
# (it is parsed with a try-parse), so every value is checked against this
# set in ``_apply_recursion`` before it is sent.
_RECURSION_MODES = frozenset(
    {"Deny", "Allow", "AllowOnlyForPrivateNetworks", "UseSpecifiedNetworkACL"}
)
# BIND ACL keywords that have no CIDR spelling, expanded for Technitium's
# ``recursionNetworkACL`` (``NetworkAccessControl`` entries: CIDR or
# ``!``-prefixed CIDR).
_ACL_ANY = ("0.0.0.0/0", "::/0")
_ACL_LOCALHOST = ("127.0.0.0/8", "::1/128")
#: The stored ``allow_recursion`` default (#1817), mirroring the control
#: plane's ``app.models.dns.DEFAULT_ALLOW_RECURSION``.
_DEFAULT_ALLOW_RECURSION = (
    "localhost",
    "localnets",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
)
_ACL_LOCALNETS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
)


# ── Blocklists (issue #744) ─────────────────────────────────────────────
#
# Technitium has no RPZ. It blocks natively, either from subscribed URL
# lists or from a per-domain "blocked zones" set, so SpatiumDDI's
# effective blocklist entries map onto the latter (``blocked/import``,
# read back with ``blocked/export``) and its exceptions onto the allowed set.
#
# ``blockingType`` decides what a blocked name answers with. Like
# ``zoneTransfer`` it SILENTLY IGNORES an unrecognised value — verified:
# ``blockingType="Bogus"`` returns ok and leaves the previous mode — so it
# is validated here rather than trusted to fail loudly.
_BLOCKING_TYPES = frozenset({"NxDomain", "AnyAddress", "CustomAddress"})

# Domains per ``blocked/import`` / ``allowed/import`` call (#1425). Each
# call rewrites the zone file once, so fewer calls is cheaper; this keeps a
# single form body around 100-200 KB. ``blocked/add`` rewrote the file on
# EVERY call, which is what made a 16k-entry list take ~30 minutes.
_BLOCKING_IMPORT_CHUNK = 5000

# Neutral block_mode → Technitium blocking type. ``sinkhole`` / ``redirect``
# both answer with an operator-chosen address, which is CustomAddress;
# ``passthru`` is not a blocking mode at all (it is an exception, handled
# through the allowed set).
_BLOCK_MODE_TYPES = {
    "nxdomain": "NxDomain",
    "sinkhole": "CustomAddress",
    "redirect": "CustomAddress",
}

# Technitium's supported TSIG algorithms, as its settings API spells them.
# hmac-sha224 is deliberately absent (#1858): ``TsigKey`` names it and the
# settings API stores it, but ``DnsDatagram.GetTsigMacSize`` has no case for
# it, so a request signed with it answers BADKEY. Installing it would look
# like success and fail every signed transfer.
_TSIG_ALGORITHMS = frozenset(
    {
        "hmac-md5",
        "hmac-sha1",
        "hmac-sha256",
        "hmac-sha256-128",
        "hmac-sha384",
        "hmac-sha384-192",
        "hmac-sha512",
        "hmac-sha512-256",
    }
)


# Exact Technitium "the server is already in that state" answers (#1770).
# Matching the bare substring "already exists" also swallowed Technitium's
# CNAME/DNAME conflict refusals, which are REFUSALS: the record does not exist
# and the server keeps serving the old data. A PRIMARY zone answers "Cannot add
# record: a CNAME record cannot exists with other record types for the same
# name." (AuthZone.cs:135/145 ``TrySetRecords``, v15.4.0, no "already exists"
# in it); "Cannot add record: CNAME record already exists for the same name."
# is the base ``AuthZone.SetRecords`` text (AuthZone.cs:817), kept here as a
# defensive case. Neither is in the no-op set below.
# Upstream (TechnitiumSoftware/DnsServer v15.4.0):
#   WebServiceZonesApi.cs:4229  "Cannot add record: record already exists."
#   WebServiceZonesApi.cs:4336-4596  "Cannot delete record: no such record exists."
#   WebServiceZonesApi.cs:1661-1877  "Zone already exists: <zone>"
# Unchanged through v15.6.1. Compared whole (case-folded, trailing period
# dropped), never as a substring.
#
# Deliberately NOT a no-op: "Record already exists. Use overwrite option if
# you wish to overwrite existing record." (WebServiceZonesApi.cs:3932/4022/
# 4183). It is raised for a CNAME / DNAME / APP add with overwrite=false when
# ANY record of that type is at the name, whatever its value. This driver only
# sends overwrite=false for a record the server lacks (reconcile adds, RRset
# members after the first), so the answer means a different one holds the
# name. Same set as ``app/services/technitium/rdata.py``; pinned by the
# backend's test_technitium_svcb_parity.py.
_RECORD_ABSENT_MESSAGE = "cannot delete record: no such record exists"
_RECORD_NOOP_MESSAGES = frozenset(
    {
        "cannot add record: record already exists",
        "cannot delete record: no such record exists",
    }
)


# Keys of a record dict that are not part of its rdata: where it lives and
# what state it is in. Everything else is the value params ``records/delete``
# and ``records/update`` identify a record by.
_RECORD_STATE_KEYS = ("domain", "type", "ttl", "zone", "disabled")


def _is_reverse_zone(zone: Any) -> bool:
    name = str(zone or "").rstrip(".").lower()
    return name.endswith((".in-addr.arpa", ".ip6.arpa"))


def _norm_error(message: Any) -> str:
    return str(message or "").strip().lower().rstrip(".").strip()


def _is_record_noop(message: Any) -> bool:
    """True when Technitium says the record op was already satisfied."""
    return _norm_error(message) in _RECORD_NOOP_MESSAGES


def _is_zone_exists(message: Any) -> bool:
    """True for ``Zone already exists: <zone>`` (zone create on an existing zone)."""
    return _norm_error(message).startswith("zone already exists:")


def _qualified_name(zone_name: str, name: str) -> str:
    """Compose the bare (no trailing dot) FQDN Technitium expects for a
    record's ``domain`` param."""
    zone = zone_name.rstrip(".")
    bare = (name or "@").rstrip(".")
    if bare in ("", "@") or bare == zone:
        return zone
    return f"{bare}.{zone}"


def _shadowing_zone(domain: str, zone: str, hosted: Any) -> str | None:
    """The hosted zone that answers ``domain`` instead of ``zone``, or None (#1712).

    Technitium keeps one tree node per name, and a node BELOW a zone apex
    holds a single sub-domain zone that the parent and the child both write
    through (``AuthZoneManager.AddRecord`` → ``AuthZoneTree.GetOrAddSubDomainZone``
    → ``AuthZoneNode.GetOrAddParentSideZone``, 15.4.0). So a parent's record
    at a name inside a child zone on the same daemon lands in the child's
    data, and ``overwrite=true`` there clears the child's own RRset. The child
    owns that name, as it does on BIND9, where the deepest zone answers; the
    parent's record cannot be served from this daemon, and writing it is
    destructive.

    The child's APEX is not shadowed when the child is ONE label below the
    parent: at that node Technitium keeps the parent's side apart
    (``_parentSideZone`` beside ``_apexZone``), which is where a delegation's
    NS lives, so the parent's records at the cut are written as before.

    From 15.6.2 the daemon refuses the parent's record outright instead of
    misfiling it ("The domain name '<d>' does not belong to the zone: <z>",
    ``AuthZoneManager.GetOrAddSubDomainZone``) — and that check also refuses
    the apex of a child TWO or more labels below the parent (``a.b.p2`` in
    ``p2`` while ``a.b.p2`` is hosted), because it tests whether the name
    relative to the parent has a dot. Verified live against 15.6.2 (#2238);
    15.4.0 accepted the same write. The child still answers that name on
    this daemon, so such a record is skipped like any other shadowed one
    rather than refused on every render.

    ``hosted`` is the zone names this daemon serves (lower-case, no trailing
    dot); returns the deepest one that is a strict descendant of ``zone`` and
    strictly contains ``domain``, or is ``domain`` itself at two or more
    labels below ``zone``.
    """
    zone = zone.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    best: str | None = None
    for cand in hosted or ():
        cand = str(cand).rstrip(".").lower()
        if cand == zone or not cand.endswith("." + zone):
            continue
        inside = domain.endswith("." + cand)
        deep_apex = domain == cand and "." in cand[: -len(zone) - 1]
        if (inside or deep_apex) and (best is None or len(cand) > len(best)):
            best = cand
    return best


def _zone_is_rendered(zone: Any) -> bool:
    """Whether the structural render creates ``zone`` on the daemon (#1712).

    Mirrors the skips in ``render``'s zone loop (unsupported type, a
    secondary / stub with no masters, a forwarder with no forwarders). Only a
    zone the daemon hosts can shadow a parent's record: one the render skips
    does not exist there, and skipping the parent's record for it would leave
    the name served by nothing.
    """
    if not isinstance(zone, dict) or not str(zone.get("name") or "").rstrip("."):
        return False
    ztype = _ZONE_TYPE_MAP.get((zone.get("type") or "primary").lower())
    if ztype is None:
        return False
    if ztype in ("Secondary", "Stub"):
        return any(zone.get("masters") or [])
    if ztype == "Forwarder":
        return any(zone.get("forwarders") or [])
    return True


def _canonical_ip(value: str) -> str:
    """Canonical form of an A/AAAA value via ``ipaddress`` (#1513).

    Records are stored exactly as typed but Technitium returns addresses
    in canonical form, so an expanded/upper-case AAAA
    (``2001:DB8:0:0::1``) never string-matched and churned on every
    structural reconcile. An unparseable value passes through unchanged
    — it degrades to a comparison mismatch, not an exception.
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value


def _strip_bare_authority_slash(uri: str) -> str:
    """Strip a single trailing slash ONLY when the URI has no path
    beyond the authority (#1513).

    ``https://host/`` → ``https://host`` (Technitium appends that slash
    itself when storing a bare-authority URI, so both sides strip it),
    while ``https://host/path/`` keeps its slash — it can change the
    resource the URI points to, and the old ``rstrip("/")`` removed it.
    """
    if not uri.endswith("/"):
        return uri
    after_authority_marker = uri.split("://", 1)[-1]
    if after_authority_marker.count("/") == 1:
        return uri[:-1]
    return uri


_URI_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "gopher": 70,
    "nntp": 119,
    "telnet": 23,
    "ldap": 389,
    "ssh": 22,
    "sftp": 22,
    "ws": 80,
    "wss": 443,
}


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4, the resolution ``System.Uri`` applies to a path."""
    out: list[str] = []
    segments = path.split("/")
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        if seg == ".":
            if last:
                out.append("")
        elif seg == "..":
            if len(out) > 1:
                out.pop()
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/".join(out)


_URI_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_PCT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")


def _normalize_escapes(part: str, safe: str) -> str:
    """RFC 3986 §6.2.2 on one URI component: a percent-escape of an
    unreserved character is decoded and every other escape's hex is
    upper-cased, as ``System.Uri`` reads it back; then whatever still needs
    escaping is escaped. Applied to both sides, so ``/%41`` and ``/A`` (or
    ``%2f`` and ``%2F``) are one record rather than a delete and add on
    every pass."""

    def _one(m: re.Match[str]) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if ch in _URI_UNRESERVED else f"%{m.group(1).upper()}"

    return quote(_PCT_ESCAPE.sub(_one, part), safe=safe)


def _normalize_uri(uri: str) -> str:
    """A URI as Technitium reads it back (#1768).

    The record GET returns ``Uri.AbsoluteUri`` (WebServiceZonesApi.cs),
    which lower-cases the scheme and host, drops a scheme's default port,
    resolves ``.``/``..`` segments, percent-encodes what needs it and gives
    a bare authority a ``/`` path. Both sides of the fingerprint go through
    this, so ``https://Example.COM:443/a`` and its read-back
    ``https://example.com/a`` are one record instead of a delete and add on
    every structural pass. A value that does not parse as hierarchical is
    left as typed.
    """
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return _strip_bare_authority_slash(uri)
    if not parts.scheme or not parts.netloc or not parts.hostname:
        return _strip_bare_authority_slash(uri)
    scheme = parts.scheme.lower()
    host = _ascii_domain(parts.hostname)
    if ":" in host:
        host = f"[{host}]"
    userinfo = parts.netloc.rpartition("@")[0]
    netloc = (f"{userinfo}@" if userinfo else "") + host
    if port is not None and _URI_DEFAULT_PORTS.get(scheme) != port:
        netloc += f":{port}"
    pchar = "%:@!$&'()*+,;=-._~"
    path = _normalize_escapes(_remove_dot_segments(parts.path), "/" + pchar) or "/"
    out = f"{scheme}://{netloc}{path}"
    if parts.query:
        out += "?" + _normalize_escapes(parts.query, "/?" + pchar)
    if parts.fragment:
        out += "#" + _normalize_escapes(parts.fragment, "/?" + pchar)
    return _strip_bare_authority_slash(out)


# ── SVCB / HTTPS (RFC 9460) ────────────────────────────────────────────
#
# Three forms meet here, and every comparison reduces them to one:
#
# * PRESENTATION, what an operator stores and BIND renders verbatim:
#   ``1 svc alpn=h2,h3 port=443``. A target without a trailing dot is
#   RELATIVE to the zone (RFC 1035 §5.1), exactly as BIND reads it.
# * TECHNITIUM WIRE, what ``zones/records/{add,delete}`` parses
#   (``WebServiceZonesApi.cs``, 15.4.0): ``svcTargetName`` is trimmed of
#   dots and stored verbatim, so Technitium has no relative names at all —
#   ``svc`` is served as ``svc.``, never as ``svc.<zone>.``. ``svcParams``
#   is split on ``|`` and walked two tokens at a time (``alpn|h2,h3|port|443``),
#   or is the literal ``false`` for none — the parameter is required, so
#   omitting it is "Parameter 'svcParams' missing.". The key is
#   ``Enum.Parse<DnsSvcParamKey>`` on the name, so ``keyNNNNN`` must go as
#   its NUMBER; ``ech`` and every unnamed key fall through to
#   ``DnsSvcUnknownParamValue``, which parses HEX, not base64.
# * TECHNITIUM READ-BACK (``zones/records/get``): ``svcTargetName`` as
#   stored (no dot, ``""`` for the root), and ``svcParams`` as an object of
#   ``key -> ToString()`` in the order the record was added — ``null`` for
#   ``no-default-alpn``, ``61:62`` colon-hex for ``ech`` and unnamed keys,
#   and an unnamed key reported by its number (``"65000"``).
#
# Canonical form: params in key-NUMBER order, ``mandatory`` sorted, hint
# addresses canonical, ``ech`` as normalised base64, unnamed keys as
# ``keyN`` with an RFC 1035-escaped value, values unquoted unless they hold
# whitespace. ``alpn`` order is significant and kept.
#
# This block is duplicated byte-for-byte in
# ``backend/app/services/technitium/rdata.py`` (the agent image cannot
# import ``app``). Keep the two identical.

_SVCB_KEY_NUM = {
    "mandatory": 0,
    "alpn": 1,
    "no-default-alpn": 2,
    "port": 3,
    "ipv4hint": 4,
    "ech": 5,
    "ipv6hint": 6,
    "dohpath": 7,
}
_SVCB_KEY_NAME = {num: name for name, num in _SVCB_KEY_NUM.items()}
# Technitium ignores the value it is given for ``no-default-alpn``
# (``DnsSvcParamValue.Parse`` returns an empty ALPN value) but its splitter
# still needs a token in the value slot, and an empty one is refused.
_SVCB_VALUELESS_PLACEHOLDER = "true"
# Technitium's own spelling of "no SvcParams" (AliasMode, or a bare
# ServiceMode record).
_SVCB_NO_PARAMS = "false"


def _svcb_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return value.strip()


def _svcb_norm_key(key: str) -> str:
    """``ALPN`` / ``key1`` / ``1`` -> ``alpn``; ``key065000`` / ``65000`` ->
    ``key65000``. Technitium reports an unnamed key by its bare number."""
    k = key.strip().lower().replace("_", "-")
    if k.isascii() and k.isdigit():
        num = int(k)
    elif k.startswith("key") and k[3:].isascii() and k[3:].isdigit():
        num = int(k[3:])
    else:
        return k
    return _SVCB_KEY_NAME.get(num, f"key{num}")


def _svcb_key_num(key: str) -> int:
    if key in _SVCB_KEY_NUM:
        return _SVCB_KEY_NUM[key]
    if key.startswith("key") and key[3:].isascii() and key[3:].isdigit():
        return int(key[3:])
    return 65536


def _svcb_is_generic(key: str) -> bool:
    return key.startswith("key") and key[3:].isascii() and key[3:].isdigit()


def _svcb_split(value: str) -> list[str]:
    """Split presentation-format rdata on whitespace outside double quotes.

    Backslash escapes are kept verbatim (``alpn=h2\\,x`` keeps its escaped
    comma), unlike ``shlex.split``, which eats the backslash.
    """
    tokens: list[str] = []
    cur: list[str] = []
    in_quote = False
    it = iter(value)
    for ch in it:
        if ch == "\\":
            cur.append(ch)
            cur.append(next(it, ""))
        elif ch == '"':
            in_quote = not in_quote
            cur.append(ch)
        elif ch.isspace() and not in_quote:
            if cur:
                tokens.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        tokens.append("".join(cur))
    return tokens


def _svcb_unquote(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    return raw


def _svcb_unescape(text: str) -> bytes:
    """RFC 1035 §5.1 character-string -> bytes (``\\DDD`` and ``\\X``)."""
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            digits = text[i + 1 : i + 4]
            if len(digits) == 3 and digits.isascii() and digits.isdigit() and int(digits) < 256:
                out.append(int(digits))
                i += 4
                continue
            out.extend(text[i + 1].encode("utf-8"))
            i += 2
            continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return bytes(out)


def _svcb_escape(data: bytes) -> str:
    """bytes -> an RFC 1035 character-string needing no quotes."""
    out: list[str] = []
    for b in data:
        if b in (0x22, 0x5C):
            out.append("\\" + chr(b))
        elif 0x21 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def _svcb_hex_bytes(value: str) -> bytes | None:
    try:
        return bytes.fromhex(value.replace(":", "").replace("-", ""))
    except ValueError:
        return None


def _svcb_b64_bytes(value: str) -> bytes | None:
    try:
        return base64.b64decode(value.strip(), validate=True)
    except (ValueError, binascii.Error):
        return None


def _svcb_canon_value(key: str, val: str | None, from_daemon: bool) -> str | None:
    """One param value in canonical presentation form (``None`` = valueless).

    ``from_daemon`` says ``val`` is Technitium's read-back ``ToString()``
    (colon-hex for ``ech`` / unnamed keys) rather than presentation text.
    """
    if val is None or val == "":
        return None
    if key == "mandatory":
        names = {_svcb_norm_key(n) for n in val.split(",") if n.strip()}
        return ",".join(sorted(names, key=lambda n: (_svcb_key_num(n), n))) or None
    if key in ("ipv4hint", "ipv6hint"):
        return ",".join(_svcb_ip(a) for a in val.split(",") if a.strip())
    if key == "port":
        return str(int(val)) if val.strip().isascii() and val.strip().isdigit() else val
    if key == "ech":
        data = _svcb_hex_bytes(val) if from_daemon else _svcb_b64_bytes(val)
        return base64.b64encode(data).decode("ascii") if data is not None else val
    if _svcb_is_generic(key):
        data = _svcb_hex_bytes(val) if from_daemon else _svcb_unescape(val)
        if data is None:
            return val
        return _svcb_escape(data) or None
    return val


def _svcb_param_list(
    items: list[tuple[str, str | None]], from_daemon: bool
) -> list[tuple[str, str | None]]:
    """Canonical ``(key, value-or-None)`` list, in key-number order."""
    out: dict[str, str | None] = {}
    for raw_key, raw_val in items:
        key = _svcb_norm_key(raw_key)
        out[key] = _svcb_canon_value(key, raw_val, from_daemon)
    return sorted(out.items(), key=lambda kv: (_svcb_key_num(kv[0]), kv[0]))


def _svcb_wire_key(key: str) -> str:
    return key[3:] if _svcb_is_generic(key) else key


def _svcb_wire_value(key: str, val: str | None) -> str:
    if key == "mandatory" and val:
        return ",".join(_svcb_wire_key(n) for n in val.split(","))
    if key == "ech" and val:
        data = _svcb_b64_bytes(val)
        return data.hex().upper() if data is not None else val
    if _svcb_is_generic(key):
        return _svcb_unescape(val).hex().upper() if val else ""
    if val is None:
        # Only ``no-default-alpn`` is valueless by definition; anything else
        # sent empty is the operator's empty value, not a made-up one.
        return _SVCB_VALUELESS_PLACEHOLDER if key == "no-default-alpn" else ""
    return val


def _svcb_wire(params: list[tuple[str, str | None]]) -> str:
    """Technitium's ``svcParams`` for an already-canonical list."""
    if not params:
        return _SVCB_NO_PARAMS
    parts: list[str] = []
    for key, val in params:
        parts.append(_svcb_wire_key(key))
        parts.append(_svcb_wire_value(key, val))
    return "|".join(parts)


def _svcb_render(params: list[tuple[str, str | None]]) -> str:
    def _q(v: str) -> str:
        return f'"{v}"' if any(c.isspace() for c in v) else v

    return " ".join(k if v is None else f"{k}={_q(v)}" for k, v in params)


def _zone_file_target(name: str, origin: str | None) -> str:
    """A presentation-format name-valued target -> Technitium's form:
    absolute, lower case, no trailing dot, ``.`` for the root.

    ONE rule for every name a record points at: SVCB / HTTPS targets, CNAME,
    DNAME, NS, PTR, MX exchange, SRV target and the NAPTR replacement (#1759).
    ``@`` is the zone, a trailing dot means absolute and is honoured whatever
    the label count (``localhost.`` stays ``localhost``), and anything else
    is relative to ``origin`` (``svc`` in ``example.net`` is
    ``svc.example.net``), as in a zone file; with no origin it is left as
    written. ``.`` is the root (Null MX ``0 .``, SRV "no service"), sent as
    ``"."``: Technitium trims the dots itself, and an EMPTY parameter is
    read as missing (``Extensions.GetQueryOrFormAlt``).
    """
    name = name.strip()
    if name in ("", "."):
        return "."
    if name.endswith("."):
        return name.rstrip(".").lower() or "."
    zone = (origin or "").strip().rstrip(".").lower()
    if name == "@":
        return zone or "."
    return f"{name}.{zone}".lower() if zone else name.lower()


def _dotted_target(name: Any) -> str:
    """A target as Technitium reports it (absolute, no trailing dot, ``"."``
    for the root) -> the presentation form stored: its trailing dot, so BIND9
    reads it as absolute too. An absent value stays empty."""
    raw = str(name or "").strip()
    if not raw:
        return ""
    bare = raw.rstrip(".")
    return f"{bare}." if bare else "."


def _svcb_daemon_target(name: Any) -> str:
    """Technitium's read-back target, which is always absolute, in the same
    form ``_zone_file_target`` produces. ``""`` is the root."""
    bare = str(name or "").strip().rstrip(".").lower()
    return bare or "."


def _svcb_parse(value: str, origin: str | None) -> tuple[int, str, list[tuple[str, str | None]]]:
    tokens = _svcb_split(value)
    if len(tokens) < 2:
        return (1, ".", [])
    priority = int(tokens[0]) if tokens[0].isascii() and tokens[0].isdigit() else 1
    items: list[tuple[str, str | None]] = []
    for tok in tokens[2:]:
        key, eq, raw = tok.partition("=")
        items.append((key, _svcb_unquote(raw) if eq else None))
    return (priority, _zone_file_target(tokens[1], origin), _svcb_param_list(items, False))


def _svcb_daemon_params(raw: Any) -> list[tuple[str, str | None]]:
    """Technitium's read-back ``svcParams`` object, canonical."""
    if not isinstance(raw, dict):
        return []
    return _svcb_param_list(
        [(str(k), None if v in (None, "") else str(v)) for k, v in raw.items()], True
    )
# ── end of the block shared with the agent ──────────────────────────────


#: The bundle key a control plane from #1513 on sets to say a dot-less
#: SVCB / HTTPS target is relative to the zone (``agent_config`` sets it).
#: Without it, a dot-less target is absolute, as the older renderer meant.
SVCB_TARGET_RULE_KEY = "svcb_target_rule"
SVCB_TARGET_RULE_ZONE_FILE = "zone-file"

#: The bundle key a control plane from #1759 on sets to say a dot-less CNAME /
#: DNAME / NS / PTR / MX / SRV / NAPTR target is relative to the zone, the
#: way the SVCB marker above says it of SVCB. Separate from that key because
#: a bundle cached by a #1513 control plane carries the SVCB marker and not
#: this one, and its CNAME targets must keep the absolute reading they were
#: rendered with. Same value, same fallback: no key, absolute.
NAME_TARGET_RULE_KEY = "name_target_rule"
NAME_TARGET_RULE_ZONE_FILE = "zone-file"


def _svcb_params(value: str, origin: str | None = None) -> tuple[int, str, str]:
    """Parse a BIND-zone-file-style SVCB/HTTPS rdata string into
    ``(priority, target, svcParams)`` for the Technitium API.

    The target is relative to ``origin`` unless it ends in a dot (a
    zone-file rule; Technitium itself has no relative names, so ``svc``
    sent as-is would be served as ``svc.``). ``svcParams`` goes out in
    key-number order and ``|``-separated (``alpn|h2,h3|port|443``) — the
    comma-joined pairs this sent before #1698 only ever parsed for ONE
    param — or as ``false`` when there are none, since the API requires it.
    """
    priority, target, params = _svcb_parse(value, origin)
    return (priority, target, _svcb_wire(params))


# ── rData → add-param normalisation ────────────────────────────────────
#
# Technitium's record GET does NOT echo back the params its record ADD
# takes. For several types it renames the keys, and for TLSA/SSHFP it
# translates the numeric rdata fields into enum NAMES. Verified against a
# live technitium/dns-server:15.4.0 — e.g. adding a TLSA with
# ``tlsaCertificateUsage=3, tlsaSelector=1, tlsaMatchingType=1`` reads
# back as ``{"certificateUsage": "DANE-EE", "selector": "SPKI",
# "matchingType": "SHA2-256"}``.
#
# Without translating that back, ``_reconcile_zones`` compares desired
# add-params against daemon rData and concludes EVERY record of these
# types differs, on every single pass, forever: it issues a delete built
# from the daemon's own key names (which the delete endpoint does not
# accept, so it errors and logs a warning) and then re-adds the record.
# Permanent churn, permanent warning spam, and the zone never reads as
# converged.
#
# Types whose rData already matches the add params — A, AAAA, CNAME,
# DNAME, PTR, NS, MX, SRV, CAA — are deliberately absent here and pass
# through untouched.

_TLSA_USAGE = {"PKIX-TA": "0", "PKIX-EE": "1", "DANE-TA": "2", "DANE-EE": "3"}
_TLSA_SELECTOR = {"Cert": "0", "SPKI": "1"}
_TLSA_MATCHING = {"Full": "0", "SHA2-256": "1", "SHA2-512": "2"}
# Note 5 is absent upstream: Technitium echoes an unmapped algorithm back
# as its own number-as-string, which the ``str(v)`` fallback already
# handles correctly.
_SSHFP_ALGO = {"RSA": "1", "DSA": "2", "ECDSA": "3", "Ed25519": "4", "Ed448": "6"}
_SSHFP_FP_TYPE = {"SHA1": "1", "SHA256": "2"}


def _unmap(table: dict[str, str], value: Any) -> str:
    """Reverse an enum-name → number mapping, passing unknown values
    through as strings so a Technitium version that adds an enum member
    degrades to a comparison mismatch on that one record rather than a
    KeyError that kills the whole reconcile."""
    return table.get(str(value), str(value))


def _normalize_rdata(rtype: str, flat: dict[str, Any]) -> dict[str, Any]:
    """Rewrite one record's daemon-returned rData into the same shape
    ``_record_params`` produces, so the two are comparable and so a
    delete built from it uses param names the API accepts."""
    out = dict(flat)
    # The GET adds a derived Unicode twin of every punycode target
    # (``cnameIdn``, ``nameServerIdn``, ...). It is never a parameter the
    # record takes, so left in it made every IDN record read as changed on
    # every pass (#1768).
    for key in [k for k in out if k.endswith("Idn")]:
        del out[key]

    if rtype in ("A", "AAAA") and out.get("ipAddress"):
        # #1513: canonicalise through ipaddress — the daemon returns
        # canonical form while the desired side may be hand-typed
        # expanded/upper-case, and the fingerprint compares strings.
        out["ipAddress"] = _canonical_ip(str(out["ipAddress"]))
    # Name-valued fields are case-insensitive; fold case on the
    # read-back side (the desired side is folded in ``_record_params``)
    # so a mixed-case target cannot churn (#1513 — the Technitium
    # case-folding itself is unverified, but folding BOTH sides is
    # correct regardless of what the daemon does).
    _name_key = {
        "CNAME": "cname",
        "DNAME": "dname",
        "NS": "nameServer",
        "PTR": "ptrName",
        "MX": "exchange",
        "SRV": "target",
    }.get(rtype)
    if _name_key and out.get(_name_key):
        out[_name_key] = str(out[_name_key]).lower()

    def _move(src: str, dst: str, conv: Any = None) -> None:
        if src in out:
            val = out.pop(src)
            out[dst] = conv(val) if conv else val

    if rtype == "CAA" and "tag" in out:
        # Technitium stores the tag lower-cased (DnsCAARecordData); the
        # desired side is folded the same way in ``_record_params`` (#1768).
        out["tag"] = str(out["tag"]).lower()
    if rtype == "TLSA":
        _move("certificateUsage", "tlsaCertificateUsage", lambda v: _unmap(_TLSA_USAGE, v))
        _move("selector", "tlsaSelector", lambda v: _unmap(_TLSA_SELECTOR, v))
        _move("matchingType", "tlsaMatchingType", lambda v: _unmap(_TLSA_MATCHING, v))
        # Technitium upper-cases the hex; our renderer passes through
        # whatever the operator typed.
        _move("certificateAssociationData", "tlsaCertificateAssociationData",
              lambda v: str(v).lower())
    elif rtype == "SSHFP":
        _move("algorithm", "sshfpAlgorithm", lambda v: _unmap(_SSHFP_ALGO, v))
        _move("fingerprintType", "sshfpFingerprintType", lambda v: _unmap(_SSHFP_FP_TYPE, v))
        _move("fingerprint", "sshfpFingerprint", lambda v: str(v).lower())
    elif rtype == "NAPTR":
        _move("order", "naptrOrder")
        _move("preference", "naptrPreference")
        _move("flags", "naptrFlags")
        _move("services", "naptrServices")
        _move("regexp", "naptrRegexp")
        _move("replacement", "naptrReplacement", lambda v: str(v).lower())
    elif rtype == "URI":
        _move("priority", "uriPriority")
        _move("weight", "uriWeight")
        # Technitium normalises a bare-authority URI by appending "/".
        # Strip that one slash on both sides rather than let it churn
        # the record — but ONLY that one: a path's trailing slash is
        # significant (#1513).
        if "uri" in out:
            out["uri"] = _normalize_uri(str(out["uri"]))
    elif rtype in ("SVCB", "HTTPS"):
        # Rebuild the exact params the desired side sends (#1513): the
        # daemon reports ``svcParams`` as ``key -> ToString()`` and the
        # target as stored, which is always absolute.
        out["svcParams"] = _svcb_wire(_svcb_daemon_params(out.get("svcParams")))
        out["svcTargetName"] = _svcb_daemon_target(out.get("svcTargetName"))
    elif rtype == "TXT":
        # Only characterStringsBase64 is the record exactly (#1694): the
        # GET's ``text`` joins the strings, so "ab" and "a" "b" read the
        # same; ``characterStrings`` decodes them as UTF-8; ``splitText``
        # is derived from the string lengths.
        strings = out.pop("characterStringsBase64", None) or []
        for derived in ("text", "splitText", "characterStrings"):
            out.pop(derived, None)
        out["characterStringsBase64"] = ",".join(str(s) for s in strings)
    return out


def _technitium_master(entry: str) -> str:
    """Translate a neutral ``masters`` entry into Technitium's form.

    SpatiumDDI validates masters as ``ip`` or ``ip@port`` — BIND's
    ``masters { ip port n; }`` shape. Technitium wants ``ip:port`` and
    rejects the ``@`` outright ("Invalid domain name … invalid character
    [64]"), which would fail the zone create on every reconcile pass.
    """
    host, sep, port = str(entry).strip().partition("@")
    return f"{host}:{port}" if sep and port else host


# SOA fields the zone row owns, besides MNAME / RNAME. Shipped by the bundle
# from #1171 on; an older control plane leaves them out and the daemon's
# values stand.
_SOA_TIMERS = ("refresh", "retry", "expire", "minimum")


def _host_name(value: Any) -> str | None:
    """``value`` as the bare, lower-case host name Technitium reads back, or
    None when it cannot be one.

    ``primary_ns`` is stored with or without the trailing dot (the zone form
    keeps it, the importers strip it) and both mean an absolute name, the
    reading the BIND9 renderer gives it too (#1153). Technitium returns
    names un-dotted and lower-case, so comparing in that form is what keeps
    a converged apex from looking changed.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".").lower()
    if not name or name == "@" or not name.isascii() or ".." in name:
        return None
    if any(c.isspace() for c in name):
        return None
    return name


def _responsible_person(value: Any) -> str | None:
    """A zone's ``admin_email`` in the ``user@domain`` form Technitium stores.

    The zone row keeps the RNAME in SOA form (``hostmaster.example.com.``,
    the first unescaped dot standing for the ``@``). Technitium converts that
    itself on write, but reads it back as an address, so the comparison has
    to happen in that form. An address that already has an ``@`` is kept.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".")
    if not name or not name.isascii() or any(c.isspace() for c in name):
        return None
    if "@" in name:
        return name.lower()
    i = 0
    while True:
        i = name.find(".", i)
        if i <= 0:
            return None
        if name[i - 1] != "\\":
            break
        i += 1
    local, domain = name[:i].replace("\\.", "."), name[i + 1 :]
    return f"{local}@{domain}".lower() if domain else None


def _zone_apex(zone_name: str, zone: dict[str, Any]) -> dict[str, Any] | None:
    """The apex a primary zone should serve: its NS set and SOA fields.

    Technitium writes its own apex when it creates a zone: one NS and an
    SOA MNAME naming the server's host name, which in a pod is the pod
    name, plus a placeholder RNAME. Left alone, every server in a group
    answers with a different, unresolvable name server, and the zone's own
    Primary NS / Admin Email / SOA timers never reach the wire.

    Same precedence as the BIND9 renderer (#1153): the zone's own apex NS
    records are the NS set, else its ``primary_ns``. MNAME is ``primary_ns``,
    else the first declared NS. A field the zone does not set is left out,
    so the daemon's value stands; a zone that sets neither apex NS, Primary
    NS nor Admin Email returns None and its apex is not touched at all. The
    bundle ships every zone's SOA timers since #1171, defaults included, so
    they cannot mean the zone set anything: they ride along only with an
    apex the zone does set.
    """
    zname = zone_name.rstrip(".").lower()
    declared: list[str] = []
    declared_ttls: list[int] = []
    zone_ttl = zone.get("ttl")
    for rec in zone.get("records") or []:
        if (rec.get("type") or "").upper() != "NS":
            continue
        if _qualified_name(zname, rec.get("name") or "@").lower() != zname:
            continue
        value = str(rec.get("value") or "").strip()
        # Read the target as a zone file would: ``@`` is the apex, a name
        # without the trailing dot is relative to the zone.
        if value in ("", "@"):
            host: str | None = zname
        elif value.endswith("."):
            host = _host_name(value)
        else:
            host = _host_name(f"{value}.{zname}")
        if host and host not in declared:
            declared.append(host)
        if host:
            rec_ttl = rec.get("ttl") if rec.get("ttl") is not None else zone_ttl
            if isinstance(rec_ttl, int) and not isinstance(rec_ttl, bool) and rec_ttl >= 0:
                declared_ttls.append(rec_ttl)

    primary = _host_name(zone.get("primary_ns"))
    ns = declared or ([primary] if primary else [])

    soa: dict[str, Any] = {}
    mname = primary or (declared[0] if declared else None)
    if mname:
        soa["primaryNameServer"] = mname
    rname = _responsible_person(zone.get("admin_email"))
    if rname:
        soa["responsiblePerson"] = rname
    if not ns and not soa:
        return None
    for field in _SOA_TIMERS:
        timer = zone.get(field)
        if isinstance(timer, int) and not isinstance(timer, bool) and timer >= 0:
            soa[field] = timer
    ttl = zone.get("ttl")
    apex: dict[str, Any] = {"ns": ns, "soa": soa}
    if declared and declared_ttls:
        # One TTL for the whole set (Technitium keeps one per RRset), the
        # minimum, as the op path writes it (#1768).
        apex["ns_ttl"] = min(declared_ttls)
    if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl > 0:
        # The SOA record's own TTL caps negative caching together with
        # MINIMUM (RFC 2308), and BIND serves it at the zone's $TTL.
        apex["ttl"] = ttl
    return apex


#: Apply-failure text per ``_unapplied`` kind (once per apply, with a zone count).
_UNAPPLIED_ACL_MESSAGES = {
    "allow_query": (
        "allow_query: the group's list has an element Technitium cannot "
        "express (localnets, an undefined ACL name or a key), so query "
        "access was left as the daemon has it on {zones} zone(s)"
    ),
    "zone_allow_query": (
        "allow_query: the zone's own list has an element Technitium cannot "
        "express (localnets, an undefined ACL name or a key), so query "
        "access was left as the daemon has it on {zones} zone(s)"
    ),
    "allow_transfer": (
        "allow_transfer: the list has an element Technitium cannot express "
        "(localnets, a key beside an address, a negated key or ACL, an "
        "undefined ACL name), so zone transfer was left as the daemon has it "
        "on {zones} zone(s)"
    ),
    "also_notify": (
        "also_notify: an entry is not a plain IP address (Technitium's notify "
        "list takes addresses only, no port, key or hostname), so it was not "
        "notified on {zones} zone(s)"
    ),
    "allow_transfer_key": (
        "allow_transfer: the list names a TSIG key the daemon does not hold "
        "(missing, no secret or an unsupported algorithm), so transfer is "
        "limited to the keys it does hold on {zones} zone(s)"
    ),
}


def _usable_tsig_keys(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """The bundle's TSIG keys ``_sync_tsig_keys`` will actually install.

    A key it skips (no secret, an algorithm Technitium does not have) must not
    be pinned onto a zone either: Technitium would then demand a signature by a
    key it does not hold and refuse every transfer (#1765).
    """
    out = []
    for k in bundle.get("tsig_keys") or []:
        if not (k.get("name") or "").rstrip("."):
            continue
        if not _tsig_key_installable(k):
            continue
        out.append(k)
    return out


def _tsig_key_installable(key: dict[str, Any]) -> bool:
    return bool(key.get("secret")) and (
        (key.get("algorithm") or "hmac-sha256").lower() in _TSIG_ALGORITHMS
    )


def _tsig_key_names(bundle: dict[str, Any]) -> list[str]:
    """Names of the bundle's installable TSIG keys, root dot stripped.

    Technitium stores names un-dotted (verified: sending ``spatium-xfer.``
    reads back as ``spatium-xfer``), so normalise here or every options
    comparison sees a difference that isn't one.
    """
    return sorted({(k.get("name") or "").rstrip(".") for k in _usable_tsig_keys(bundle)})


def _bundle_acls(bundle: dict[str, Any]) -> dict[str, list[tuple[str, bool]]]:
    """The bundle's named ACLs (#899) as ``name -> [(value, negate)]``."""
    out: dict[str, list[tuple[str, bool]]] = {}
    for acl in bundle.get("acls") or []:
        name = str(acl.get("name") or "").strip()
        if name:
            out[name] = [
                (str(e.get("value") or ""), bool(e.get("negate")))
                for e in acl.get("entries") or []
            ]
    return out


# ── BIND address-match translation (#1765)
#
# SpatiumDDI stores ``allow_query`` / ``allow_transfer`` as BIND address-match
# lists. Technitium has no such grammar: a network ACL is an ordered list of
# addresses / CIDRs where a leading ``!`` denies and the first match wins
# (APIDOCS "Set Zone Options", ``NetworkAccessControl.cs``), no match denies,
# and transfer TSIG keys are a SEPARATE set that is ANDed with the ACL
# (``DnsServer.cs``: ``IsZoneTransferAllowed`` then ``IsTsigAuthenticated``).
# This block translates what can be translated exactly and raises
# ``AddressMatchError`` for everything else, because a guess either widens
# access or locks the zone out. It is shared, byte for byte, with the agent
# (``test_technitium_acl_parity.py``).
_OPEN_ACL: list[str] = ["0.0.0.0/0", "::/0"]
_V4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_KEY_ELEMENT = re.compile(r'^key\s+"?([A-Za-z0-9][A-Za-z0-9_.-]*)"?$', re.IGNORECASE)


class AddressMatchError(ValueError):
    """The list holds an element Technitium cannot express exactly."""


def _flatten_address_match(
    elements: list[Any], acls: dict[str, list[tuple[str, bool]]], trail: tuple[str, ...]
) -> list[tuple[bool, str, str]]:
    """Ordered ``(negated, kind, value)`` items, named ACLs expanded inline.

    ``kind`` is ``net`` / ``any`` / ``key`` (``none`` arrives as a negated
    ``any``, which is what BIND compiles it to). BIND flattens a nested
    ACL into the list that cites it, so first-match order is preserved.
    """
    items: list[tuple[bool, str, str]] = []
    for raw in elements:
        text = str(raw).strip()
        if not text:
            continue
        neg = text.startswith("!")
        body = text[1:].strip() if neg else text
        low = body.lower()
        if low == "any":
            items.append((neg, "any", ""))
            continue
        if low == "none":
            # BIND compiles ``none`` as ``!any`` (aclconf.c: "none == !any"):
            # a match that DENIES everyone, ending the list there. So
            # ``["none", "10.0.0.0/8"]`` admits nobody, and ``!none`` admits
            # everyone. Dropping it instead would let the later elements grant.
            items.append((not neg, "any", ""))
            continue
        if low == "localhost":
            if neg:
                raise AddressMatchError(
                    "'!localhost' cannot be applied: Technitium has no equivalent of the "
                    "server's own addresses, so the exclusion would be lost"
                )
            items.append((False, "net", "127.0.0.1/32"))
            items.append((False, "net", "::1/128"))
            continue
        if low == "localnets":
            raise AddressMatchError(
                "'localnets' cannot be applied: Technitium has no equivalent of the "
                "server's directly attached networks"
            )
        key = _KEY_ELEMENT.match(body)
        if key:
            if neg:
                raise AddressMatchError(f"'!{body}' cannot be applied: a key cannot be negated")
            items.append((False, "key", key.group(1)))
            continue
        try:
            net = ipaddress.ip_network(body, strict=False)
        except ValueError:
            pass
        else:
            if net.version == 6 and net.subnet_of(_V4_MAPPED):  # type: ignore[arg-type]
                raise AddressMatchError(
                    f"{body!r} cannot be applied: Technitium matches an IPv4-mapped client "
                    "as IPv4, so an IPv4-mapped prefix would never match; write the IPv4 "
                    "prefix instead"
                )
            items.append((neg, "net", str(net)))
            continue
        if body not in acls:
            raise AddressMatchError(
                f"{body!r} is not an address, a CIDR prefix, 'key <name>' or an ACL defined in "
                "this group"
            )
        if body in trail:
            raise AddressMatchError(f"ACL {body!r} refers to itself")
        inner = _flatten_address_match(
            [
                ("!" if n or v.startswith("!") else "") + v.lstrip("!").strip()
                for v, n in acls[body]
            ],
            acls,
            (*trail, body),
        )
        if neg:
            if any(i[0] or i[1] == "key" for i in inner):
                raise AddressMatchError(
                    f"'!{body}' cannot be applied: the ACL holds a negation or a key, and "
                    "inverting it is not a prefix list"
                )
            inner = [(True, k, v) for _, k, v in inner]
        items.extend(inner)
    return items


def translate_address_match(
    elements: Any,
    acls: dict[str, list[tuple[str, bool]]] | None = None,
    *,
    allow_keys: bool = False,
) -> tuple[list[str], list[str]]:
    """BIND address-match list -> ``(technitium_acl, key_names)``.

    ``acl`` is an ordered list for ``*NetworkACL`` (``!`` kept, ``any`` as both
    default routes, ``none`` as their negation); ``key_names`` are the ``key X`` elements.
    With keys present the result is the negations followed by the open ACL, to
    be ANDed with the key set: that is exact only while every address element
    is a negation placed before the first key. A positive address beside a key
    is an OR in BIND and an AND here, so it is refused rather than narrowed.
    """
    items = _flatten_address_match(list(elements or []), acls or {}, ())
    # A deny-everyone match (``none`` / ``!any``) ends evaluation in BIND and in
    # Technitium alike, so nothing after it is reachable: drop the tail rather
    # than refuse an element that can never take effect.
    deny_all = next((i for i, it in enumerate(items) if it[0] and it[1] == "any"), None)
    if deny_all is not None:
        items = items[: deny_all + 1]
    first_key = next((i for i, it in enumerate(items) if it[1] == "key"), None)
    if first_key is not None and deny_all is not None and deny_all > first_key:
        # ``[key X, none]``: after the keys, a final deny-all only restates
        # "no match denies", which holds in both systems.
        items = items[:deny_all]
    if first_key is not None and not allow_keys:
        raise AddressMatchError("'key <name>' cannot be applied to this list")
    acl: list[str] = []
    keys: list[str] = []
    for index, (neg, kind, value) in enumerate(items):
        if kind == "key":
            if value not in keys:
                keys.append(value)
            continue
        if first_key is not None:
            if not neg:
                raise AddressMatchError(
                    "an address listed next to 'key <name>' is an OR in BIND but Technitium "
                    "requires the address AND the key, so it cannot be applied"
                )
            if index > first_key:
                raise AddressMatchError(
                    "a negation listed after 'key <name>' cannot be applied: BIND lets the key "
                    "through first, Technitium would still apply the exclusion"
                )
        for net in _OPEN_ACL if kind == "any" else [value]:
            acl.append(("!" if neg else "") + net)
    if first_key is not None:
        acl.extend(_OPEN_ACL)
    return acl, keys


# ── end of the block shared with the agent


# Zone types whose queries the group's ``allow_query`` governs. BIND applies
# an options-level ``allow-query`` to every query the server receives, a
# conditional-forward zone's included, so a Forwarder zone carries it too
# (Technitium's "Set Zone Options" accepts ``queryAccess`` on every zone type
# but ``SecondaryCatalog``). A catalog zone is not a served namespace.
_QUERY_ACCESS_ZONE_TYPES = frozenset({"Primary", "Secondary", "Stub", "Forwarder"})


def _query_access(
    allow_query: Any, acls: dict[str, list[tuple[str, bool]]] | None = None
) -> tuple[str, list[str]] | None:
    """Translate a group's BIND ``allow-query`` list into Technitium's
    per-zone ``queryAccess`` + ``queryAccessNetworkACL`` (#1763, #1765).

    Parameters per APIDOCS.md, "Set Zone Options" (TechnitiumSoftware/
    DnsServer v15.4.0): ``queryAccess`` is one of ``Deny`` / ``Allow`` /
    ``AllowOnlyPrivateNetworks`` / ``AllowOnlyZoneNameServers`` /
    ``UseSpecifiedNetworkACL`` / ``AllowZoneNameServersAndUseSpecifiedNetworkACL``;
    ``queryAccessNetworkACL`` is a comma separated list of IPs / networks, a
    leading ``!`` denies, evaluated in order, and "if no networks match, the
    default policy is to deny all except loopback".

    The grammar is ``translate_address_match``'s: addresses, ``!`` negations,
    ``localhost`` and named ACLs from the bundle. Returns ``None`` when the
    list holds an element with no Technitium equivalent (``localnets``, a key,
    an undefined ACL name): the caller leaves the zone alone and says so,
    because guessing would either widen the access or lock the zone out.

    Empty / absent means ``any``, as the BIND9 agent reads it. ``none`` is
    NOT a no-op: BIND compiles it as ``!any`` (``aclconf.c``: "none ==
    !any"), so ``["none", "10.0.0.0/8"]`` admits nobody.
    """
    elements = [str(e).strip() for e in (allow_query or []) if str(e).strip()]
    if not elements:
        return "Allow", []
    lowered = [e.lower() for e in elements]
    if lowered == ["any"]:
        return "Allow", []
    if lowered == ["none"]:
        return "Deny", []
    try:
        acl, _ = translate_address_match(elements, acls, allow_keys=False)
    except AddressMatchError:
        return None
    if not acl:
        return "Deny", []
    if acl == _OPEN_ACL:
        return "Allow", []
    return "UseSpecifiedNetworkACL", acl


def _transfer_access(
    source: Any,
    names: list[str],
    acls: dict[str, list[tuple[str, bool]]] | None = None,
) -> tuple[str, list[str], list[str], list[str]] | None:
    """Translate an ``allow_transfer`` list into
    ``(zoneTransfer, zoneTransferNetworkACL, zoneTransferTsigKeyNames, missing)``.

    ``names`` are the group's installable TSIG keys. Technitium ANDs the
    network ACL with the key set (``DnsServer.cs``), so ``Allow`` + names is
    "any source, but signed by one of these" (#734).

    * empty / ``none``: the #734 posture, ``Allow`` + every key, or ``Deny``
      when the group has none;
    * ``key X``: only the named keys that are installed. ``missing`` lists
      the ones that are not; when none are, the zone is denied rather than
      left open to a signature nobody can make;
    * an address list: the translated ACL, plus every group key as before.

    ``None`` when the list cannot be expressed exactly.
    """
    elements = [str(a).strip() for a in (source or []) if str(a).strip()]
    if not elements or {e.lower() for e in elements} == {"none"}:
        return ("Allow" if names else "Deny"), [], names, []
    try:
        acl, keys = translate_address_match(elements, acls, allow_keys=True)
    except AddressMatchError:
        return None
    missing: list[str] = []
    if keys:
        installed = {n.lower(): n for n in names}
        wanted = [installed[k.lower()] for k in keys if k.lower() in installed]
        missing = [k for k in keys if k.lower() not in installed]
        if not wanted:
            return "Deny", [], [], missing
        names = sorted(set(wanted))
    if not acl:
        return "Deny", [], [], missing
    if acl == _OPEN_ACL:
        return "Allow", [], names, missing
    return "UseSpecifiedNetworkACL", acl, names, missing


#: Zone types whose NOTIFY the group / zone settings govern (#2267). Technitium
#: accepts ``notify`` on Primary and Secondary zones; a Stub or Forwarder zone
#: has nothing to notify (BIND renders no notify for them either).
_NOTIFY_ZONE_TYPES = frozenset({"Primary", "Secondary"})

#: BIND's ``notify`` choices that notify from Primary zones only.
_NOTIFY_PRIMARY_ONLY = frozenset({"master-only", "primary-only"})


def _notify_options(
    ztype: str, bundle: dict[str, Any], zone: dict[str, Any] | None
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Translate the group's / zone's BIND ``notify`` + ``also-notify`` into
    Technitium's per-zone ``notify`` + ``notifyNameServers`` (#2267).

    Technitium defaults every zone to ``ZoneNameServers``, so without this a
    stealth primary (``notify no``) still notified its NS hosts and
    also-notify targets were never notified. The mapping mirrors BIND:

    * ``yes``: the NS set, plus the also-notify list when there is one
      (``BothZoneAndSpecifiedNameServers``);
    * ``explicit``: only the also-notify list (``SpecifiedNameServers``);
    * ``no``: ``None``;
    * ``master-only`` / ``primary-only``: as ``yes`` on a Primary, ``None``
      on a Secondary.

    The zone's own value shadows the group's; ``None`` inherits, and so does
    an empty also-notify list (the BIND9 agent renders nothing for one).
    ``explicit`` with no targets is ``None``: BIND notifies nobody then.
    Always sent, ``notifyNameServers`` included (empty clears), so switching
    back to ``yes`` does not strand an old target list on the zone.
    Technitium's list takes bare addresses; any other entry is skipped and
    reported rather than guessed at.
    """
    opts = bundle.get("options") or {}
    z = zone or {}
    mode = str(z.get("notify_enabled") or opts.get("notify_enabled") or "yes").strip().lower()
    own = z.get("also_notify")
    raw = own if own else opts.get("also_notify")
    targets: list[str] = []
    bad = False
    for entry in raw or []:
        text = str(entry).strip()
        if not text:
            continue
        try:
            targets.append(str(ipaddress.ip_address(text)))
        except ValueError:
            bad = True
    unapplied = (
        [{"kind": "also_notify", "reason": "also_notify has an entry that is not an IP address"}]
        if bad
        else []
    )
    if mode in _NOTIFY_PRIMARY_ONLY:
        mode = "yes" if ztype == "Primary" else "no"
    if mode == "no":
        notify = "None"
    elif mode == "explicit":
        notify = "SpecifiedNameServers" if targets else "None"
    else:
        notify = "BothZoneAndSpecifiedNameServers" if targets else "ZoneNameServers"
    if notify in ("None", "ZoneNameServers"):
        targets = []
    return {"notify": notify, "notifyNameServers": targets}, unapplied


#: Zone types whose OWN ``allow_query`` overrides the group's (#2263). BIND
#: accepts a zone-level ``allow-query`` on master / slave / stub zones only,
#: and the BIND9 agent renders it there and nowhere else, so a Forwarder zone
#: keeps the group's list here too.
_ZONE_QUERY_OVERRIDE_TYPES = frozenset({"Primary", "Secondary", "Stub"})


def _effective_allow_query(
    ztype: str, bundle: dict[str, Any], zone: dict[str, Any] | None
) -> tuple[Any, bool]:
    """The ``allow_query`` list in force for one zone, and whether it is the
    zone's own (#2263).

    The zone's value shadows the group's, as a zone-level ``allow-query``
    does in BIND. ``None`` inherits; so does an empty list, because the
    BIND9 agent renders nothing for one and the zone then falls back to the
    options-level list. Reading ``[]`` as ``Allow`` here would open a zone
    the group restricts.
    """
    own = (zone or {}).get("allow_query")
    if (
        ztype in _ZONE_QUERY_OVERRIDE_TYPES
        and own is not None
        and any(str(e).strip() for e in own)
    ):
        return own, True
    return (bundle.get("options") or {}).get("allow_query"), False


def _zone_options_payload(
    ztype: str, bundle: dict[str, Any], zone: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Map the bundle's transfer policy onto Technitium's per-zone options.

    BIND expresses ``allow-transfer`` once for the whole server and lets a
    zone override it; Technitium has no global equivalent, so the effective
    policy is resolved here and stamped onto each zone we own. Only
    meaningful for zones this server is authoritative for — a Secondary/Stub
    transfers *in*, and re-serving it is a separate decision we do not make
    on the operator's behalf.

    ``zone["allow_transfer"]`` (#734) overrides the server-level list when
    set; ``None`` means inherit, matching how the BIND9 agent treats the
    same field. Without this the per-zone value would ship in the bundle and
    be silently ignored here — which is the exact defect #734 is about, one
    driver over.

    The list follows BIND's vocabulary and is translated by
    ``_transfer_access`` (#1765): ``["none"]`` (or empty) denies, ``key X``
    becomes the key set, ``localhost`` loopback, named ACLs are expanded, and
    ``!`` exclusions stay in order under ``UseSpecifiedNetworkACL``. A list
    with an element Technitium cannot express is left alone and reported in
    ``_unapplied`` — it used to be guessed at, which turned
    ``["!10.1.0.0/16", "any"]`` into ``Allow`` and lost the exclusion.

    Issue #734: ``none`` is the default, so honouring it literally left the
    control plane unable to read any zone — the drift report and
    sync-with-servers both AXFR, and both got REFUSED on every install
    nobody had hand-configured. When the group has TSIG keys we therefore
    fall back to ``Allow`` + ``zoneTransferTsigKeyNames``, which Technitium
    reads as "from any source, but the transfer must be signed by one of
    these keys". That is the same posture the BIND9 agent renders as
    ``allow-transfer { key "…"; };`` and is narrower than an address ACL,
    not wider: it demands possession of a secret.
    """
    payload: dict[str, Any] = {}
    unapplied: list[dict[str, str]] = []
    acls = _bundle_acls(bundle)
    if ztype in _QUERY_ACCESS_ZONE_TYPES:
        # The group's ``allow_query`` (#1763), or the zone's own (#2263).
        # Always sent, ``Allow`` included, so widening the list back to
        # ``any`` un-restricts a zone an earlier bundle restricted; an empty
        # ACL clears the stored one.
        source, own = _effective_allow_query(ztype, bundle, zone)
        qa = _query_access(source, acls)
        if qa is None:
            unapplied.append(
                {
                    "kind": "zone_allow_query" if own else "allow_query",
                    "reason": "allow_query has an element Technitium cannot express",
                }
            )
            if own:
                # A Primary this pass creates is held at ``Deny`` and then
                # released (#1758); with no query access to release it to,
                # the release falls back to ``Allow``. For a zone whose own
                # list is meant to restrict it, that is wider than the group's
                # list, which a zone without the override would have got. So
                # the release uses the group's list when it is expressible
                # (#2263). An existing zone is still left as the daemon has it.
                group_qa = _query_access((bundle.get("options") or {}).get("allow_query"), acls)
                if group_qa is not None:
                    payload["_release_query_access"] = group_qa
        else:
            payload["queryAccess"] = qa[0]
            payload["queryAccessNetworkACL"] = qa[1]
    if ztype in _NOTIFY_ZONE_TYPES:
        notify, notify_unapplied = _notify_options(ztype, bundle, zone)
        payload.update(notify)
        unapplied.extend(notify_unapplied)
    if ztype != "Primary":
        if unapplied:
            payload["_unapplied"] = unapplied
        return payload
    opts = bundle.get("options") or {}
    zone_acl = (zone or {}).get("allow_transfer")
    source = zone_acl if zone_acl is not None else opts.get("allow_transfer")
    transfer = _transfer_access(source, _tsig_key_names(bundle), acls)
    if transfer is None:
        unapplied.append(
            {
                "kind": "allow_transfer",
                "reason": "allow_transfer has an element Technitium cannot express",
            }
        )
    else:
        mode, acl, names, missing = transfer
        payload["zoneTransfer"] = mode
        if acl:
            payload["zoneTransferNetworkACL"] = acl
        # Naming keys here is what makes a transfer TSIG-*authenticated*
        # rather than merely address-filtered.
        #
        # ALWAYS sent, including empty. Technitium treats an absent parameter
        # as "leave unchanged" and an empty one as "clear" (verified in
        # upstream ``WebServiceZonesApi.cs``: ``Length == 0`` sets the set to
        # null). So omitting it when the group's last key is deleted would
        # strand the old key names on every zone, and transfers from an
        # otherwise-permitted network would then fail forever, demanding a
        # signature by a key that no longer exists anywhere. The control plane
        # is the source of truth for this list, the same stance
        # ``_sync_tsig_keys`` takes for the keys.
        #
        # On a Deny zone the list is necessarily empty (the translation only
        # picks Deny when there are no keys to name), so this never reads as
        # "signed transfer enabled" on a zone that cannot transfer at all.
        payload["zoneTransferTsigKeyNames"] = names
        if missing:
            unapplied.append(
                {
                    "kind": "allow_transfer_key",
                    "reason": "allow_transfer names key(s) the daemon does not hold: "
                    + ", ".join(missing),
                }
            )
    if unapplied:
        payload["_unapplied"] = unapplied
    return payload


def _ascii_domain(domain: Any) -> str:
    """A domain as Technitium stores it: lower case, no trailing dot, IDNA.

    Technitium converts a Unicode name to its ASCII form on import, and
    ``export`` returns that form, so the desired set has to be compared in
    it too or an IDN entry would read as changed on every apply.
    """
    name = str(domain).strip().rstrip(".").lower()
    if name.isascii():
        return name
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def _blocking_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    """Flatten the bundle's effective blocklists into Technitium's shape.

    SpatiumDDI models blocking as RPZ zones with per-entry actions;
    Technitium has a flat blocked-domain set plus an allowed set that
    overrides it. So:

    * ``action="block"`` entries become blocked domains.
    * ``action="allow"`` / ``block_mode="passthru"`` entries, and each
      list's ``exceptions``, become allowed domains — Technitium's
      allowed set is exactly an RPZ passthru.
    * ``action="redirect"`` entries are **dropped**, and logged. They
      need a per-domain CNAME rewrite; Technitium's custom address is
      server-wide, so there is nothing here to express them with.
      Neither branch above is right for them — routing them to
      ``allowed`` (which is what happened before #878) inverts a
      SafeSearch rule into an exemption, and blocking them would take
      the search engine off the air.

    Per-view blocklists collapse into the same flat set: Technitium's
    native blocking is server-wide with no view concept, and the driver
    already declines views outright. Collapsing is the honest reading of
    "block these names on this server" — the alternative would be to
    silently apply one view's list to every client.

    ``is_wildcard`` is dropped deliberately: Technitium blocks a domain
    *and its subdomains* by default, so an exact-match entry and a
    wildcard entry land the same way. Flagged in the driver docs rather
    than silently pretending the distinction survives.
    """
    blocked: set[str] = set()
    allowed: set[str] = set()
    modes: set[str] = set()
    custom_addresses: set[str] = set()
    invalid_addresses: set[str] = set()
    skipped_redirects: set[str] = set()

    for bl in bundle.get("blocklists") or []:
        for exc in bl.get("exceptions") or []:
            if exc:
                allowed.add(str(exc).rstrip(".").lower())
        for entry in bl.get("entries") or []:
            domain = str(entry.get("domain") or "").rstrip(".").lower()
            if not domain:
                continue
            action = str(entry.get("action") or "block").lower()
            mode = str(entry.get("block_mode") or "nxdomain").lower()
            if action == "redirect":
                # Technitium's native blocking has no per-domain rewrite:
                # it can answer a blocked name with a custom address, but
                # that address is server-wide, so "send www.google.com to
                # forcesafesearch.google.com" cannot be expressed. Skipping
                # is the honest answer. Falling through to the allow branch
                # below — which is what happened before #878 — inverted the
                # entry into "never block this domain", quietly turning a
                # SafeSearch rule into an exemption.
                skipped_redirects.add(domain)
                continue
            if action != "block" or mode == "passthru":
                allowed.add(domain)
                continue
            blocked.add(domain)
            mapped = _BLOCK_MODE_TYPES.get(mode)
            if mapped:
                modes.add(mapped)
            if mode in ("sinkhole", "redirect"):
                # The list's ``sinkhole_ip`` is what a sinkhole answers with
                # (#2124); it used to be ignored here, so a sinkhole list
                # with no per-entry target fell back to NxDomain. A value
                # that is not an IP address is left out rather than handed
                # to Technitium, which would refuse the whole settings call.
                for candidate in (entry.get("sinkhole_ip"), entry.get("target")):
                    if candidate:
                        try:
                            custom_addresses.add(
                                str(ipaddress.ip_address(str(candidate).strip()))
                            )
                        except ValueError:
                            invalid_addresses.add(str(candidate))

    if skipped_redirects:
        log.warning(
            "technitium_redirect_entries_unsupported",
            count=len(skipped_redirects),
            sample=sorted(skipped_redirects)[:5],
            detail=(
                "Per-domain redirect entries (e.g. SafeSearch enforcement) "
                "need RPZ CNAME rewrites, which Technitium's native blocking "
                "cannot express. Those entries are not enforced on this "
                "server; use a BIND9 group if they matter."
            ),
        )

    if invalid_addresses:
        log.warning(
            "technitium_sinkhole_address_unusable",
            sample=sorted(invalid_addresses)[:5],
            detail=(
                "A sinkhole address is not an IP address and was left out; "
                "blocked names answer with the unspecified address instead."
            ),
        )

    # One server-wide blocking type has to cover every entry. If the lists
    # disagree, prefer the address-answering mode: it is the more specific
    # intent (an operator asked for a sinkhole), and NxDomain would drop
    # the sinkhole silently.
    #
    # Same answer the BIND9 renderer gives (#2124): both families, the
    # list's address replacing the unspecified address of its own family.
    # A sinkhole with no address at all is AnyAddress — Technitium's name
    # for exactly 0.0.0.0 / :: — rather than a CustomAddress with nothing
    # in it, which the apply step would turn into NxDomain.
    if "CustomAddress" in modes:
        if custom_addresses:
            blocking_type = "CustomAddress"
            families = {ipaddress.ip_address(a).version for a in custom_addresses}
            if 4 not in families:
                custom_addresses.add("0.0.0.0")
            if 6 not in families:
                custom_addresses.add("::")
        else:
            blocking_type = "AnyAddress"
    else:
        blocking_type = "NxDomain"

    return {
        "enabled": bool(blocked),
        "blocked": sorted(blocked),
        "allowed": sorted(allowed),
        "blocking_type": blocking_type,
        "custom_addresses": sorted(custom_addresses),
    }


def _txt_params(value: str) -> dict[str, Any]:
    """A TXT value as the character-strings it stands for (#1694).

    Technitium's ``text`` param is the text itself, so the quotes of an
    already-quoted value (``"v=spf1 -all"``, as providers print SPF,
    DMARC and DKIM values) were served as part of the string, two quoted
    strings could not stay two, and a ``\\DDD`` octet that is not UTF-8
    could not be sent at all. ``characterStringsBase64`` takes the strings
    themselves, octet for octet, comma-separated. They come from the parse
    the BIND9 and PowerDNS drivers render (``_txt.txt_strings``), so the
    three engines serve the same strings, and the record GET hands the same
    list back for ``_normalize_rdata`` to compare and delete by.

    Technitium cannot hold an empty character-string: it drops one from the
    list, and a record left with no string at all is served as a malformed
    packet. So empty strings are left out here as well, and what is compared
    is what the server holds. A value that is nothing but empty strings
    (``""``) goes as its text, as it did before #1694, and an empty value is
    refused by the server, as before.
    """
    strings = [s for s in txt_strings(value) if s]
    if not strings:
        if not value:
            return {"text": ""}
        # As the ``text`` param took it: one string, cut every 255 octets.
        raw = value.encode("utf-8")
        strings = [raw[i : i + 255] for i in range(0, len(raw), 255)]
    return {
        "characterStringsBase64": ",".join(
            base64.b64encode(s).decode("ascii") for s in strings
        )
    }


def _record_params(
    rtype: str,
    value: str,
    rec: dict[str, Any],
    origin: str | None = None,
    name_origin: str | None = None,
) -> dict[str, Any]:
    """Build the type-specific param dict for
    ``/api/zones/records/{add,delete}`` — shared by both endpoints since
    ``delete`` requires the exact same value params to identify the record.
    """
    if rtype in ("SVCB", "HTTPS"):
        # Before the blanket rstrip: a trailing dot on the TARGET is what
        # says it is absolute (a bare one is relative to the zone).
        # ``svcParams`` is always sent: the API requires it (``false`` = none).
        priority, target, params = _svcb_params(value, origin)
        return {"svcPriority": priority, "svcTargetName": target, "svcParams": params}
    if rtype == "TXT":
        # Text, not a name: it keeps a trailing full stop (#1694).
        return _txt_params(value)
    raw = value
    value = value.rstrip(".")

    def _target(name: str) -> str:
        # The one target rule for every name-valued type (#1759): ``@`` is
        # the zone, a trailing dot is absolute, anything else is relative to
        # the zone, ``.`` is the root and goes out as ``"."`` (Technitium
        # reads an empty parameter as missing). ``name_origin`` is None for
        # a bundle that predates the rule: a dot-less target is absolute.
        if name_origin is None:
            target = name.rstrip(".").lower() or "."
        else:
            target = _zone_file_target(name, name_origin)
        # IDNA, as Technitium stores it, so an IDN target compares equal to
        # its read-back instead of churning every pass (#1768).
        return target if target == "." else _ascii_domain(target)

    if rtype in ("A", "AAAA"):
        # Canonicalised (#1513) so the desired side matches the daemon's
        # canonical read-back regardless of how the operator typed it.
        return {"ipAddress": _canonical_ip(value)}
    # Name-valued targets are folded to lower case on BOTH sides of the
    # fingerprint (#1513); DNS names are case-insensitive.
    if rtype == "CNAME":
        return {"cname": _target(raw)}
    if rtype == "DNAME":
        return {"dname": _target(raw)}
    if rtype == "NS":
        return {"nameServer": _target(raw)}
    if rtype == "PTR":
        return {"ptrName": _target(raw)}
    if rtype == "MX":
        # Absence, not falsiness — preference 0 is the highest priority
        # (Microsoft 365 publishes it), and ``or 10`` silently promoted
        # it to a backup. Issue #1518.
        return {
            "exchange": _target(raw),
            "preference": rec.get("priority") if rec.get("priority") is not None else 10,
        }
    if rtype == "SRV":
        return {
            "target": _target(raw),
            "priority": rec.get("priority") if rec.get("priority") is not None else 0,
            "weight": rec.get("weight") if rec.get("weight") is not None else 0,
            "port": rec.get("port") if rec.get("port") is not None else 0,
        }
    if rtype == "CAA":
        # value shape: "<flags> <tag> <target>", e.g. '0 issue "letsencrypt.org"'
        tokens = shlex.split(value)
        flags = int(tokens[0]) if tokens and tokens[0].isascii() and tokens[0].isdigit() else 0
        # Lower-cased: Technitium stores the tag that way (#1768).
        tag = tokens[1].lower() if len(tokens) > 1 else "issue"
        target = tokens[2] if len(tokens) > 2 else ""
        return {"flags": flags, "tag": tag, "value": target}
    if rtype == "TLSA":
        tokens = shlex.split(value)
        return {
            "tlsaCertificateUsage": tokens[0] if len(tokens) > 0 else "0",
            "tlsaSelector": tokens[1] if len(tokens) > 1 else "0",
            "tlsaMatchingType": tokens[2] if len(tokens) > 2 else "0",
            # Lower-cased to match _normalize_rdata's read-back side —
            # Technitium upper-cases the stored hex.
            "tlsaCertificateAssociationData": (
                tokens[3].lower() if len(tokens) > 3 else ""
            ),
        }
    if rtype == "SSHFP":
        tokens = shlex.split(value)
        return {
            "sshfpAlgorithm": tokens[0] if len(tokens) > 0 else "0",
            "sshfpFingerprintType": tokens[1] if len(tokens) > 1 else "0",
            "sshfpFingerprint": tokens[2].lower() if len(tokens) > 2 else "",
        }
    if rtype == "NAPTR":
        # The replacement is the last token and its trailing dot says it is
        # absolute, so split ``raw``, not the rstripped value (#1759).
        tokens = shlex.split(raw if name_origin is not None else value)
        return {
            "naptrOrder": tokens[0] if len(tokens) > 0 else "0",
            "naptrPreference": tokens[1] if len(tokens) > 1 else "0",
            "naptrFlags": tokens[2] if len(tokens) > 2 else "",
            "naptrServices": tokens[3] if len(tokens) > 3 else "",
            "naptrRegexp": tokens[4] if len(tokens) > 4 else "",
            "naptrReplacement": _target(tokens[5] if len(tokens) > 5 else "."),
        }
    if rtype == "URI":
        tokens = shlex.split(value)
        return {
            "uriPriority": tokens[0] if len(tokens) > 0 else "1",
            "uriWeight": tokens[1] if len(tokens) > 1 else "1",
            # Only a bare-authority trailing slash is stripped (#1513) —
            # Technitium appends one there when it stores the record,
            # but a path's trailing slash is part of the target.
            "uri": _normalize_uri(tokens[2]) if len(tokens) > 2 else "",
        }
    # Unrecognised type — pass the raw value through under a best-guess key
    # so the API's own error message tells us what's missing, rather than
    # silently dropping the record.
    return {"value": value}


class TechnitiumCredentialsError(RuntimeError):
    """Technitium refused the agent's admin credentials (#1772).

    ``reason`` is ``bad-credentials`` or ``2fa-required``. The text is what
    reaches the control plane as the #882 apply-status ``error``, so it
    names the cause and the way out rather than "no API token available".
    """

    #: Raised before any authenticated call succeeds — every call in an apply
    #: carries the same token — so the daemon has taken nothing from this
    #: apply and there is nothing to revert (see ``ConfigApplyError``).
    daemon_untouched = True

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        super().__init__(_creds_message(reason, detail))


def _creds_message(reason: str, detail: str = "") -> str:
    if reason == "2fa-required":
        what = (
            "Technitium requires a two-factor code for the 'admin' account "
            "(2fa-required), so the agent cannot mint a new API token"
        )
    elif reason == "locked-out":
        what = (
            "Technitium has blocked logins from the agent's address after "
            "repeated failures (locked-out), so the agent cannot mint a new "
            "API token; the block lifts after 5 minutes"
        )
    else:
        what = (
            "Technitium rejected the agent's stored admin password "
            "(bad-credentials), so the agent cannot mint a new API token"
        )
    fix = (
        "Recovery: disable TOTP on 'admin', or make the two passwords agree — "
        "write Technitium's current 'admin' password into "
        "technitium-admin-password in the agent state directory (the file is "
        "regenerated if the state volume was lost), or set 'admin' in "
        "Technitium to the password in that file. Changing that file, or "
        "deleting technitium-credentials-rejected.json beside it, retries at "
        "once; otherwise the agent retries at most every 15 minutes to stay "
        "clear of Technitium's 5-attempt login lockout"
    )
    return f"{what}. {fix}." + (f" Technitium said: {detail}" if detail else "")


class TechnitiumDriver(DriverBase):
    """Technitium agent driver — v1."""

    # Per-apply refusal collector (#1516). ``swap_and_reload`` installs a
    # list here; the log-and-continue helpers below append every step the
    # daemon refused, and ``swap_and_reload`` hands the list to
    # ``refused_zones()`` (#1280's partial apply). The apply still lands:
    # the sync loop reports the refusals, commits the bundle and keeps
    # draining record ops, instead of quarantining the whole bundle and
    # holding back every later change behind the one refused record. A
    # transport / auth failure is not a refusal — ``_call`` raises those,
    # which fails the apply as before. ``None`` outside an apply (record
    # ops, direct helper calls) means "log only", preserving the helpers'
    # standalone behaviour.
    _apply_failures: list[str] | None = None

    # How a dot-less SVCB / HTTPS target in the bundle is read (#1513). A
    # control plane from before #1513 rendered a dot-less target meaning
    # ABSOLUTE (it was sent to the daemon as-is, and Technitium has no
    # relative names); one from #1513 on means relative to the zone, as in a
    # zone file, and says so with ``svcb_target_rule: "zone-file"`` in the
    # bundle. Set by ``render`` from the bundle being applied, so replaying a
    # cached bundle from the older control plane keeps its own meaning, and
    # read by ``apply_record_op`` for ops shipped beside that bundle.
    _svcb_zone_file_targets: bool = False
    # The same, for every other name-valued target (#1759), read from
    # ``name_target_rule``. Independent of the SVCB flag: a bundle cached by
    # a #1513 control plane has the SVCB marker and not this one.
    _name_zone_file_targets: bool = False

    # Zones whose group ``allow_query`` this apply could not express (#1763),
    # collected by ``_apply_zone_options`` and reported ONCE by
    # ``swap_and_reload``: the cause is one group option, and a refusal per
    # zone would bury every other refusal in the truncated apply error.
    _unapplied_acl: dict[str, list[str]] | None = None

    def _note_apply_failure(self, what: str) -> None:
        if self._apply_failures is not None:
            self._apply_failures.append(what)

    def _svcb_origin(self, zone: str) -> str | None:
        """The origin a dot-less SVCB target is relative to, or ``None`` when
        the applied bundle predates #1513 and a dot-less target is absolute."""
        return zone if self._svcb_zone_file_targets else None

    def _name_origin(self, zone: str) -> str | None:
        """The origin a dot-less CNAME / DNAME / NS / PTR / MX / SRV / NAPTR
        target is relative to, or ``None`` when the applied bundle predates
        #1759 and a dot-less target is absolute."""
        return zone if self._name_zone_file_targets else None


    # ── Render / validate / swap ────────────────────────────────────────────

    def render(self, bundle: dict[str, Any]) -> None:
        """Stash the desired-state JSON for the API reconciler.

        There is no config file to write for this driver — Technitium's
        own on-disk state under ``/etc/dns`` is entirely daemon-managed.
        The bundle-to-JSON step exists purely so ``swap_and_reload`` has a
        stable, atomically-swapped snapshot to reconcile against (matches
        the render → validate → swap_and_reload shape every driver shares).
        """
        new_dir = self.state_dir / "rendered.new"
        if new_dir.exists():
            shutil.rmtree(new_dir)
        new_dir.mkdir(parents=True)

        self._svcb_zone_file_targets = bundle.get(SVCB_TARGET_RULE_KEY) == SVCB_TARGET_RULE_ZONE_FILE
        self._name_zone_file_targets = bundle.get(NAME_TARGET_RULE_KEY) == NAME_TARGET_RULE_ZONE_FILE

        raw_zones = bundle.get("zones")
        if not isinstance(raw_zones, list):
            raw_zones = None
        # Every zone name the bundle carries, including the ones skipped
        # below: ``_retire_dropped_zones`` must not delete a zone SpatiumDDI
        # still has just because this driver could not render it. ``None``
        # when the bundle has no zone list at all, which is not the same
        # claim as an empty one and retires nothing.
        bundle_zone_names = (
            None
            if raw_zones is None
            else sorted(
                {
                    str(z.get("name") or "").rstrip(".").lower()
                    for z in raw_zones
                    if isinstance(z, dict) and str(z.get("name") or "").rstrip(".")
                }
            )
        )
        # The zones this render creates on the daemon (#1712): only those can
        # shadow a parent's record. Not ``bundle_zone_names``, which keeps the
        # skipped ones too.
        hosted_zone_names = sorted(
            {
                str(z.get("name") or "").rstrip(".").lower()
                for z in raw_zones or []
                if _zone_is_rendered(z)
            }
        )

        # The key a secondary signs with is always one of the group's own
        # (#1765): the control plane names only a key this group holds with
        # the same secret as one its master grants, so no other group's
        # secret is ever installed here.
        server_tsig_keys = list(bundle.get("tsig_keys") or [])
        installable_keys = {
            (k.get("name") or "").rstrip(".").lower(): (k.get("name") or "").rstrip(".")
            for k in _usable_tsig_keys(bundle)
        }

        def _signing_key(name: Any, where: str) -> str | None:
            """The installed spelling of a transfer key, or None (and say so)."""
            wanted = str(name or "").rstrip(".")
            if not wanted:
                return None
            if wanted.lower() in installable_keys:
                return installable_keys[wanted.lower()]
            log.warning("technitium_transfer_key_not_installed", where=where, key=wanted)
            return None

        zones_payload = []
        for zone in raw_zones or []:
            zname = (zone.get("name") or "").rstrip(".")
            if not zname:
                continue
            raw_type = (zone.get("type") or "primary").lower()
            ztype = _ZONE_TYPE_MAP.get(raw_type)
            if ztype is None:
                log.warning(
                    "technitium_zone_type_unsupported",
                    zone=zname,
                    zone_type=raw_type,
                    supported=sorted(_ZONE_TYPE_MAP),
                )
                continue
            masters = [str(m) for m in (zone.get("masters") or []) if m]
            forwarders = [str(f) for f in (zone.get("forwarders") or []) if f]
            # Secondary/stub transfer FROM a primary, so with no address to
            # transfer from there is nothing to create — Technitium rejects
            # the create outright. Skip rather than fail the whole render.
            if ztype in ("Secondary", "Stub") and not masters:
                log.warning(
                    "technitium_zone_missing_masters", zone=zname, zone_type=raw_type
                )
                continue
            if ztype == "Forwarder" and not forwarders:
                log.warning("technitium_zone_missing_forwarders", zone=zname)
                continue

            records = []
            # Only a primary's records are ours. A secondary/stub fills
            # itself from the transfer and a forwarder holds none, so
            # rendering records for them would make the reconciler delete
            # whatever the daemon just pulled down.
            if ztype in _RECORD_MANAGED_ZONE_TYPES:
                for rec in zone.get("records") or []:
                    rtype = (rec.get("type") or "").upper()
                    if rtype in _DAEMON_MANAGED_APEX_TYPES:
                        continue
                    name = _qualified_name(zname, rec.get("name") or "@")
                    shadow = _shadowing_zone(name, zname, hosted_zone_names)
                    if shadow is not None:
                        # #1712: the child zone owns this name on the daemon.
                        log.warning(
                            "technitium_record_shadowed_by_child_zone",
                            zone=zname,
                            name=name,
                            type=rtype,
                            child_zone=shadow,
                        )
                        continue
                    if rtype == "NS" and name == zname:
                        # Apex NS is reconciled with the SOA, as a set
                        # (``_zone_apex`` / ``_reconcile_zone_apex``), not
                        # record by record: the daemon writes its own apex
                        # NS at zone create. Off-apex NS (delegations) are
                        # handled normally.
                        continue
                    # Absence, not falsiness — a TTL of 0 means "never
                    # cache" and must survive the structural reconcile
                    # exactly as the incremental op path writes it.
                    # Issue #1518.
                    _rec_ttl = rec.get("ttl")
                    _zone_ttl = zone.get("ttl")
                    records.append(
                        {
                            "domain": name,
                            "type": rtype,
                            "ttl": (
                                _rec_ttl
                                if _rec_ttl is not None
                                else (_zone_ttl if _zone_ttl is not None else 3600)
                            ),
                            **_record_params(
                                rtype,
                                rec.get("value") or "",
                                rec,
                                self._svcb_origin(zname),
                                self._name_origin(zname),
                            ),
                        }
                    )

            # Technitium keeps ONE TTL per RRset: adding a record rewrites
            # every sibling to the new record's TTL (AuthZone.AddRecord).
            # The op path already writes the set minimum (``rrset.py``), so
            # stamp it here too, or a set with mixed TTLs flips between its
            # members' values on every structural pass (#1768). Technitium-
            # only: BIND9 and PowerDNS render per-record TTLs unchanged.
            set_ttl: dict[tuple[str, str], int] = {}
            for r in records:
                key = (r["domain"], r["type"])
                set_ttl[key] = min(set_ttl.get(key, r["ttl"]), r["ttl"])
            for r in records:
                r["ttl"] = set_ttl[(r["domain"], r["type"])]

            entry: dict[str, Any] = {
                "zone": zname,
                "type": ztype,
                "records": records,
                # Drives ``zones/options/set``. Absent/empty values are not
                # sent at all, so the daemon default stands rather than us
                # stamping an opinion onto every zone.
                "options": _zone_options_payload(ztype, bundle, zone),
            }
            if masters:
                entry["masters"] = masters
            if ztype == "Secondary":
                # Stub has no transfer, so no key (APIDOCS "Create Zone":
                # ``tsigKeyName`` is for Secondary / SecondaryForwarder /
                # SecondaryCatalog).
                signing = _signing_key(zone.get("masters_tsig_key"), zname)
                if signing:
                    entry["tsig_key"] = signing
                elif zone.get("masters_tsig_key") or zone.get("masters_tsig_unresolved"):
                    # A SpatiumDDI master requires a signed transfer and there
                    # is no key to sign with: say so instead of creating a
                    # zone that is refused every AXFR and expires.
                    entry["tsig_unresolved"] = True
            if forwarders:
                entry["forwarders"] = [_zone_forwarder(f, zone) for f in forwarders]
            if ztype == "Forwarder":
                dnssec = _dnssec_flag((bundle.get("options") or {}).get("dnssec_validation"))
                if dnssec is not None:
                    entry["dnssec_validation"] = dnssec
            if ztype in _RECORD_MANAGED_ZONE_TYPES:
                apex = _zone_apex(zname, zone)
                if apex is not None:
                    entry["apex"] = apex
            zones_payload.append(entry)


        (new_dir / "zones.json").write_text(json.dumps(zones_payload, indent=2))

        # Server-scoped state the zone loop can't express (issue #743).
        # Written to its own file, and 0600: unlike zones.json this one
        # carries TSIG shared secrets.
        catalog = bundle.get("catalog") or bundle.get("catalog_block") or None
        if catalog and catalog.get("producer_tsig_key"):
            catalog = {
                **catalog,
                "producer_tsig_key": _signing_key(
                    catalog.get("producer_tsig_key"), "catalog consumer"
                ),
            }
        server_payload = {
            # Encrypted transports + forwarders (#741). Carried verbatim so
            # swap_and_reload can apply them without re-reading the bundle.
            "options": bundle.get("options") or {},
            "tls_cert": bundle.get("tls_cert") or None,
            # Blocklists (#744). Flattened here rather than in the apply
            # path so the rendered snapshot is the whole desired state.
            "blocking": _blocking_payload(bundle),
            "tsig_keys": [
                {
                    "name": (k.get("name") or "").rstrip("."),
                    "secret": k.get("secret") or "",
                    "algorithm": (k.get("algorithm") or "hmac-sha256").lower(),
                }
                for k in server_tsig_keys
                if (k.get("name") or "").rstrip(".")
            ],
            "catalog": catalog,
            "bundle_zone_names": bundle_zone_names,
            "hosted_zone_names": hosted_zone_names,
        }
        self._write_secret(
            new_dir / "server.json", json.dumps(server_payload, indent=2)
        )

    def validate(self) -> None:
        new_dir = self.state_dir / "rendered.new"
        zones_path = new_dir / "zones.json"
        if not zones_path.exists():
            raise RuntimeError("zones.json was not written")
        try:
            json.loads(zones_path.read_text())
        except ValueError as exc:
            raise RuntimeError(f"zones.json is not valid JSON: {exc}") from exc

    def swap_and_reload(self) -> None:
        """Promote the new render into place and reconcile via REST.

        Cold-boot ordering mirrors PowerDNS: the supervisor calls
        ``start_daemon`` before the first ``apply_config``, so on first
        boot the daemon may still be initializing its web server when we
        get here. Wait for the API before reconciling — otherwise the
        first call fails with connection-refused, the reconcile silently
        gives up, and the structural etag has already advanced so the
        sync loop never retries.
        """
        new_dir = self.state_dir / "rendered.new"
        current = self.state_dir / "rendered"
        backup = self.state_dir / "rendered.prev"
        if current.exists():
            if backup.exists():
                shutil.rmtree(backup)
            current.rename(backup)
        new_dir.rename(current)

        if not self.daemon_running():
            log.info("technitium_daemon_starting_after_first_render")
            self.start_daemon()
        self._wait_for_api_up()

        zones_path = current / "zones.json"
        try:
            payload = json.loads(zones_path.read_text())
        except Exception as exc:
            log.error("technitium_zones_payload_unreadable", error=str(exc))
            # #1516: returning normally here read as a successful apply —
            # the sync loop advanced the etag, reported the serials as
            # served and committed the bundle as last-known-good with
            # nothing applied at all. Raise so the #882 quarantine /
            # revert path engages and the bundle is retried — this is our
            # own state failing, not the daemon refusing data.
            raise RuntimeError(f"technitium zones.json unreadable: {exc}") from exc

        token = self._get_api_token()
        if token is None:
            log.error("technitium_reconcile_skipped_no_token")
            raise RuntimeError("technitium reconcile skipped: no API token available")

        # TSIG keys first: a zone's ``zoneTransferTsigKeyNames`` is accepted
        # even when it names a key the server does not have (verified — the
        # API stores it happily), and the failure only shows up later as a
        # refused transfer. Push the keys before anything references them.
        #
        # Every step below still runs even when an earlier one is refused
        # (#1516): attempt everything, collect the refusals, and report
        # them through ``refused_zones()`` so the apply reads as a partial
        # one rather than as success (#1280's model).
        self._apply_failures = []
        self._unapplied_acl = {}
        try:
            server_path = current / "server.json"
            server_state: dict[str, Any] = {}
            server_state_known = False
            if server_path.exists():
                try:
                    server_state = json.loads(server_path.read_text())
                    server_state_known = True
                except ValueError as exc:
                    # Our own render, unreadable: the TSIG / transport /
                    # blocking state is unknown rather than refused, so this
                    # fails the apply outright.
                    log.error("technitium_server_payload_unreadable", error=str(exc))
                    raise RuntimeError(f"technitium server.json unreadable: {exc}") from exc
            # #1517: unconditional whenever server.json was readable —
            # an emptied key list is a real desired state and the callee
            # clears every key on the daemon. Only an unreadable (or
            # missing) server.json skips it: then the desired list is
            # unknown, not empty, and clearing would be a guess.
            if server_state_known:
                self._sync_tsig_keys(token, server_state.get("tsig_keys") or [])

            # Encrypted listeners + upstream forwarding (#741). Before the zone
            # reconcile so a slow zone pass cannot delay bringing a listener up.
            server_options = server_state.get("options") or {}
            if server_options:
                self._apply_transport_settings(
                    token, server_options, server_state.get("tls_cert")
                )
                self._apply_forwarders(token, server_options)
                self._apply_dnssec_validation(token, server_options)
                # #1761: recursion policy + per-client rate limit. Both
                # have daemon defaults that stay in force unless sent.
                self._apply_recursion(token, server_options)
                self._apply_rate_limits(token, server_options)

            # Blocklists (#744). Always applied, even when empty — an emptied
            # list has to actually clear on the daemon.
            self._apply_blocking(token, server_state.get("blocking") or {})

            # Retire before reconciling: Technitium files a parent's record
            # under the closest zone it hosts, so a dropped child zone that
            # shadows it takes the record along on delete. The reconcile
            # below then puts it back in the parent in the same pass.
            self._retire_dropped_zones(
                token,
                payload,
                backup / "zones.json",
                bundle_zone_names=server_state.get("bundle_zone_names"),
            )
            self._reconcile_zones(token, payload)
            self._apply_catalog(token, server_state.get("catalog"), payload)
            unsigned = sorted(e["zone"] for e in payload if e.get("tsig_unresolved"))
            if unsigned:
                self._note_apply_failure(
                    "secondary zone(s) "
                    + ", ".join(unsigned)
                    + ": the master is a SpatiumDDI server that requires a signed "
                    "transfer and this group holds no key it grants (add the same TSIG "
                    "key, name and secret, to both groups), so every transfer will be "
                    "refused"
                )
            for kind, skipped in sorted((self._unapplied_acl or {}).items()):
                self._note_apply_failure(_UNAPPLIED_ACL_MESSAGES[kind].format(zones=len(skipped)))
            failures = list(self._apply_failures)
        finally:
            self._apply_failures = None
            self._unapplied_acl = None
        # Partial apply, not a failure (#1280): every step the daemon took is
        # live, and re-applying this bundle or the last-known-good cannot make
        # it accept what it just refused — the QA walk of #1608 showed a
        # raise here quarantining the bundle, holding back every later change
        # to the group, and the revert deleting records it had just added.
        self._refused_zones = tuple(failures)
        if failures:
            log.warning(
                "technitium_apply_partly_refused", count=len(failures), refused=failures[:10]
            )

    def _managed_zones_path(self) -> Path:
        return self.state_dir / _MANAGED_ZONES_FILE

    def _retire_dropped_zones(
        self,
        token: str,
        payload: list[dict[str, Any]],
        previous_render: Path,
        *,
        bundle_zone_names: list[str] | None,
    ) -> None:
        """Delete the zones this agent put on the daemon that the bundle dropped.

        ``_reconcile_zones`` creates every zone in the bundle and never
        deletes one, so a zone deleted in SpatiumDDI kept answering on every
        Technitium server, authoritatively, with the records it last had.
        BIND9 has no such gap: a zone that leaves the bundle leaves
        ``named.conf``.

        Only zones in the ledger are candidates, and the ledger holds only
        names this agent got from a bundle. A zone an operator created on
        the daemon directly is never in it, so it is never touched. The
        ledger is seeded from the previous render the first time (an agent
        upgraded from a version without it), so a zone dropped by the very
        bundle that brought the upgrade is still retired; anything orphaned
        before that is left for the operator. A delete that fails keeps its
        name in the ledger so the next pass retries it.

        Retirement follows the zone list the control plane sent, not what
        this driver managed to render, so two cases hold it back:

        * ``bundle_zone_names`` is ``None``: the bundle had no zone list
          (key absent, ``null``, not a list) or ``server.json`` could not be
          read. Nothing is deleted and the ledger is kept. An explicit empty
          list is different: it is what a group with no zones sends, and
          every zone in the ledger is retired, as BIND9 empties
          ``named.conf``.
        * A zone the bundle still names but the render skipped (a type
          Technitium cannot serve, a secondary with no primaries, a
          forwarder with no upstream) stays, and stays in the ledger.
        """
        desired = {str(z.get("zone") or "").lower() for z in payload if z.get("zone")}
        path = self._managed_zones_path()
        managed: set[str]
        try:
            managed = {str(n).lower() for n in json.loads(path.read_text())}
        except FileNotFoundError:
            managed = set()
            try:
                previous = json.loads(previous_render.read_text())
                managed = {str(z.get("zone") or "").lower() for z in previous if z.get("zone")}
            except (OSError, ValueError, AttributeError):
                pass
        except (OSError, ValueError, TypeError) as exc:
            # An unreadable ledger must not turn into "delete nothing ever"
            # silently, nor into a guess. Rebuild it from this bundle.
            log.warning("technitium_managed_zones_unreadable", error=str(exc))
            managed = set()

        if not isinstance(bundle_zone_names, list):
            if managed - desired:
                log.warning(
                    "technitium_zone_retire_held_back",
                    reason="bundle_has_no_zone_list",
                    zones=sorted(managed - desired),
                )
            self._write_secret(path, json.dumps(sorted(managed | desired)))
            return

        named = {str(n).lower() for n in bundle_zone_names}
        held = (managed - desired) & named
        if held:
            log.warning(
                "technitium_zone_retire_held_back",
                reason="zone_still_in_bundle",
                zones=sorted(held),
            )

        kept: set[str] = set()
        for zone in sorted(managed - desired - named):
            body = self._call(token, "POST", "zones/delete", {"zone": zone}).json()
            error = body.get("errorMessage") or ""
            if body.get("status") == "ok":
                log.info("technitium_zone_retired", zone=zone)
            elif "no such zone" in error.lower() or "does not exist" in error.lower():
                pass  # already gone, e.g. removed by hand
            else:
                kept.add(zone)
                log.warning("technitium_zone_retire_failed", zone=zone, error=error)

        self._write_secret(path, json.dumps(sorted(desired | held | kept)))

    def _sync_tsig_keys(self, token: str, keys: list[dict[str, Any]]) -> None:
        """Publish the bundle's TSIG keys into Technitium's global settings.

        Wire format is a FLAT pipe-delimited token list read in triples —
        ``name|secret|algorithm|name2|secret2|algorithm2|…`` — not one
        pipe-joined record per key and not JSON. Both of those were tried
        against a live daemon: JSON and a 2-token record fail with "Offset
        and length were out of bounds for the array", which is the arity
        check complaining, and a ``name|algorithm|secret`` ordering fails
        with "TSIG algorithm is not supported" because it reads the secret
        as the algorithm.

        ``settings/set`` REPLACES the whole key list, so anything an
        operator added directly in the Technitium console is dropped on the
        next sync. That is the same "control plane is the source of truth"
        stance the rest of the driver takes, but it is worth knowing.
        """
        tokens: list[str] = []
        for k in keys:
            name = (k.get("name") or "").rstrip(".")
            secret = k.get("secret") or ""
            algorithm = (k.get("algorithm") or "hmac-sha256").lower()
            if not name:
                continue
            if not secret:
                log.warning("technitium_tsig_key_without_secret", key=name)
                self._note_apply_failure(f"tsig key {name}: no secret, so it was not installed")
                continue
            if algorithm not in _TSIG_ALGORITHMS:
                log.warning(
                    "technitium_tsig_algorithm_unsupported",
                    key=name,
                    algorithm=algorithm,
                    supported=sorted(_TSIG_ALGORITHMS),
                )
                # Reported, not just logged (#1765): a skipped key is not
                # pinned onto the zones (``_tsig_key_names``), so a transfer
                # signed with it is refused and the operator needs to know
                # why.
                self._note_apply_failure(
                    f"tsig key {name}: algorithm {algorithm} is not supported by "
                    "Technitium, so it was not installed"
                )
                continue
            tokens.extend([name, secret, algorithm])
        # An empty set is a real desired state, not "nothing to do": a
        # revoked key that is never cleared stays installed and signed
        # transfers keep working. Same bug class as the forwarders path.
        resp = self._call(token, "POST", "settings/set", {"tsigKeys": "|".join(tokens)})
        body = resp.json()
        if body.get("status") != "ok":
            log.error(
                "technitium_tsig_keys_apply_failed", error=body.get("errorMessage")
            )
            self._note_apply_failure(f"tsig keys: {body.get('errorMessage')}")
        else:
            log.info("technitium_tsig_keys_applied", count=len(tokens) // 3)

    def _apply_catalog(
        self, token: str, catalog: dict[str, Any] | None, payload: list[dict[str, Any]]
    ) -> None:
        """Apply the group's catalog-zone role.

        **Producer** creates the ``Catalog`` zone and stamps
        ``catalog=<name>`` onto each primary this server owns.

        **Consumer** creates a ``SecondaryCatalog`` zone pointed at the
        producer. That zone is NOT in the bundle's zone list — the control
        plane ships it as a catalog block, not as a zone row — so it has to
        be created here or a consumer silently does nothing at all.

        **Neither** (catalog turned off) clears membership. Without that,
        disabling catalog zones would leave every member permanently
        enrolled, because nothing else ever touches the option.

        The catalog zone itself is also deleted whenever it stops
        being the desired one (issue #1519): catalog off, a renamed
        catalog zone, or a producer↔consumer flip. A flip has to delete
        first — creating the new role under the same name answers
        "already exists", which the create path treats as success, so
        the zone would silently keep its old type. The previously
        applied role is read from agent state (``_CATALOG_STATE_FILE``)
        because a disabled catalog block carries no zone name at all.
        """
        cat_name = (catalog or {}).get("zone_name") or ""
        cat_name = cat_name.rstrip(".")
        mode = (catalog or {}).get("mode")

        if mode == "consumer":
            producer = (catalog or {}).get("producer_addr")
            if not (cat_name and producer):
                log.warning(
                    "technitium_catalog_consumer_incomplete",
                    zone=cat_name or None,
                    producer=producer,
                )
                self._note_apply_failure("catalog consumer: incomplete catalog block")
                return
            self._retire_stale_catalog_zone(token, cat_name, mode)
            self._ensure_zone_exists(
                token,
                {
                    "zone": cat_name,
                    "type": "SecondaryCatalog",
                    "masters": [str(producer)],
                    "tsig_key": (catalog or {}).get("producer_tsig_key"),
                },
            )
            self._save_catalog_state({"zone_name": cat_name, "mode": mode})
            return

        desired_type = _CATALOG_ZONE_TYPES.get(mode or "") if cat_name else None
        self._retire_stale_catalog_zone(token, cat_name, mode)

        if mode == "producer" and cat_name:
            self._ensure_zone_exists(token, {"zone": cat_name, "type": "Catalog"})

        # Producer stamps the name on; disabled clears it. Empty string is
        # how Technitium clears the field (verified — it reads back null).
        desired = cat_name if (mode == "producer" and cat_name) else ""
        for entry in payload:
            if entry.get("type") != "Primary":
                continue
            zone = entry["zone"]
            resp = self._call(
                token, "POST", "zones/options/set", {"zone": zone, "catalog": desired}
            )
            body = resp.json()
            if body.get("status") != "ok":
                log.warning(
                    "technitium_catalog_membership_failed",
                    zone=zone,
                    catalog=desired or None,
                    error=body.get("errorMessage"),
                )
                self._note_apply_failure(
                    f"catalog membership {zone}: {body.get('errorMessage')}"
                )
        self._save_catalog_state(
            {"zone_name": cat_name, "mode": mode} if desired_type else None
        )

    # ── Catalog-zone state (issue #1519) ───────────────────────────────

    def _catalog_state_path(self) -> Path:
        return self.state_dir / _CATALOG_STATE_FILE

    def _load_catalog_state(self) -> dict[str, Any] | None:
        try:
            state = json.loads(self._catalog_state_path().read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(state, dict) or not state.get("zone_name"):
            return None
        return state

    def _save_catalog_state(self, state: dict[str, Any] | None) -> None:
        path = self._catalog_state_path()
        if state is None:
            path.unlink(missing_ok=True)
            return
        path.write_text(json.dumps(state))

    def _retire_stale_catalog_zone(
        self, token: str, cat_name: str, mode: str | None
    ) -> None:
        """Delete the previously applied catalog zone if it is no
        longer the desired one (different name, different role, or
        catalog now off)."""
        prev = self._load_catalog_state()
        if prev is None:
            return
        prev_name = str(prev.get("zone_name") or "").rstrip(".")
        prev_type = _CATALOG_ZONE_TYPES.get(str(prev.get("mode") or ""))
        if not prev_name or prev_type is None:
            return
        desired_type = _CATALOG_ZONE_TYPES.get(mode or "") if cat_name else None
        if prev_name == cat_name and prev_type == desired_type:
            return
        resp = self._call(token, "POST", "zones/delete", {"zone": prev_name})
        body = resp.json()
        if body.get("status") != "ok":
            log.warning(
                "technitium_catalog_zone_delete_failed",
                zone=prev_name,
                zone_type=prev_type,
                error=body.get("errorMessage"),
            )
        else:
            log.info(
                "technitium_catalog_zone_retired",
                zone=prev_name,
                zone_type=prev_type,
            )

    def _wait_for_api_up(self, *, timeout_s: float = 15.0) -> None:
        deadline = time.monotonic() + timeout_s
        with httpx.Client(timeout=1.0) as client:
            while time.monotonic() < deadline:
                try:
                    resp = client.get(f"{_API_BASE}/user/session/get")
                    if resp.status_code < 500:
                        return
                except httpx.HTTPError:
                    # Expected while the daemon is still starting: connect
                    # refused / read timeout until its web server binds
                    # :5380. That is precisely what this loop is polling
                    # for, so swallow and retry until the deadline; the
                    # timeout warning below is what surfaces a real
                    # failure to come up.
                    pass
                time.sleep(0.3)
        log.warning("technitium_api_wait_timeout", timeout_s=timeout_s)

    # ── Record ops (REST calls against loopback API) ────────────────────────

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        """Apply a single record op via the Technitium REST API.

        ``create``/``update`` map to ``/api/zones/records/add`` with
        ``overwrite=true``. The op payload only ever carries the NEW
        value, never the old one, so a value *change* has to be
        expressed as an rrset REPLACE — exactly what BIND9's driver does
        with ``dns.update.Update.replace`` and PowerDNS's with an rrset
        ``REPLACE`` PATCH. ``overwrite=true`` is Technitium's
        equivalent: it wipes the rrset at ``(domain, type)`` and writes
        the new value + TTL.

        Do NOT revert this to ``overwrite=false``. Technitium *appends*
        at that setting, so an edited record ends up served alongside
        its own previous value — verified against a live
        ``technitium/dns-server:15.4.0``: adding ``www A 10.0.0.2``
        over an existing ``www A 10.0.0.1`` leaves the zone answering
        both, round-robin. That does not self-heal, because record CRUD
        bumps the bundle's ``etag`` but not its ``structural_etag``, so
        ``swap_and_reload``'s full-zone reconcile never runs on a record
        edit (see ``sync.py``).

        (A TTL-only edit is *not* affected either way — ``overwrite=false``
        updates the TTL of a value-identical record rather than erroring.
        Only the value-change case needs the REPLACE.)

        The op payload now carries the complete desired ``rrset`` (#773) —
        the control plane knows the whole set, which is the only place that
        knowledge exists — so the normal path replays it as N calls: member 0
        with ``overwrite=true`` to clear, the rest with ``overwrite=false`` to
        append. That is a whole-RRset replace expressed in the vocabulary this
        API has, and it is what keeps a name with several values (round-robin
        A, a backup MX, SPF beside a verification TXT) from collapsing to
        whichever op landed last.

        ``rrset_action`` is the older project-wide per-op override (see
        ``bind9.py``) and remains the fallback for an op enqueued by a control
        plane that predates ``rrset``: DNS pools set ``"add"`` because N A
        records share one name there and a REPLACE would clobber siblings
        every time a member is added.
        """
        token = self._get_api_token()
        if token is None:
            raise RuntimeError("no Technitium API token available")

        zone = op["zone_name"].rstrip(".")
        op_kind = op["op"]

        # DNSSEC ops (issue #740) are zone-level, not rrset-shaped. They
        # ride the same record-op queue but branch off before any of the
        # record machinery below, exactly as the PowerDNS driver does.
        if op_kind == "dnssec_sign":
            return {"dnssec_state": self._dnssec_sign(token, zone)}
        if op_kind == "dnssec_unsign":
            return {"dnssec_state": self._dnssec_unsign(token, zone)}

        rec = op["record"]
        rtype = (rec.get("type") or "").upper()
        name = _qualified_name(zone, rec.get("name") or "@")
        shadow = _shadowing_zone(name, zone, self._hosted_zone_names())
        if shadow is not None:
            # #1712: Technitium would file this under the child zone and, with
            # ``overwrite=true``, clear the child's own RRset at the name.
            log.warning(
                "technitium_record_op_shadowed_by_child_zone",
                zone=zone,
                name=name,
                type=rtype,
                op=op_kind,
                child_zone=shadow,
            )
            return None
        # Absence, not falsiness — a TTL of 0 is legal ("never cache this") and
        # ``or`` silently turned it into an hour. Matches bind9's driver, which
        # has always tested for None here.
        _op_ttl = rec.get("ttl")
        ttl = 3600 if _op_ttl is None else _op_ttl
        params = {
            "domain": name,
            "zone": zone,
            "type": rtype,
            **_record_params(
                rtype,
                rec.get("value") or "",
                rec,
                self._svcb_origin(zone),
                self._name_origin(zone),
            ),
        }

        # #773 — the control plane ships the complete desired RRset. Technitium's
        # REST API is one record per call, so there is no way to install N
        # values atomically; the shape below picks the least destructive
        # sequence available for each op kind.
        #
        # A ``delete`` is expressed as a value-scoped delete of the op's OWN
        # value — the survivors in ``members`` are already on the server, so
        # touching them would be a wipe-and-rebuild with a window where the
        # name serves less than it should. One call, nothing at risk. (Rebuilding
        # from the set would be more self-healing, and is not worth trading a
        # guaranteed-safe delete for.)
        #
        # A ``create`` / ``update`` has no such option: the op may be changing a
        # value, and this API cannot say "replace THIS RR" — so it is member 0
        # with ``overwrite=true`` (which clears) followed by appends. Member 0
        # always lands, so a mid-sequence failure leaves a subset containing it
        # rather than an empty name, and the op is replayed. A member the server
        # permanently rejects strands the rest of the set once the retry budget
        # runs out — still strictly more than the single value the pre-#773 path
        # left behind.
        rrset = rec.get("rrset") if isinstance(rec.get("rrset"), dict) else None
        members = rrset.get("members") if rrset is not None else None
        if rrset is not None and members is not None and op_kind in RRSET_OP_KINDS:
            # Absence, not falsiness — a TTL of 0 is legal and meaningful.
            _rrset_ttl = rrset.get("ttl")
            rrset_ttl = int(ttl if _rrset_ttl is None else _rrset_ttl)
            if op_kind == "delete":
                # Both the "siblings survive" and the "last value gone" cases:
                # the op's own params identify exactly the RR to remove, and
                # Technitium drops the rrset once its last record goes.
                self._record_call(token, "delete", params, zone, name, rtype, op_kind)
            else:
                for index, member in enumerate(members):
                    self._record_call(
                        token,
                        "add",
                        {
                            "domain": name,
                            "zone": zone,
                            "type": rtype,
                            "ttl": rrset_ttl,
                            "overwrite": "true" if index == 0 else "false",
                            **_record_params(
                                rtype,
                                member.get("value") or "",
                                member,
                                self._svcb_origin(zone),
                                self._name_origin(zone),
                            ),
                        },
                        zone,
                        name,
                        rtype,
                        op_kind,
                    )
            log.info(
                "technitium_rrset_applied",
                zone=zone,
                name=name,
                type=rtype,
                op=op_kind,
                members=len(members),
            )
            return None

        # Fallback for an op enqueued by a control plane that predates the
        # ``rrset`` payload. ``rrset_action`` is the older per-op override.
        rrset_action = (rec.get("rrset_action") or "").lower()
        endpoint = "delete" if op_kind == "delete" else "add"
        if op_kind != "delete":
            params["ttl"] = ttl
            # REPLACE the rrset by default (matches bind9's ``upd.replace``
            # and PowerDNS's rrset REPLACE); append only when the caller
            # explicitly asks for sibling-preserving semantics.
            params["overwrite"] = "false" if rrset_action == "add" else "true"

        if self._record_call(token, endpoint, params, zone, name, rtype, op_kind):
            log.info(
                "technitium_record_op_applied",
                zone=zone,
                name=name,
                type=rtype,
                op=op_kind,
            )
        return None

    def _hosted_zone_names(self) -> list[str]:
        """Zones the last render created on the daemon, or [] when unreadable.

        Read from the rendered snapshot rather than held in memory so a record
        op arriving after an agent restart, before any new render, still knows
        the zone layout. A snapshot an older agent wrote has no
        ``hosted_zone_names``; its ``bundle_zone_names`` is the nearest answer
        until the next render rewrites it.
        """
        try:
            state = json.loads((self.state_dir / "rendered" / "server.json").read_text())
        except (OSError, ValueError):
            return []
        if not isinstance(state, dict):
            return []
        names = state.get("hosted_zone_names")
        if names is None:
            names = state.get("bundle_zone_names")
        return [str(n) for n in names] if isinstance(names, list) else []

    def _record_call(
        self,
        token: str,
        endpoint: str,
        params: dict[str, Any],
        zone: str,
        name: str,
        rtype: str,
        op_kind: str,
    ) -> bool:
        """POST one ``zones/records/{add,delete}`` call, raising on a real error.

        Returns False for an idempotent no-op so a caller can skip its
        "applied" log line, True when the server accepted the change.

        Technitium answers HTTP 200 with ``{"status": "error"}`` for a rejected
        record, so the body has to be inspected. Two of those are not failures:
        a retried create of an identical record, and a delete of a record that
        is already gone — both mean the server is already in the state the op
        asks for, which is exactly what a replayed op should find. Crucially
        they must NOT abort a multi-member RRset write half way — one member
        the server already has does not make the remaining members optional.
        """
        body = self._call(token, "POST", f"zones/records/{endpoint}", params).json()
        if body.get("status") != "error":
            return True
        if _is_record_noop(body.get("errorMessage")):
            log.info(
                "technitium_record_op_idempotent_noop",
                zone=zone,
                name=name,
                type=rtype,
                op=op_kind,
                detail=body.get("errorMessage"),
            )
            return False
        raise RuntimeError(
            f"Technitium {endpoint} {zone}/{name}/{rtype} failed: "
            f"{body.get('errorMessage')}"
        )

    # ── Blocklists (issue #744) ─────────────────────────────────────────

    def _apply_blocking(self, token: str, blocking: dict[str, Any]) -> None:
        """Converge Technitium's blocked / allowed domain sets.

        Read with ``{kind}/export``, written with ``{kind}/flush`` +
        ``{kind}/import`` (#1425).

        ``export`` returns the set as a flat list, one name per line. That
        is the read model ``blocked/list`` cannot be: ``list`` is a
        one-level tree browser whose intermediate nodes are not themselves
        blocked domains, so reconciling against it deleted whole subtrees
        (verified). With a flat read, a set that already matches the bundle
        is left alone — no rewrite, no window without blocking — which is
        every structural apply that did not touch a blocklist.

        A set that differs is flushed and re-imported rather than diffed
        entry by entry: ``delete`` also rewrites the zone file per call,
        so a large diff would cost what the old per-domain ``add`` did.
        ``import`` takes a comma-separated list and saves once per call;
        a 16k-entry list that took ~30 minutes through ``add`` now takes
        a handful of calls. An unreadable live set (an error answer) is
        treated as different, so it is rewritten rather than trusted.
        """
        if not blocking:
            return

        blocking_type = blocking.get("blocking_type") or "NxDomain"
        if blocking_type not in _BLOCKING_TYPES:
            log.error(
                "technitium_blocking_type_invalid",
                value=blocking_type,
                supported=sorted(_BLOCKING_TYPES),
            )
            self._note_apply_failure(f"blocking: invalid type {blocking_type}")
            return

        settings: dict[str, Any] = {
            "enableBlocking": "true" if blocking.get("enabled") else "false",
            "blockingType": blocking_type,
        }
        if blocking_type == "CustomAddress":
            addresses = blocking.get("custom_addresses") or []
            if not addresses:
                # CustomAddress with nothing to answer would blackhole the
                # name in a way the operator did not ask for. Fall back to
                # NxDomain and say so.
                log.warning("technitium_blocking_custom_address_missing")
                settings["blockingType"] = "NxDomain"
            else:
                settings["customBlockingAddresses"] = ",".join(addresses)
        body = self._call(token, "POST", "settings/set", settings).json()
        if body.get("status") != "ok":
            log.error(
                "technitium_blocking_settings_failed", error=body.get("errorMessage")
            )
            self._note_apply_failure(f"blocking settings: {body.get('errorMessage')}")
            return

        unchanged: list[str] = []
        for kind in ("blocked", "allowed"):
            desired = sorted(
                {_ascii_domain(d) for d in blocking.get(kind) or [] if str(d).strip()}
            )
            live = self._export_domains(token, kind)
            if live is not None and live == set(desired):
                unchanged.append(kind)
                continue
            flushed = self._call(token, "POST", f"{kind}/flush", {}).json()
            if flushed.get("status") != "ok":
                log.error(
                    f"technitium_{kind}_flush_failed",
                    error=flushed.get("errorMessage"),
                )
                self._note_apply_failure(
                    f"blocking {kind} flush: {flushed.get('errorMessage')}"
                )
                continue
            for start in range(0, len(desired), _BLOCKING_IMPORT_CHUNK):
                chunk = desired[start : start + _BLOCKING_IMPORT_CHUNK]
                imported = self._call(
                    token, "POST", f"{kind}/import", {f"{kind}Zones": ",".join(chunk)}
                ).json()
                if imported.get("status") != "ok":
                    log.error(
                        f"technitium_{kind}_import_failed",
                        first=chunk[0],
                        count=len(chunk),
                        error=imported.get("errorMessage"),
                    )
                    self._note_apply_failure(
                        f"blocking {kind} import ({len(chunk)} from {chunk[0]}): "
                        f"{imported.get('errorMessage')}"
                    )
        log.info(
            "technitium_blocking_applied",
            enabled=bool(blocking.get("enabled")),
            blocking_type=settings["blockingType"],
            blocked=len(blocking.get("blocked") or []),
            allowed=len(blocking.get("allowed") or []),
            unchanged=unchanged,
        )

    def _export_domains(self, token: str, kind: str) -> set[str] | None:
        """The live blocked / allowed set as a flat set, or None if unreadable.

        ``{kind}/export`` answers ``text/plain``, one name per line. Any
        JSON answer is an error (an invalid token, a permission refusal),
        so None: the caller then rewrites rather than trusts it.
        """
        resp = self._call(token, "GET", f"{kind}/export", {})
        try:
            resp.json()
        except ValueError:
            pass
        else:
            return None
        if getattr(resp, "status_code", 200) != 200:
            return None
        return {
            line.strip().rstrip(".").lower()
            for line in (resp.text or "").splitlines()
            if line.strip()
        }

    # ── Encrypted transports (issue #741) ───────────────────────────────

    def _write_tls_cert(self, cert: dict[str, Any]) -> str | None:
        """Convert the bundle's PEM cert+key to PKCS #12 on disk.

        Technitium takes the TLS material as a ``dnsTlsCertificatePath``
        pointing at a **PKCS #12** file; handing it PEM fails with "DNS
        Server TLS certificate file must be PKCS #12 formatted". The
        bundle ships PEM, because that is what the ApplianceCertificate
        store holds and what BIND9 consumes, so the conversion lives here.

        Written 0600 through the same atomic path as the other secrets —
        the .pfx embeds the private key.
        """
        cert_pem = (cert.get("cert_pem") or "").encode()
        key_pem = (cert.get("key_pem") or "").encode()
        if not cert_pem or not key_pem:
            return None
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs12
            from cryptography.x509 import load_pem_x509_certificates

            chain = load_pem_x509_certificates(cert_pem)
            if not chain:
                raise ValueError("no certificate found in cert_pem")
            private_key = serialization.load_pem_private_key(key_pem, password=None)
            blob = pkcs12.serialize_key_and_certificates(
                name=(cert.get("name") or "spatiumddi").encode(),
                key=private_key,  # type: ignore[arg-type]
                cert=chain[0],
                cas=chain[1:] or None,
                encryption_algorithm=serialization.NoEncryption(),
            )
        except Exception as exc:  # noqa: BLE001 — any parse failure is fatal
            # Degrade to Do53 rather than take the daemon down: an
            # unreadable cert must not stop the plain :53 listener, which
            # is the whole "every path degrades to Do53" promise (#50).
            log.error("technitium_tls_cert_convert_failed", error=str(exc))
            return None

        path = self.state_dir / _TLS_CERT_FILE
        tmp = path.with_suffix(path.suffix + ".new")
        fd = os.open(
            str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
        )
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        tmp.replace(path)
        return str(path)

    def _apply_transport_settings(
        self, token: str, options: dict[str, Any], cert: dict[str, Any] | None
    ) -> None:
        """Push the encrypted-listener + forwarder settings.

        Ordering matters. Technitium accepts ``enableDnsOverTls=true`` even
        when the certificate path in the SAME call is rejected (verified —
        the flag lands, the path does not), which would leave a listener
        enabled with no cert. So the cert path goes first, in its own call,
        and the listeners are only enabled if that call succeeded.
        """
        cert_path = self._write_tls_cert(cert) if cert else None
        wants_tls = bool(
            options.get("dot_enabled")
            or options.get("doh_enabled")
            or options.get("doq_enabled")
        )

        cert_ok = True
        if wants_tls:
            if not cert_path:
                log.error("technitium_encrypted_transport_skipped_no_cert")
                self._note_apply_failure("encrypted transport: no usable TLS cert")
                cert_ok = False
            else:
                body = self._call(
                    token, "POST", "settings/set", {"dnsTlsCertificatePath": cert_path}
                ).json()
                if body.get("status") != "ok":
                    log.error(
                        "technitium_tls_cert_path_rejected",
                        path=cert_path,
                        error=body.get("errorMessage"),
                    )
                    self._note_apply_failure(
                        f"tls cert path: {body.get('errorMessage')}"
                    )
                    cert_ok = False

        if wants_tls and not cert_ok:
            # Returning here would leave an ALREADY-ENABLED listener up on
            # a stale certificate, which is the opposite of the "every
            # path degrades to Do53" promise (#50). Fall through with
            # every listener forced off instead, so the daemon actually
            # drops back to plain :53.
            log.warning("technitium_encrypted_transport_disabled_degrading_to_do53")
            options = {**options, "dot_enabled": False, "doh_enabled": False,
                       "doq_enabled": False}

        params: dict[str, Any] = {
            "enableDnsOverTls": "true" if options.get("dot_enabled") else "false",
            "enableDnsOverHttps": "true" if options.get("doh_enabled") else "false",
            "enableDnsOverQuic": "true" if options.get("doq_enabled") else "false",
        }
        if options.get("dot_enabled"):
            params["dnsOverTlsPort"] = int(options.get("dot_port") or 853)
        if options.get("doh_enabled"):
            params["dnsOverHttpsPort"] = int(options.get("doh_port") or 443)
            # Technitium serves DoH on a FIXED path and exposes no setting
            # for it (verified: no path key in settings/get). An operator
            # who changed doh_path would otherwise be handed a URL the
            # daemon does not answer on.
            doh_path = str(options.get("doh_path") or "/dns-query")
            if doh_path != "/dns-query":
                log.warning(
                    "technitium_doh_path_not_configurable",
                    requested=doh_path,
                    served="/dns-query",
                )
        if options.get("doq_enabled"):
            params["dnsOverQuicPort"] = int(options.get("doq_port") or 853)

        resp = self._call(token, "POST", "settings/set", params)
        body = resp.json()
        if body.get("status") != "ok":
            log.error(
                "technitium_transport_settings_failed", error=body.get("errorMessage")
            )
            self._note_apply_failure(
                f"transport settings: {body.get('errorMessage')}"
            )
            return
        log.info(
            "technitium_transport_settings_applied",
            dot=bool(options.get("dot_enabled")),
            doh=bool(options.get("doh_enabled")),
            doq=bool(options.get("doq_enabled")),
        )

    def _apply_dnssec_validation(self, token: str, options: dict[str, Any]) -> None:
        """Set the resolver's DNSSEC validation from the group's option (#1763).

        ``settings/set`` takes a boolean ``dnssecValidation`` (APIDOCS.md,
        "Set DNS Settings", Technitium DnsServer v15.4.0), default ``true``.
        The group's ``dnssec_validation`` is BIND's ``auto | yes | no``: ``no``
        turns validation off, and both others validate (``auto`` is BIND's
        built-in-trust-anchor mode, which is what Technitium does when on).
        Without this, ``no`` behind a DNSSEC-stripping upstream still
        validated and SERVFAILed every signed name. An old bundle without
        the key leaves the daemon alone.
        """
        raw = options.get("dnssec_validation")
        if raw is None:
            return
        value = str(raw).strip().lower()
        if value not in ("auto", "yes", "no"):
            log.error("technitium_dnssec_validation_value_invalid", value=raw)
            self._note_apply_failure(f"dnssec validation: bad value {raw!r}")
            return
        body = self._call(
            token,
            "POST",
            "settings/set",
            {"dnssecValidation": "false" if value == "no" else "true"},
        ).json()
        if body.get("status") != "ok":
            log.error("technitium_dnssec_validation_failed", error=body.get("errorMessage"))
            self._note_apply_failure(f"dnssec validation: {body.get('errorMessage')}")

    def _apply_forwarders(self, token: str, options: dict[str, Any]) -> None:
        """Set the upstream forwarders and the protocol to reach them with.

        ``forwarderProtocol`` is SILENTLY IGNORED unless ``forwarders`` is
        set in the SAME call (verified: setting the protocol alone returns
        ok and leaves it at Udp). So the two always go together, or not at
        all.

        For DoT/DoH/DoQ the certificate is checked against a **name**, so
        the group's ``forward_tls_hostname`` is paired with every forwarder
        IP as ``"<name> (<ip>)"`` (``https://<name>/dns-query (<ip>)`` for
        DoH). Technitium dials the bracketed IP and validates the name
        (APIDOCS.md "Name Server Address Format"). It used to send the name
        alone, which made the daemon resolve it by plaintext recursion from
        the root before it could forward (#1764).

        Technitium has no switch to skip certificate validation
        (``TlsClientConnection`` authenticates against the server's host
        unconditionally), so ``forward_tls_verify=false`` cannot be honoured
        and a hostname is required for every encrypted transport. A stored
        row without one is refused (reported, previous forwarders kept)
        rather than sent as bare IPs, which would fail every forwarded query
        wherever the certificate carries no IP SAN.

        A neutral ``ip@port`` is sent as Technitium's ``ip:port``.
        """
        forwarders = [str(f) for f in (options.get("forwarders") or []) if f]
        transport = str(options.get("forward_transport") or "do53")
        protocol = _FORWARDER_PROTOCOLS.get(transport)
        if protocol is None:
            log.warning("technitium_forward_transport_unsupported", transport=transport)
            self._note_apply_failure(f"forwarders: unsupported transport {transport}")
            return

        if not forwarders:
            # Clearing has to be an explicit empty write, not an early
            # return: removing every forwarder in the UI would otherwise
            # leave the daemon resolving through the old upstreams forever,
            # because nothing else ever touches the setting.
            resp = self._call(
                token, "POST", "settings/set", {"forwarders": "", "forwarderProtocol": "Udp"}
            )
            body = resp.json()
            if body.get("status") != "ok":
                log.error(
                    "technitium_forwarders_clear_failed", error=body.get("errorMessage")
                )
                self._note_apply_failure(
                    f"forwarders clear: {body.get('errorMessage')}"
                )
            else:
                log.info("technitium_forwarders_cleared")
            return

        if transport != "do53":
            hostname = options.get("forward_tls_hostname")
            if hostname:
                forwarders = _encrypted_forwarders(forwarders, str(hostname), transport)
            else:
                # Not "send the IPs over Tls": Technitium validates the
                # certificate against the address it was given, so bare IPs
                # work only where the certificate carries them as IP SANs,
                # and everywhere else every forwarded query would fail. The
                # previous forwarders keep resolving and the refusal is
                # reported; the API no longer lets this be newly stored.
                log.error(
                    "technitium_forwarder_hostname_missing",
                    transport=transport,
                    hint=(
                        "forward_tls_hostname is required: Technitium always validates "
                        "the upstream certificate, against that name"
                    ),
                )
                self._note_apply_failure(
                    f"forwarders: no forward_tls_hostname for {transport}; Technitium "
                    "always validates the upstream certificate, so set one"
                )
                return
        else:
            forwarders = [_technitium_forwarder(f) for f in forwarders]

        resp = self._call(
            token,
            "POST",
            "settings/set",
            {"forwarders": ",".join(forwarders), "forwarderProtocol": protocol},
        )
        body = resp.json()
        if body.get("status") != "ok":
            log.error(
                "technitium_forwarders_failed",
                protocol=protocol,
                error=body.get("errorMessage"),
            )
            self._note_apply_failure(f"forwarders: {body.get('errorMessage')}")
            return
        log.info(
            "technitium_forwarders_applied", protocol=protocol, count=len(forwarders)
        )

    def _apply_recursion(self, token: str, options: dict[str, Any]) -> None:
        """Set the recursion policy from the bundle (#1761).

        Technitium's fresh default is ``AllowOnlyForPrivateNetworks``; left
        alone, a group with recursion off (or ``is_recursive=false``, which
        the bundle already folds into ``recursion_enabled``) still resolves
        for every RFC 1918 client, and an ``allow_recursion`` naming a
        public range is refused. Always sent, so turning recursion off or
        editing the list converges instead of sticking.
        """
        mode, acl = self._recursion_params(options)
        if mode not in _RECURSION_MODES:
            # settings/set try-parses the enum and ignores a bad value with
            # status "ok", so an unknown mode would read as applied.
            log.error("technitium_recursion_mode_invalid", mode=mode)
            self._note_apply_failure(f"recursion: invalid mode {mode!r}")
            return
        params: dict[str, Any] = {"recursion": mode}
        if mode == "UseSpecifiedNetworkACL":
            params["recursionNetworkACL"] = ",".join(acl)
        body = self._call(token, "POST", "settings/set", params).json()
        if body.get("status") != "ok":
            log.error("technitium_recursion_failed", mode=mode, error=body.get("errorMessage"))
            self._note_apply_failure(f"recursion: {body.get('errorMessage')}")
            return
        log.info("technitium_recursion_applied", mode=mode, acl=len(acl))

    @staticmethod
    def _recursion_params(options: dict[str, Any]) -> tuple[str, list[str]]:
        """Pure mapping: bundle options → (``recursion`` mode, ACL entries).

        * ``recursion_enabled`` false → ``Deny``.
        * ``allow_recursion`` absent (an older control plane) → the stored
          default, local + private networks (#1817). Otherwise the list
          is read literally, with no special case for any value:
          ``["any"]`` → ``Allow`` (open, deliberately), ``none`` / empty →
          ``Deny``.
        * NOTE ``localnets`` differs from BIND's: BIND's is the server's
          directly attached subnets, Technitium has no such notion, so it is
          the RFC 1918 + ULA + link-local ranges (``_ACL_LOCALNETS``), which
          is also what Technitium's own ``AllowOnlyForPrivateNetworks`` allows.
        * otherwise ``UseSpecifiedNetworkACL`` with the list translated to
          CIDRs. Unresolvable tokens (named ACLs, garbage) are dropped with
          a warning; if none survive the result is ``Deny`` — fail closed.
        * the ACL is deduplicated, first occurrence kept: the default lists
          ``localnets`` AND the private ranges it expands to here, and a
          later duplicate can never fire in a first-match list anyway.
        """
        if not options.get("recursion_enabled", True):
            return "Deny", []
        stored = options.get("allow_recursion")
        if stored is None:
            stored = list(_DEFAULT_ALLOW_RECURSION)
        raw = [str(e).strip() for e in stored if str(e).strip()]
        if [e.lower() for e in raw] == ["any"]:
            return "Allow", []
        acl: list[str] = []
        seen: set[tuple[bool, str]] = set()
        for entry in raw:
            deny = entry.startswith("!")
            name = entry.lstrip("!").strip()
            low = name.lower()
            if low == "any":
                cidrs: tuple[str, ...] = _ACL_ANY
            elif low == "none":
                continue
            elif low == "localhost":
                cidrs = _ACL_LOCALHOST
            elif low == "localnets":
                cidrs = _ACL_LOCALNETS
            else:
                try:
                    ipaddress.ip_network(name, strict=False)
                except ValueError:
                    log.warning("technitium_allow_recursion_entry_dropped", entry=entry)
                    continue
                cidrs = (name,)
            for c in cidrs:
                seen_key = (deny, str(ipaddress.ip_network(c, strict=False)))
                if seen_key not in seen:
                    seen.add(seen_key)
                    acl.append(("!" + c) if deny else c)
        if not any(not a.startswith("!") for a in acl):
            return "Deny", []
        return "UseSpecifiedNetworkACL", acl

    def _apply_rate_limits(self, token: str, options: dict[str, Any]) -> None:
        """Map the group's RRL intent onto Technitium's QPM limits (#1761).

        Technitium ships ``qpmPrefixLimits`` of 600/min per IPv4 /32 and
        6000/min per /24 (IPv6 600 / 1200 / 6000), averaged over 5 minutes,
        applied to every inbound query. With RRL off in SpatiumDDI those
        defaults stayed in force and dropped a busy downstream resolver's
        answers. So: RRL off (or ``log-only``, which Technitium cannot
        express) sends EMPTY limits, which disables the feature; RRL on
        derives a per-client (/32, /128) limit from
        ``rrl_responses_per_second`` x 60, a sample window from
        ``rrl_window`` (seconds → whole minutes, min 1) and the truncation
        share from ``rrl_slip`` (BIND: every Nth response slips, so 100/N %;
        0 = drop all). ``rrl_exempt_clients`` becomes the bypass list.
        This is an approximation, not equivalence: BIND limits identical
        responses per second, Technitium counts queries per minute.
        """
        params = self._rate_limit_params(options)
        body = self._call(token, "POST", "settings/set", params).json()
        if body.get("status") != "ok":
            log.error("technitium_rate_limits_failed", error=body.get("errorMessage"))
            self._note_apply_failure(f"rate limits: {body.get('errorMessage')}")
            return
        log.info("technitium_rate_limits_applied", enabled=bool(params["qpmPrefixLimitsIPv4"]))

    @staticmethod
    def _rate_limit_params(options: dict[str, Any]) -> dict[str, Any]:
        """Pure mapping: bundle options → the ``settings/set`` qpm payload."""
        if not options.get("rrl_enabled") or options.get("rrl_log_only"):
            if options.get("rrl_enabled"):
                log.warning(
                    "technitium_rrl_log_only_not_supported",
                    hint="Technitium cannot log without limiting; limits left off",
                )
            return {
                "qpmPrefixLimitsIPv4": "",
                "qpmPrefixLimitsIPv6": "",
                "qpmLimitBypassList": "",
            }
        rps = max(1, int(options.get("rrl_responses_per_second") or 15))
        limit = rps * 60
        window_s = max(1, int(options.get("rrl_window") or 15))
        slip = int(options.get("rrl_slip") if options.get("rrl_slip") is not None else 2)
        pct = 0 if slip <= 0 else min(100, round(100 / slip))
        bypass: list[str] = []
        for c in options.get("rrl_exempt_clients") or []:
            try:
                ipaddress.ip_network(str(c).strip(), strict=False)
            except ValueError:
                log.warning("technitium_rrl_exempt_entry_dropped", entry=str(c))
                continue
            bypass.append(str(c).strip())
        return {
            "qpmPrefixLimitsIPv4": f"32|{limit}|{limit}",
            "qpmPrefixLimitsIPv6": f"128|{limit}|{limit}",
            "qpmLimitSampleMinutes": max(1, -(-window_s // 60)),
            "qpmLimitUdpTruncationPercentage": pct,
            "qpmLimitBypassList": ",".join(bypass),
        }

    # ── DNSSEC (issue #740) ─────────────────────────────────────────────

    def _dnssec_sign(self, token: str, zone: str) -> dict[str, Any]:
        """Sign the zone, then report its DS rrset + per-key state.

        Idempotent by the same reasoning as PowerDNS's: repeated "Sign
        zone" clicks should converge on "signed", not error. Technitium
        answers an already-signed zone with ``Cannot sign zone: the zone
        is already signed.`` (verified live), which is treated as success
        so the collect below still reports current state.
        """
        resp = self._call(
            token, "POST", "zones/dnssec/sign", {"zone": zone, **_DNSSEC_SIGN_DEFAULTS}
        )
        body = resp.json()
        if body.get("status") != "ok":
            msg = (body.get("errorMessage") or "").lower()
            if "already signed" not in msg:
                raise RuntimeError(
                    f"Technitium sign {zone} failed: {body.get('errorMessage')}"
                )
            log.info("technitium_dnssec_already_signed", zone=zone)
        else:
            log.info("technitium_dnssec_signed", zone=zone)
        return self._collect_dnssec_state(token, zone)

    def _dnssec_unsign(self, token: str, zone: str) -> dict[str, Any]:
        """Unsign, and report empty DS + no keys so the control plane
        clears its cache — a stale DS left on display is one the parent
        zone no longer trusts."""
        resp = self._call(token, "POST", "zones/dnssec/unsign", {"zone": zone})
        body = resp.json()
        if body.get("status") != "ok":
            msg = (body.get("errorMessage") or "").lower()
            if "not signed" not in msg and "unsigned" not in msg:
                raise RuntimeError(
                    f"Technitium unsign {zone} failed: {body.get('errorMessage')}"
                )
        log.info("technitium_dnssec_unsigned", zone=zone)
        return {"zone_name": zone, "ds_records": [], "keys": []}

    def _collect_dnssec_state(self, token: str, zone: str) -> dict[str, Any]:
        """Build the control plane's DNSSEC report for one zone.

        Two calls, because Technitium splits the information:

        * ``zones/dnssec/properties/get`` has the key inventory (tag, type,
          algorithm number, rollover state) but **no DS records at all**.
        * The DS material lives on the zone's own DNSKEY records, under
          ``rData.computedDigests`` — and only on the KSK, since a DS
          attests the key-signing key to the parent. Each KSK yields one
          digest per supported type (SHA256 + SHA384 observed), all of
          which the operator should publish to cover validators of
          differing sophistication.

        Unlike PowerDNS's agent this reports ``keys`` as well as
        ``ds_records``, because Technitium exposes per-key state and the
        control plane already models it (issue #49's ``DNSKey`` rows).
        """
        props = self._call(
            token, "GET", "zones/dnssec/properties/get", {"zone": zone}
        ).json()
        priv = (props.get("response") or {}).get("dnssecPrivateKeys") or []
        algo_by_tag = {
            k.get("keyTag"): int(k.get("algorithmNumber") or 0) for k in priv
        }

        ds_records: list[str] = []
        keys: list[dict[str, Any]] = []
        recs = self._call(
            token,
            "GET",
            "zones/records/get",
            {"domain": zone, "zone": zone, "listZone": "true"},
        ).json()
        for rec in (recs.get("response") or {}).get("records") or []:
            if rec.get("type") != "DNSKEY":
                continue
            rdata = rec.get("rData") or {}
            key_tag = rdata.get("computedKeyTag")
            algorithm = int(rdata.get("algorithmNumber") or algo_by_tag.get(key_tag) or 0)
            for digest in rdata.get("computedDigests") or []:
                digest_num = _DS_DIGEST_TYPES.get(str(digest.get("digestType")).upper())
                value = digest.get("digest")
                if not (key_tag and digest_num and value):
                    continue
                ds_records.append(f"{key_tag} {algorithm} {digest_num} {value}")

        for k in priv:
            keys.append(
                {
                    "key_tag": int(k.get("keyTag") or 0),
                    "key_type": _DNSSEC_KEY_TYPES.get(str(k.get("keyType")), "zsk"),
                    "algorithm": int(k.get("algorithmNumber") or 0),
                    "state": str(k.get("state") or "unknown").lower(),
                    "timing": {
                        key: k[src]
                        for key, src in (
                            ("state_changed_on", "stateChangedOn"),
                            ("state_ready_by", "stateReadyBy"),
                        )
                        if k.get(src)
                    },
                }
            )
        return {"zone_name": zone, "ds_records": ds_records, "keys": keys}

    def _reconcile_zones(self, token: str, payload: list[dict[str, Any]]) -> None:
        """Bring each zone's record set in line with ``payload`` via a
        full per-zone diff: create the zone if missing, then delete
        records present on the daemon but absent from desired state and
        add records present in desired state but absent on the daemon.

        Zones absent from ``payload`` are not deleted here. A zone this
        agent created and the bundle has since dropped is retired by
        ``_retire_dropped_zones``; a zone it never managed is left alone.
        """
        # Reverse zones go LAST. Deleting an A/AAAA through the API also
        # deletes the PTR it points from in a reverse zone on the same server
        # (``DeleteRecord``, WebServiceZonesApi.cs, no flag turns it off), so a
        # reverse zone reconciled before the forward zone that deletes would
        # stay a PTR short until the next structural change. After them, its
        # fresh read sees the hole and re-adds the PTR the bundle owns (#1768).
        payload = sorted(payload, key=lambda z: _is_reverse_zone(z.get("zone")))
        held = self._load_held_zones()
        held &= {z["zone"] for z in payload}
        for zone_payload in payload:
            zone = zone_payload["zone"]
            held_back = self._reconcile_one_zone(token, zone_payload, zone in held)
            if held_back:
                # Release refused or skipped: remembered so the next pass
                # releases it (#1758).
                held.add(zone)
            else:
                held.discard(zone)
            self._save_held_zones(held)

    def _reconcile_one_zone(self, token: str, zone_payload: dict[str, Any], held: bool) -> bool:
        """Reconcile one zone; returns True if it is still held (#1758).

        A Primary this pass just created answers under Technitium's DEFAULT
        SOA (``hostadmin@<zone>``, TTL and minimum 900 s, ``PrimaryZone``
        ctor, 15.4.0) until its own SOA and records land: 8-11 s on a real
        group move, and a resolver can cache an NXDOMAIN from that window
        for the 900 s. ``zones/create`` takes no SOA and no options, so the
        zone is HELD straight after the create: its ``queryAccess`` is set
        to ``Deny``, and its real options (query access included) are sent
        only once records and apex are reconciled. A Forwarder converted
        into a Primary (#1457) gets the same SOA from
        ``_replace_placeholder_soa`` and is held the same way.

        Why ``queryAccess=Deny`` and not ``zones/disable``: a DISABLED zone
        is not authoritative at all (``AuthZoneManager.QueryAsync`` returns
        null for ``!apexZone.IsActive``), and ``DnsServer.ProcessRequestAsync``
        then RECURSES whenever the query has RD set and recursion is allowed,
        which is the normal case for an internal zone on a resolving group.
        ``corp.lan`` would then get the root's NXDOMAIN (negative TTL 86400)
        and a split-horizon ``example.com`` its PUBLIC answers, both cached
        downstream far longer than the 900 s this fixes. A zone that is
        active but denies the client answers REFUSED from ``QueryAsync``
        (``IsQueryAllowedAsync``) before any recursion or locally-served
        special zone is consulted, and nobody caches a REFUSED (RFC 2308
        caches NXDOMAIN / NODATA only), so a client moves to the next server.

        A new zone has no catalog membership yet (``_apply_catalog`` runs
        after every zone), so its own ``queryAccess`` is the one in force.
        A zone that already exists is never held, so a second pass issues
        nothing extra. ``held`` is a zone a previous pass held and did not
        release (agent killed mid-pass, release refused).
        """
        zone = zone_payload["zone"]
        new_primary = self._ensure_zone_exists(token, zone_payload)
        is_primary = zone_payload.get("type", "Primary") == "Primary"
        options = zone_payload.get("options") or {}
        if new_primary and is_primary and self._hold_zone(token, zone):
            held = True
            self._save_held_zone_now(zone)
        if not held:
            self._reconcile_zone_body(token, zone, zone_payload, options)
            return False
        try:
            # The zone's options, query access among them, are what release
            # the hold, so they are applied last rather than first.
            self._reconcile_zone_body(token, zone, zone_payload, None)
        finally:
            released = self._release_zone(token, zone, options)
        return not released

    def _hold_zone(self, token: str, zone: str) -> bool:
        """Refuse every query to ``zone`` (loopback aside). True on success."""
        return self._set_query_access(token, zone, {"queryAccess": "Deny"}, "hold")

    def _release_zone(self, token: str, zone: str, options: dict[str, Any]) -> bool:
        """Apply a held zone's options, which carry its query access.

        No query access in the bundle (an ``allow_query`` Technitium cannot
        express, which a normal pass leaves as the daemon has it) means
        ``Allow``: what the zone had before the hold (``ApexZone`` ctor,
        15.4.0), not a translation of the operator's list. The exception is
        a zone whose OWN list cannot be expressed (#2263): it is released
        to the group's list (``_release_query_access``) when that one can
        be, so it is never opened wider than a zone without the override.
        If the options
        call is refused or not sent (a bad ``zoneTransfer`` is never sent),
        the query access still goes out on its own: a zone left at ``Deny``
        is not served at all.
        """
        params = dict(options)
        if "queryAccess" not in params:
            access, acl = params.get("_release_query_access") or ("Allow", [])
            params.update(queryAccess=access, queryAccessNetworkACL=list(acl))
        try:
            if self._apply_zone_options(token, zone, params):
                return True
        except (httpx.HTTPError, ValueError) as exc:  # fall back below
            log.warning("technitium_zone_options_failed", zone=zone, error=str(exc))
        acl = params.get("queryAccessNetworkACL") or []
        return self._set_query_access(
            token,
            zone,
            {
                "queryAccess": params["queryAccess"],
                "queryAccessNetworkACL": ",".join(str(a) for a in acl)
                if isinstance(acl, list)
                else str(acl),
            },
            "release",
        )

    def _set_query_access(
        self, token: str, zone: str, params: dict[str, Any], what: str
    ) -> bool:
        try:
            body = self._call(
                token, "POST", "zones/options/set", {"zone": zone, **params}
            ).json()
        except (httpx.HTTPError, ValueError) as exc:  # report; never raise past the pass
            body = {"status": "error", "errorMessage": str(exc)}
        if body.get("status") == "ok":
            return True
        log.warning(f"technitium_zone_{what}_failed", zone=zone, error=body.get("errorMessage"))
        if what == "release":
            # Still refusing every query: the zone is not served, which the
            # operator must see. The next pass retries from the marker.
            self._note_apply_failure(
                f"{zone}: zone still refusing queries (release failed): "
                f"{body.get('errorMessage')}"
            )
        return False

    @property
    def _held_zones_path(self) -> Path:
        return Path(self.state_dir) / _HELD_ZONES_FILE

    def _load_held_zones(self) -> set[str]:
        try:
            data = json.loads(self._held_zones_path.read_text())
        except FileNotFoundError:
            return set()
        except (OSError, ValueError) as exc:
            log.warning("technitium_held_zones_unreadable", error=str(exc))
            return set()
        if not isinstance(data, list):
            log.warning("technitium_held_zones_unreadable", error="not a list")
            return set()
        return {z for z in data if isinstance(z, str) and z}

    def _save_held_zones(self, held: set[str]) -> None:
        path = self._held_zones_path
        try:
            if held:
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(sorted(held)))
                os.replace(tmp, path)
            else:
                path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("technitium_held_zones_write_failed", error=str(exc))

    def _save_held_zone_now(self, zone: str) -> None:
        self._save_held_zones(self._load_held_zones() | {zone})

    def _reconcile_zone_body(
        self,
        token: str,
        zone: str,
        zone_payload: dict[str, Any],
        options: dict[str, Any] | None,
    ) -> None:
        if options is not None:
            self._apply_zone_options(token, zone, options)

        # Records belong to us only on a Primary. A Secondary/Stub is
        # filled by the transfer and a Forwarder holds none, so diffing
        # them would delete whatever the daemon just pulled down.
        if zone_payload.get("type", "Primary") not in _RECORD_MANAGED_ZONE_TYPES:
            return

        existing = self._get_zone_records(token, zone)
        desired = zone_payload.get("records") or []

        def _identity(rec: dict[str, Any]) -> tuple[Any, ...]:
            # Which record this is: owner, type and rdata. The TTL and
            # the disabled flag are STATE of a record, not identity, so
            # a change in either is an update in place (below) and never
            # a delete and add (#1768). Values are str()-normalised —
            # Technitium returns some rdata fields as numbers/enums where
            # our add-params are strings, and a bare type mismatch would
            # make every such record look "changed" on every pass.
            extra = tuple(
                sorted((k, str(v)) for k, v in rec.items() if k not in _RECORD_STATE_KEYS)
            )
            return (rec.get("domain"), rec.get("type"), extra)

        def _state(rec: dict[str, Any]) -> tuple[Any, ...]:
            # Compared as int so a JSON "300" from the daemon doesn't
            # read as different from a rendered 300. A record disabled
            # in the console is not served, so it is not converged.
            ttl = rec.get("ttl")
            return (int(ttl) if ttl is not None else None, bool(rec.get("disabled")))

        existing_by_id = {_identity(r): r for r in existing}
        desired_by_id = {_identity(r): r for r in desired}

        to_delete = [r for i, r in existing_by_id.items() if i not in desired_by_id]
        to_add = [r for i, r in desired_by_id.items() if i not in existing_by_id]
        # Same record, different TTL or disabled: one ``update``. Neither
        # touches the owner's PTR the way a delete does, and an RRset
        # keeps serving throughout. ``records/update`` takes the current
        # value params and, with no ``new*`` param, keeps the value; it
        # re-enables (``disable`` defaults false) and sets ``ttl``
        # (APIDOCS "Update Record"; ``AuthZone.UpdateRecord`` is a
        # zone-level delete + add, without the web API's PTR cleanup).
        to_update = [
            (existing_by_id[i], r)
            for i, r in desired_by_id.items()
            if i in existing_by_id and _state(existing_by_id[i]) != _state(r)
        ]

        updated = 0
        for old, want in to_update:
            body = self._call(
                token,
                "POST",
                "zones/records/update",
                {
                    "domain": old["domain"],
                    "zone": zone,
                    "type": old["type"],
                    **{k: v for k, v in old.items() if k not in _RECORD_STATE_KEYS},
                    "ttl": want["ttl"],
                    "disable": "false",
                },
            ).json()
            if body.get("status") == "error":
                log.warning(
                    "technitium_reconcile_update_failed",
                    zone=zone,
                    record=old,
                    error=body.get("errorMessage"),
                )
                self._note_apply_failure(
                    f"{zone}: record update {old.get('domain')} {old.get('type')}: "
                    f"{body.get('errorMessage')}"
                )
            else:
                updated += 1

        deleted = 0
        for rec in to_delete:
            resp = self._call(
                token,
                "POST",
                "zones/records/delete",
                {
                    "domain": rec["domain"],
                    "zone": zone,
                    "type": rec["type"],
                    **{k: v for k, v in rec.items() if k not in _RECORD_STATE_KEYS},
                },
            )
            body = resp.json()
            if body.get("status") == "error":
                # "no such record" means it was already gone — a no-op,
                # not a deletion. Counting it (or the failure case) would
                # report churn that never happened, which is the same
                # phantom the apex-NS filter above exists to prevent.
                if _norm_error(body.get("errorMessage")) != _RECORD_ABSENT_MESSAGE:
                    log.warning(
                        "technitium_reconcile_delete_failed",
                        zone=zone,
                        record=rec,
                        error=body.get("errorMessage"),
                    )
                    self._note_apply_failure(
                        f"{zone}: record delete {rec.get('domain')} {rec.get('type')}: "
                        f"{body.get('errorMessage')}"
                    )
            else:
                deleted += 1

        added = 0
        for rec in to_add:
            resp = self._call(
                token,
                "POST",
                "zones/records/add",
                {**rec, "zone": zone, "overwrite": "false"},
            )
            body = resp.json()
            if body.get("status") == "error":
                # "already exists" is a no-op, not an add — same
                # reasoning as the delete branch above.
                if not _is_record_noop(body.get("errorMessage")):
                    log.error(
                        "technitium_reconcile_add_failed",
                        zone=zone,
                        record=rec,
                        error=body.get("errorMessage"),
                    )
                    self._note_apply_failure(
                        f"{zone}: record add {rec.get('domain')} {rec.get('type')}: "
                        f"{body.get('errorMessage')}"
                    )
                continue
            added += 1
        if added or deleted or updated:
            log.info(
                "technitium_zone_reconciled",
                zone=zone,
                added=added,
                deleted=deleted,
                updated=updated,
            )
        self._reconcile_zone_apex(token, zone, zone_payload.get("apex"))
    def _reconcile_zone_apex(self, token: str, zone: str, apex: dict[str, Any] | None) -> None:
        """Bring a primary zone's SOA and apex NS set in line with ``apex``.

        Both are written only when they differ from what the daemon serves.
        A SOA update makes Technitium bump the serial (verified against
        15.4: it requires the current serial and stores current + 1), so an
        unconditional write would change every zone's serial on every pass.

        NS targets are added before the old ones are removed, so the zone is
        never left without a name server, even if a call fails halfway.
        """
        if not apex:
            return
        resp = self._call(token, "GET", "zones/records/get", {"domain": zone, "zone": zone})
        try:
            body = resp.json()
        except ValueError:
            return
        if body.get("status") != "ok":
            log.warning(
                "technitium_zone_apex_read_failed", zone=zone, error=body.get("errorMessage")
            )
            return
        records = body.get("response", {}).get("records") or []
        apex_name = zone.rstrip(".").lower()
        at_apex = [r for r in records if (r.get("name") or "").lower() == apex_name]
        soa = next((r for r in at_apex if r.get("type") == "SOA"), None)
        live_ns = [
            str((r.get("rData") or {}).get("nameServer") or "").rstrip(".").lower()
            for r in at_apex
            if r.get("type") == "NS"
        ]
        live_ns_ttl = {
            str((r.get("rData") or {}).get("nameServer") or "").rstrip(".").lower(): r.get("ttl")
            for r in at_apex
            if r.get("type") == "NS"
        }

        soa_changed = False
        desired_soa = apex.get("soa") or {}
        ttl = apex.get("ttl")
        if soa is not None and (desired_soa or ttl is not None):
            current = soa.get("rData") or {}
            current_fields: dict[str, Any] = {
                key: str(current.get(key) or "").rstrip(".").lower()
                for key in ("primaryNameServer", "responsiblePerson")
            }
            current_fields.update({f: current.get(f) for f in _SOA_TIMERS})
            differs = any(current_fields.get(k) != v for k, v in desired_soa.items())
            if ttl is not None and soa.get("ttl") != ttl:
                differs = True
            if differs:
                params: dict[str, Any] = {
                    "zone": zone,
                    "domain": zone,
                    "type": "SOA",
                    "serial": current.get("serial"),
                    "ttl": ttl if ttl is not None else soa.get("ttl"),
                    **{k: current_fields[k] for k in ("primaryNameServer", "responsiblePerson")},
                    **{f: current.get(f) for f in _SOA_TIMERS},
                }
                params.update(desired_soa)
                body = self._call(token, "POST", "zones/records/update", params).json()
                if body.get("status") == "ok":
                    soa_changed = True
                else:
                    log.warning(
                        "technitium_zone_soa_update_failed",
                        zone=zone,
                        error=body.get("errorMessage"),
                    )

        added: list[str] = []
        removed: list[str] = []
        retimed: list[str] = []
        desired_ns = apex.get("ns") or []
        # The set's TTL, when the zone declares one (#1768): without it a
        # TTL-only change to the apex NS never reached the daemon, because a
        # target already there was skipped whatever its TTL.
        ns_ttl = apex.get("ns_ttl")
        if desired_ns:
            for target in desired_ns:
                if target in live_ns:
                    if ns_ttl is not None and live_ns_ttl.get(target) != ns_ttl:
                        # In place: a delete and add would leave the zone
                        # without that name server for a moment.
                        body = self._call(
                            token,
                            "POST",
                            "zones/records/update",
                            {
                                "zone": zone,
                                "domain": zone,
                                "type": "NS",
                                "nameServer": target,
                                "ttl": ns_ttl,
                            },
                        ).json()
                        if body.get("status") == "ok":
                            retimed.append(target)
                        else:
                            log.warning(
                                "technitium_zone_apex_ns_ttl_failed",
                                zone=zone,
                                name_server=target,
                                error=body.get("errorMessage"),
                            )
                    continue
                body = self._call(
                    token,
                    "POST",
                    "zones/records/add",
                    {
                        "zone": zone,
                        "domain": zone,
                        "type": "NS",
                        "ttl": ns_ttl if ns_ttl is not None else (ttl if ttl is not None else 3600),
                        "nameServer": target,
                    },
                ).json()
                if body.get("status") == "ok":
                    added.append(target)
                else:
                    log.warning(
                        "technitium_zone_apex_ns_add_failed",
                        zone=zone,
                        name_server=target,
                        error=body.get("errorMessage"),
                    )
            # Only drop the old set once the new one is in place.
            if all(t in live_ns or t in added for t in desired_ns):
                for target in live_ns:
                    if target in desired_ns:
                        continue
                    body = self._call(
                        token,
                        "POST",
                        "zones/records/delete",
                        {"zone": zone, "domain": zone, "type": "NS", "nameServer": target},
                    ).json()
                    if body.get("status") == "ok":
                        removed.append(target)
                    else:
                        log.warning(
                            "technitium_zone_apex_ns_delete_failed",
                            zone=zone,
                            name_server=target,
                            error=body.get("errorMessage"),
                        )
        if soa_changed or added or removed or retimed:
            log.info(
                "technitium_zone_apex_reconciled",
                zone=zone,
                soa_updated=soa_changed,
                ns_added=added,
                ns_removed=removed,
                ns_retimed=retimed,
            )

    def _ensure_zone_exists(self, token: str, entry: dict[str, Any]) -> bool:
        """Create the zone if absent, with the params its type requires.

        Returns True when this call created the zone, or converted an
        existing one into a Primary (#1457): either way the zone starts
        answering authoritatively from a SOA that is not its own, so the
        caller holds it until the apex is reconciled (#1758).

        Unlike a Primary, a Secondary/Stub create is **not** guaranteed to
        succeed and is **not** safely retryable-forever: Technitium resolves
        SOA against the configured primaries at create time and errors if
        none answer (verified live — "DNS Server did not receive SOA record
        in response from any of the primary name servers"). So an
        unreachable or misconfigured primary fails here on every reconcile
        pass. Logged at error, deliberately loudly, because the zone simply
        will not exist until the operator fixes the far end.
        """
        zone = entry["zone"]
        ztype = entry.get("type", "Primary")
        params: dict[str, Any] = {"zone": zone, "type": ztype}
        forwarder_specs: list[tuple[str, str, int]] = []
        dnssec: bool | None = None
        if ztype in ("Secondary", "Stub", "SecondaryCatalog"):
            params["primaryNameServerAddresses"] = ",".join(
                _technitium_master(m) for m in entry.get("masters") or []
            )
            if ztype in _TSIG_SECONDARY_ZONE_TYPES and entry.get("tsig_key"):
                # The key the zone's masters require for a transfer (#1765).
                # Without it a signed-only primary refuses every AXFR, and the
                # zone expires to SERVFAIL after a create that succeeded.
                params["tsigKeyName"] = entry["tsig_key"]
        elif ztype == "Forwarder":
            # First upstream rides zones/create with its protocol (without
            # ``protocol`` Technitium uses Udp and re-derives the address, so
            # a DoH URL went out as cleartext host:53, #1764). The rest are
            # further apex FWD records, added by ``_sync_forwarder_records``.
            forwarder_specs = _forwarder_specs([str(f) for f in entry.get("forwarders") or []])
            dnssec = entry.get("dnssec_validation")
            params["forwarder"] = forwarder_specs[0][0]
            params["protocol"] = forwarder_specs[0][1]
            if dnssec is not None:
                params["dnssecValidation"] = "true" if dnssec else "false"

        resp = self._call(token, "POST", "zones/create", params)
        body = resp.json()
        if body.get("status") == "error":
            if _is_zone_exists(body.get("errorMessage")):
                # The create params carry the zone's UPSTREAM (a
                # secondary/stub's primaries, a forwarder's target), and
                # create is a no-op once the zone exists. Without this,
                # retargeting a secondary at a new primary would be a
                # permanent silent no-op: the operator edits it, the
                # bundle changes, and the daemon keeps transferring from
                # the old address forever.
                #
                # The same holds for the zone TYPE (#1457): a zone switched
                # from forward to primary in SpatiumDDI stayed a Forwarder
                # here, so every name that was not a local record went to
                # the old upstream. Convert first, so the upstream below is
                # applied to the type the zone now has (a zone converted to
                # Forwarder gets every upstream in the bundle, #1764).
                converted = self._reconcile_zone_type(token, zone, ztype)
                self._reapply_zone_upstream(
                    token, zone, ztype, params, forwarder_specs, dnssec
                )
                return converted
            log.error(
                "technitium_zone_create_failed",
                zone=zone,
                zone_type=ztype,
                error=body.get("errorMessage"),
            )
            self._note_apply_failure(
                f"{zone}: zone create: {body.get('errorMessage')}"
            )
            return False
        if ztype == "Forwarder":
            # The create carried the first upstream only.
            self._sync_forwarder_records(token, zone, forwarder_specs, dnssec)
        return True

    def _reconcile_zone_type(self, token: str, zone: str, ztype: str) -> bool:
        """Bring an existing zone's type in line with the bundle (#1457).

        ``zones/create`` never changes the type of a zone that already
        exists, so a type change in SpatiumDDI used to stop at the daemon.
        ``zones/convert`` changes it in place and keeps the zone's records
        (verified live against 15.4.0: Forwarder → Primary keeps every
        record, Primary → Forwarder works too). Converting to Secondary or
        Stub is refused by Technitium ("not supported") from both Primary
        and Forwarder; that is logged at error rather than worked around
        with a delete + recreate, because deleting a zone is not something
        the agent does on its own (see ``_reconcile_zones``).

        An unreadable live type is skipped, not guessed: converting on a
        wrong guess is worse than leaving the zone as it is.

        Returns True when the zone was converted (to any type).
        """
        body = self._call(token, "GET", "zones/options/get", {"zone": zone}).json()
        live = (body.get("response") or {}).get("type") if body.get("status") == "ok" else None
        if not live:
            log.warning(
                "technitium_zone_type_unreadable",
                zone=zone,
                error=body.get("errorMessage"),
            )
            return False
        if live == ztype:
            return False
        resp = self._call(token, "POST", "zones/convert", {"zone": zone, "type": ztype}).json()
        if resp.get("status") == "ok":
            log.info("technitium_zone_type_converted", zone=zone, from_type=live, to_type=ztype)
            if live == "Forwarder" and ztype == "Primary":
                self._replace_placeholder_soa(token, zone)
            return True
        log.error(
            "technitium_zone_type_mismatch",
            zone=zone,
            live_type=live,
            desired_type=ztype,
            error=resp.get("errorMessage"),
        )
        self._note_apply_failure(f"{zone}: zone type: {resp.get('errorMessage')}")
        return False

    def _reapply_zone_upstream(
        self,
        token: str,
        zone: str,
        ztype: str,
        params: dict[str, Any],
        forwarder_specs: list[tuple[str, str, int]] | None = None,
        dnssec: bool | None = None,
    ) -> None:
        """Push an existing zone's upstream to the daemon.

        A secondary/stub's primaries go through ``zones/options/set``. A
        Forwarder's upstreams do not: ``zones/options/set`` has no
        ``forwarder`` parameter (it answers ``ok`` and stores nothing,
        #1647); they live in the zone's apex FWD records, see
        ``_sync_forwarder_records``.
        """
        if "forwarder" in params:
            self._sync_forwarder_records(token, zone, forwarder_specs or [], dnssec)
            return
        opts: dict[str, Any] = {"zone": zone}
        if "primaryNameServerAddresses" in params:
            opts["primaryNameServerAddresses"] = params["primaryNameServerAddresses"]
        else:
            return
        if ztype in _TSIG_SECONDARY_ZONE_TYPES:
            # Always sent, empty included: an absent parameter leaves the old
            # key, an empty one clears it (``WebServiceZonesApi.cs``), and the
            # control plane decides which masters need signing (#1765).
            opts["primaryZoneTransferTsigKeyName"] = params.get("tsigKeyName", "")
        body = self._call(token, "POST", "zones/options/set", opts).json()
        if body.get("status") != "ok":
            log.warning(
                "technitium_zone_upstream_reapply_failed",
                zone=zone,
                zone_type=ztype,
                error=body.get("errorMessage"),
            )
            self._note_apply_failure(
                f"{zone}: zone upstream: {body.get('errorMessage')}"
            )

    def _apex_records(self, token: str, zone: str) -> list[dict[str, Any]] | None:
        """The zone's apex records, or None when they can't be read."""
        body = self._call(
            token, "GET", "zones/records/get", {"domain": zone, "zone": zone}
        ).json()
        if body.get("status") != "ok":
            log.warning(
                "technitium_zone_apex_unreadable", zone=zone, error=body.get("errorMessage")
            )
            return None
        return [
            r
            for r in (body.get("response") or {}).get("records") or []
            if (r.get("name") or "").rstrip(".").lower() == zone.lower()
        ]

    def _sync_forwarder_records(
        self,
        token: str,
        zone: str,
        specs: list[tuple[str, str, int]],
        dnssec: bool | None,
    ) -> None:
        """Make the zone's apex FWD records exactly ``specs`` (#1764).

        A Forwarder zone's upstreams are its apex FWD records. A record's
        identity is ``(protocol, forwarder)``; ``forwarderPriority`` and
        ``dnssecValidation`` are its data (APIDOCS.md "Add Record" /
        "Update Record" / "Delete Record"; ``WebServiceZonesApi.cs``).
        So: a missing record is added, one whose priority or DNSSEC flag
        differs is updated in place, and a record no longer wanted is
        deleted LAST, so the zone never has no upstream in between. If an
        add is refused, nothing is deleted: the old upstream stays until
        the new one is in (#1647). ``dnssec`` None leaves the flag at
        whatever the record has.

        This is also the path a zone converted to Forwarder takes
        (#1457): ``zones/convert`` from Primary leaves it with no FWD
        record at all, so every upstream here is an add. Every refusal is
        noted, so a refused forwarder change reads as a partial apply
        (#1516).
        """
        if not specs:
            return
        apex = self._apex_records(token, zone)
        if apex is None:
            self._note_apply_failure(f"{zone}: zone upstream: apex records unreadable")
            return
        live = [(r.get("rData") or {}) for r in apex if r.get("type") == "FWD"]
        by_key = {(_norm_forwarder(r.get("forwarder") or ""), r.get("protocol") or "Udp"): r for r in live}
        wanted: set[tuple[str, str]] = set()
        add_refused = False
        for address, protocol, priority in specs:
            key = (_norm_forwarder(address), protocol)
            wanted.add(key)
            have = by_key.get(key)
            params: dict[str, Any] = {
                "domain": zone,
                "zone": zone,
                "type": "FWD",
                "forwarder": address,
                "protocol": protocol,
                "forwarderPriority": str(priority),
            }
            if have is None:
                if dnssec is not None:
                    params["dnssecValidation"] = "true" if dnssec else "false"
                path = "zones/records/add"
            else:
                live_dnssec = bool(have.get("dnssecValidation"))
                if int(have.get("priority") or 0) == priority and (
                    dnssec is None or live_dnssec == dnssec
                ):
                    continue
                params["forwarder"] = have.get("forwarder") or address
                params["dnssecValidation"] = (
                    "true" if (live_dnssec if dnssec is None else dnssec) else "false"
                )
                path = "zones/records/update"
            result = self._call(token, "POST", path, params).json()
            if result.get("status") != "ok" and _is_record_noop(result.get("errorMessage")):
                # Technitium's exact "record already exists" (#1770): this
                # upstream is in, under a spelling ``_norm_forwarder`` did not
                # fold to ours. Applied, so it does not hold back the stale
                # deletes below. The CNAME-style conflict answers are not in
                # the no-op set and still count as refused.
                log.info("technitium_zone_forwarder_set", zone=zone, forwarder=address)
            elif result.get("status") != "ok":
                log.warning(
                    "technitium_zone_forwarder_set_failed",
                    zone=zone,
                    forwarder=address,
                    error=result.get("errorMessage"),
                )
                self._note_apply_failure(
                    f"{zone}: zone upstream: {address}: {result.get('errorMessage')}"
                )
                if path == "zones/records/add":
                    add_refused = True
            else:
                log.info("technitium_zone_forwarder_set", zone=zone, forwarder=address)
        stale = [(k, r) for k, r in by_key.items() if k not in wanted]
        if stale and add_refused:
            log.warning(
                "technitium_zone_forwarder_stale_kept",
                zone=zone,
                forwarders=[r.get("forwarder") for _, r in stale],
            )
            return
        for _key, rdata in stale:
            result = self._call(
                token,
                "POST",
                "zones/records/delete",
                {
                    "domain": zone,
                    "zone": zone,
                    "type": "FWD",
                    "forwarder": rdata.get("forwarder"),
                    "protocol": rdata.get("protocol") or "Udp",
                },
            ).json()
            if result.get("status") != "ok" and (
                _norm_error(result.get("errorMessage")) != _RECORD_ABSENT_MESSAGE
            ):
                # "no such record exists" (#1770): already gone, which is the
                # state this delete wanted.
                log.warning(
                    "technitium_zone_forwarder_remove_failed",
                    zone=zone,
                    forwarder=rdata.get("forwarder"),
                    error=result.get("errorMessage"),
                )
                self._note_apply_failure(
                    f"{zone}: zone upstream: {rdata.get('forwarder')}: "
                    f"{result.get('errorMessage')}"
                )

    def _replace_placeholder_soa(self, token: str, zone: str) -> None:
        """Give a zone converted from Forwarder a real SOA.

        A Forwarder zone carries a placeholder SOA (responsible person
        ``invalid``, TTL 0), and ``zones/convert`` keeps it. As a Primary
        that means negative answers are not cached. Set what Technitium
        gives a zone created as Primary (``hostadmin@<zone>``, TTL 900),
        keeping the rest. Only the placeholder is touched; any other SOA
        is left alone.
        """
        apex = self._apex_records(token, zone)
        soa = next((r for r in apex or [] if r.get("type") == "SOA"), None)
        if soa is None:
            return
        rdata = soa.get("rData") or {}
        if rdata.get("responsiblePerson") != "invalid":
            return
        body = self._call(
            token,
            "POST",
            "zones/records/update",
            {
                "domain": zone,
                "zone": zone,
                "type": "SOA",
                "ttl": "900",
                "primaryNameServer": rdata.get("primaryNameServer") or "",
                "responsiblePerson": f"hostadmin@{zone}",
                "serial": str(rdata.get("serial") or 1),
                "refresh": str(rdata.get("refresh") or 900),
                "retry": str(rdata.get("retry") or 300),
                "expire": str(rdata.get("expire") or 604800),
                "minimum": str(rdata.get("minimum") or 900),
            },
        ).json()
        if body.get("status") != "ok":
            log.warning(
                "technitium_zone_soa_placeholder_kept", zone=zone, error=body.get("errorMessage")
            )

    def _apply_zone_options(
        self, token: str, zone: str, options: dict[str, Any]
    ) -> bool:
        """Push per-zone options, validating enums before we send them.

        ``zones/options/set`` answers ``{"status": "ok"}`` for a value it
        does not recognise and leaves the existing setting untouched
        (verified live with ``zoneTransfer="Bogus"``). So an unvalidated
        typo would not fail — it would quietly leave zone transfer at
        whatever it was, which for a zone we meant to lock down is a
        security regression that no log line would report. Refuse to send
        anything not in the known set.

        True when there was nothing to send or the daemon took it.
        """
        options = dict(options)
        # Only the hold release reads it (#2263); never a daemon parameter.
        options.pop("_release_query_access", None)
        for item in options.pop("_unapplied", None) or []:
            # Left as the daemon has it rather than guessed at (see
            # ``_query_access`` / ``_transfer_access``); the API refuses to
            # store such a value for a Technitium group, so this is a row saved
            # before that gate.
            log.error("technitium_zone_option_unapplied", zone=zone, **item)
            if self._unapplied_acl is not None:
                self._unapplied_acl.setdefault(item["kind"], []).append(zone)
        if not options:
            return True
        transfer = options.get("zoneTransfer")
        if transfer is not None and transfer not in _ZONE_TRANSFER_VALUES:
            log.error(
                "technitium_zone_transfer_value_invalid",
                zone=zone,
                value=transfer,
                supported=sorted(_ZONE_TRANSFER_VALUES),
            )
            self._note_apply_failure(f"{zone}: zone options: bad zoneTransfer {transfer}")
            return False

        params: dict[str, Any] = {"zone": zone}
        for key, value in options.items():
            # List-valued options go over the wire comma-joined.
            params[key] = ",".join(str(v) for v in value) if isinstance(value, list) else value

        resp = self._call(token, "POST", "zones/options/set", params)
        body = resp.json()
        if body.get("status") != "ok":
            log.warning(
                "technitium_zone_options_failed",
                zone=zone,
                error=body.get("errorMessage"),
            )
            self._note_apply_failure(
                f"{zone}: zone options: {body.get('errorMessage')}"
            )
            return False
        return True

    def _get_zone_records(self, token: str, zone: str) -> list[dict[str, Any]]:
        resp = self._call(
            token,
            "GET",
            "zones/records/get",
            {"domain": zone, "zone": zone, "listZone": "true"},
        )
        try:
            body = resp.json()
        except ValueError:
            self._note_apply_failure(f"{zone}: zone records get: non-JSON response")
            return []
        if body.get("status") != "ok":
            # Reading an empty/error body as "zone is empty" would make
            # the reconcile re-add everything and report the refused
            # reads as churn (#1516).
            self._note_apply_failure(
                f"{zone}: zone records get: {body.get('errorMessage') or body.get('status')}"
            )
            return []
        out = []
        for rec in body.get("response", {}).get("records") or []:
            rtype = rec.get("type")
            if rtype in _DAEMON_MANAGED_APEX_TYPES:
                continue
            # Signing artefacts belong to the daemon, not the bundle. A
            # signed zone serves DNSKEY/RRSIG/NSEC* that no bundle
            # describes, so without this the reconciler tries to delete
            # the zone's own signatures on every pass.
            if rtype in _DNSSEC_RECORD_TYPES:
                continue
            # Apex NS is daemon-managed too (Technitium stamps one pointing
            # at its own hostname at zone-create). Filter it HERE rather
            # than skipping it later in the delete loop: left in, it lands
            # in ``to_delete`` on every pass, gets skipped, and still gets
            # counted — reporting a deletion that never happened and making
            # a steady-state zone look like it churns its apex NS forever.
            if rtype == "NS" and (rec.get("name") or "") == zone:
                continue
            flat = {"domain": rec.get("name"), "type": rtype, "ttl": rec.get("ttl")}
            flat.update(rec.get("rData") or {})
            if rec.get("disabled"):
                flat["disabled"] = True
            # Technitium's SVCB/HTTPS rData carries derived fields
            # (autoIpv4Hint/autoIpv6Hint) that never round-trip through our
            # add params — drop them so the fingerprint comparison in
            # ``_reconcile_zones`` doesn't treat every such record as
            # "different from desired" on every single reconcile pass.
            # TXT's derived fields are folded by ``_normalize_rdata``
            # (#1694).
            for extra_key in ("autoIpv4Hint", "autoIpv6Hint"):
                flat.pop(extra_key, None)
            out.append(_normalize_rdata(rtype, flat))
        return out

    # ── Auth (permanent API token) ──────────────────────────────────────────

    def _admin_password_path(self) -> Path:
        return self.state_dir / _ADMIN_PASSWORD_FILE

    def _api_token_path(self) -> Path:
        return self.state_dir / _API_TOKEN_FILE

    def admin_bootstrap_password(self) -> str:
        """Return the admin password used to initialise the daemon on its
        very first start (via the ``DNS_SERVER_ADMIN_PASSWORD`` env var
        passed to the subprocess). Generated once, persisted like the
        PowerDNS API key (atomic O_NOFOLLOW write, 0600) — needed again
        any time the local API token is lost and must be re-derived via
        ``/api/user/createToken``.
        """
        return self._read_or_create_secret(self._admin_password_path())

    def _get_api_token(self) -> str | None:
        path = self._api_token_path()
        if path.exists():
            try:
                return path.read_text().strip()
            except PermissionError as exc:
                raise RuntimeError(
                    f"Technitium API token file at {path} exists but is "
                    "unreadable by the agent. Fix ownership/permissions "
                    "(should be spatium:spatium 0600)."
                ) from exc
        return self._create_api_token()

    def _create_api_token(self) -> str | None:
        """Exchange the admin bootstrap password for a permanent API
        token via ``/api/user/createToken`` — called at most once ever
        per state dir, since the endpoint mints a NEW token on every
        call (confirmed empirically: it is not idempotent on
        ``tokenName``, so retrying here would silently accumulate
        orphaned tokens on the server).
        """
        password = self.admin_bootstrap_password()
        self._raise_if_creds_cooling_down()
        try:
            # A form body, never query parameters: a URL is logged (httpx
            # writes every request line at INFO) and the password must not be
            # (GHSA-x4gw-9gqx-vr4m).
            resp = httpx.post(
                f"{_API_BASE}/user/createToken",
                data={"user": "admin", "pass": password, "tokenName": _TOKEN_NAME},
                timeout=_API_TIMEOUT,
            )
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.error("technitium_create_token_failed", error=str(exc))
            return None
        if body.get("status") != "ok" or not body.get("token"):
            detail = str(body.get("errorMessage") or "")
            log.error("technitium_create_token_rejected", error=detail or None)
            # Verified against APIDOCS.md ("2fa-required" status) and
            # AuthManager.cs: a wrong password answers "Invalid username or
            # password for user: …" and TOTP-enabled users get 2fa-required.
            # Both are verdicts about the credentials, not transient faults.
            # A blocked address answers "Max limit of 5 attempts exceeded"
            # before the password is even checked (not counted, but the
            # agent would otherwise retry it on every op).
            reason = None
            if body.get("status") == "2fa-required":
                reason = "2fa-required"
            elif "invalid username or password" in detail.lower():
                reason = "bad-credentials"
            elif detail.lower().startswith("max limit of"):
                reason = "locked-out"
            if reason is not None:
                self._record_creds_rejected(reason, detail)
                raise TechnitiumCredentialsError(reason, detail)
            return None
        token = body["token"]
        self._write_secret(self._api_token_path(), token)
        log.info("technitium_api_token_created")
        return token

    def _creds_rejected_path(self) -> Path:
        return self.state_dir / _CREDS_REJECTED_FILE

    def _password_file_identity(self) -> str:
        """Which version of the admin password file is on disk.

        Inode, size and mtime, so a rewritten file lifts the hold, without
        storing anything derived from the password itself: a fast hash of it
        in the state directory could be guessed offline (#1772, CodeQL).
        Empty when the file is missing.
        """
        try:
            st = self._admin_password_path().stat()
        except OSError:
            return ""
        return f"{st.st_ino}:{st.st_size}:{st.st_mtime_ns}"

    def _record_creds_rejected(self, reason: str, detail: str) -> None:
        # ``detail`` is kept so the suppressed attempts report the same error
        # text as the real one: a steady apply-status error, not one that
        # changes shape after the first failure.
        write_private(
            self._creds_rejected_path(),
            json.dumps(
                {
                    "reason": reason,
                    "detail": detail,
                    "at": time.time(),
                    "pw_file": self._password_file_identity(),
                }
            ),
        )

    def _raise_if_creds_cooling_down(self) -> None:
        """Refuse to present credentials Technitium has already refused.

        Lifted by a changed password file, by the retry window elapsing, or
        by deleting the marker; an unreadable marker never blocks.
        """
        path = self._creds_rejected_path()
        try:
            rec = json.loads(path.read_text())
            reason = str(rec["reason"])
            detail = str(rec.get("detail") or "")
            at = float(rec["at"])
            same_pw = rec.get("pw_file") == self._password_file_identity()
        except (OSError, ValueError, KeyError, TypeError):
            return
        if same_pw and time.time() - at < _CREDS_RETRY_SECONDS:
            log.warning("technitium_create_token_suppressed", reason=reason)
            raise TechnitiumCredentialsError(reason, detail)
        path.unlink(missing_ok=True)

    @staticmethod
    def _write_secret(path: Path, value: str) -> None:
        """0600 + atomic, via the shared primitive (#869).

        The trailing newline is part of this store's format —
        ``_read_or_create_secret`` strips it on the way back out.
        """
        write_private(path, value + "\n")

    def _read_or_create_secret(self, path: Path) -> str:
        if path.exists():
            try:
                return path.read_text().strip()
            except PermissionError as exc:
                raise RuntimeError(
                    f"Secret file at {path} exists but is unreadable by "
                    "the agent. Fix ownership/permissions (should be "
                    "spatium:spatium 0600)."
                ) from exc
        value = secrets.token_urlsafe(24)
        self._write_secret(path, value)
        return value

    def _call(
        self, token: str, method: str, path: str, params: dict[str, Any]
    ) -> httpx.Response:
        """Issue one API call, auth'd via ``Authorization: Bearer``.

        Technitium returns HTTP 200 even on an invalid/expired token —
        the failure surfaces only in the JSON body's ``status`` field
        (confirmed empirically: ``{"status": "invalid-token", ...}`` at
        HTTP 200). Callers must inspect ``.json()["status"]``, not the
        HTTP status code, to detect auth failure.

        On ``invalid-token`` the cached token is re-provisioned and the
        call retried once. The state dir (which holds the token) and
        ``/etc/dns`` (which holds the daemon's admin account) are
        SEPARATE volumes in every deployment shape, so they can desync —
        wipe the daemon's config to reset zones and the cached token now
        points at an account that no longer exists. Without this the
        agent wedges permanently: every call 200s with ``invalid-token``,
        ``_get_zone_records`` reads it as an empty zone, every add fails,
        and nothing ever re-bootstraps. Mirrors the agent↔control-plane
        401/404 re-bootstrap contract (CLAUDE.md cross-cutting #3).
        """
        resp = self._request(token, method, path, params)
        if self._is_invalid_token(resp):
            fresh = self._reprovision_token(token)
            if fresh is not None:
                log.info("technitium_api_token_reprovisioned", path=path)
                resp = self._request(fresh, method, path, params)
        # A daemon that cannot authenticate us or answers 5xx has not
        # REFUSED anything — it is unusable. Raise, so a structural apply
        # fails (and is quarantined / reverted) instead of reading every
        # step as a per-item refusal and reporting a partial apply (#1608).
        if self._is_invalid_token(resp):
            raise RuntimeError(f"Technitium API {path}: token rejected (auth failure)")
        status_code = getattr(resp, "status_code", 200)
        if isinstance(status_code, int) and status_code >= 500:
            raise RuntimeError(f"Technitium API {path}: HTTP {status_code}")
        return resp

    def _request(
        self, token: str, method: str, path: str, params: dict[str, Any]
    ) -> httpx.Response:
        with httpx.Client(timeout=_API_TIMEOUT) as client:
            headers = self._auth_header(token)
            if method == "GET":
                return client.get(f"{_API_BASE}/{path}", params=params, headers=headers)
            return client.post(f"{_API_BASE}/{path}", data=params, headers=headers)

    @staticmethod
    def _is_invalid_token(resp: httpx.Response) -> bool:
        try:
            return bool(resp.json().get("status") == "invalid-token")
        except ValueError:
            # Non-JSON body — not an auth answer; let the caller surface it.
            return False

    def _reprovision_token(self, stale: str) -> str | None:
        """Drop the cached token and mint a fresh one.

        Re-reads the file first: several calls in one reconcile pass hold
        the same stale token in a local, so without this each would mint
        its own replacement and orphan the rest server-side
        (``createToken`` is not idempotent on ``tokenName``).
        """
        path = self._api_token_path()
        try:
            current = path.read_text().strip() if path.exists() else None
        except OSError:
            current = None
        if current is not None and current != stale:
            return current
        path.unlink(missing_ok=True)
        return self._create_api_token()

    @staticmethod
    def _auth_header(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start_daemon(self) -> None:
        """Spawn ``dotnet DnsServerApp.dll /etc/dns``.

        The bootstrap admin password is passed via
        ``DNS_SERVER_ADMIN_PASSWORD`` on every start — Technitium only
        consumes it the very first time ``/etc/dns`` is empty (fresh
        config), so this is a harmless no-op on every subsequent start.
        """
        if not shutil.which("dotnet"):
            log.error("technitium_dotnet_binary_missing")
            return
        existing = find_running_daemon("dotnet")
        if existing is not None:
            self.daemon_pid = existing
            log.info(
                "technitium_already_running_adopted",
                pid=existing,
                note="did not spawn a second daemon",
            )
            return
        env = dict(os.environ)
        env["DNS_SERVER_ADMIN_PASSWORD"] = self.admin_bootstrap_password()
        log_path = self.state_dir / "technitium.log"
        log_fh = log_path.open("ab", buffering=0)
        self.daemon_pid = subprocess.Popen(
            ["dotnet", "/opt/technitium/dns/DnsServerApp.dll", "/etc/dns"],
            env=env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
        ).pid
        self._daemon_log_path = log_path
        log.info("technitium_dns_server_started", pid=self.daemon_pid, log_path=str(log_path))

    def daemon_running(self) -> bool:
        if self.daemon_pid is None:
            found = find_running_daemon("dotnet")
            if found is None:
                return False
            self.daemon_pid = found
            return True
        try:
            os.kill(self.daemon_pid, 0)
        except OSError:
            return False
        return not is_zombie(str(self.daemon_pid))


__all__ = ["TechnitiumDriver"]
