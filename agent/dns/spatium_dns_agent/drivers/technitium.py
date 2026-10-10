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
import ipaddress
import json
import os
import secrets
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from ..secure_io import write_private
from ._process import find_running_daemon, is_zombie
from ._txt import txt_strings
from .base import RRSET_OP_KINDS, DriverBase

log = structlog.get_logger(__name__)


_API_BASE = "http://127.0.0.1:5380/api"
_API_TIMEOUT = 10.0
_ADMIN_PASSWORD_FILE = "technitium-admin-password"
_API_TOKEN_FILE = "technitium-api.token"
_TOKEN_NAME = "spatiumddi-agent"
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
_TSIG_ALGORITHMS = frozenset(
    {
        "hmac-md5",
        "hmac-sha1",
        "hmac-sha256",
        "hmac-sha256-128",
        "hmac-sha384",
        "hmac-sha512",
    }
)


def _qualified_name(zone_name: str, name: str) -> str:
    """Compose the bare (no trailing dot) FQDN Technitium expects for a
    record's ``domain`` param."""
    zone = zone_name.rstrip(".")
    bare = (name or "@").rstrip(".")
    if bare in ("", "@") or bare == zone:
        return zone
    return f"{bare}.{zone}"


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


def _svcb_params(value: str) -> tuple[int, str, str]:
    """Parse a BIND-zone-file-style SVCB/HTTPS rdata string into
    ``(priority, target, svcParams)`` for the Technitium API.

    Input shape (matches what the control-plane driver + BIND9 render,
    e.g. ``'1 . alpn="h2,h3"'``): priority, target, then space-separated
    ``key=value`` params with optionally-quoted values.

    Multi-value params pass through intact: Technitium's ``svcParams``
    wire format is ``key|value`` pairs comma-joined, and a single param
    whose value itself contains commas (``alpn|h2,h3``) is accepted and
    stored as ``{"alpn": "h2,h3"}`` — verified against a live
    ``technitium/dns-server:15.4.0``. What it rejects is splitting the
    values into separate pairs (``alpn|h2|h3`` and ``alpn|h2,alpn|h3``
    both fail with "Requested value 'h3' was not found"), so join on
    the value, never on the key. Issue #745.
    """
    tokens = shlex.split(value)
    if len(tokens) < 2:
        return (1, ".", "")
    priority = int(tokens[0]) if tokens[0].isdigit() else 1
    # The caller's leading ``value.rstrip(".")`` cannot reach this target —
    # it is mid-string, with the svcParams after it — so strip the root dot
    # here. Technitium stores the target un-dotted, and leaving it on makes
    # every SVCB/HTTPS record read as changed on every reconcile. ``or "."``
    # keeps a bare apex target from becoming the empty string.
    target = (tokens[1].rstrip(".") or ".").lower()
    # Pairs are emitted SORTED BY KEY (#1513): the read-back side rebuilds
    # svcParams sorted (``_normalize_rdata`` sorts the daemon's dict), so
    # an operator-typed order never matched and the record was deleted
    # and re-added on every structural reconcile.
    #
    # A valueless param (``no-default-alpn``) is emitted as ``key|`` —
    # the empty-value form of the same wire pair — instead of being
    # skipped, which silently changed the served answer. NOTE: the
    # ``key|`` form has NOT been verified against a live daemon (the fix
    # direction in #1513 asks for that check); if a daemon rejects it,
    # the #1516 partial-refusal path now surfaces the refusal instead of
    # the record silently never being served.
    parsed: list[tuple[str, str]] = []
    for tok in tokens[2:]:
        if "=" in tok:
            key, _, raw_val = tok.partition("=")
            parsed.append((key, f"{key}|{raw_val}"))
        else:
            parsed.append((tok, f"{tok}|"))
    parsed.sort(key=lambda pair: pair[0])
    return (priority, target, ",".join(pair for _, pair in parsed))


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
        _move("replacement", "naptrReplacement")
    elif rtype == "URI":
        _move("priority", "uriPriority")
        _move("weight", "uriWeight")
        # Technitium normalises a bare-authority URI by appending "/".
        # Strip that one slash on both sides rather than let it churn
        # the record — but ONLY that one: a path's trailing slash is
        # significant (#1513).
        if "uri" in out:
            out["uri"] = _strip_bare_authority_slash(str(out["uri"]))
    elif rtype in ("SVCB", "HTTPS"):
        # svcParams goes out as "k|v,k|v" and comes back as a dict.
        params = out.get("svcParams")
        if isinstance(params, dict):
            out["svcParams"] = ",".join(f"{k}|{v}" for k, v in sorted(params.items()))
        if out.get("svcTargetName"):
            out["svcTargetName"] = str(out["svcTargetName"]).lower()
        # An apex target "." is stored as the empty string.
        if out.get("svcTargetName") == "":
            out["svcTargetName"] = "."
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
    if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl > 0:
        # The SOA record's own TTL caps negative caching together with
        # MINIMUM (RFC 2308), and BIND serves it at the zone's $TTL.
        apex["ttl"] = ttl
    return apex


def _tsig_key_names(bundle: dict[str, Any]) -> list[str]:
    """Bundle TSIG key names, root dot stripped.

    Technitium stores names un-dotted (verified: sending ``spatium-xfer.``
    reads back as ``spatium-xfer``), so normalise here or every options
    comparison sees a difference that isn't one.
    """
    out = []
    for k in bundle.get("tsig_keys") or []:
        name = (k.get("name") or "").rstrip(".")
        if name:
            out.append(name)
    return sorted(set(out))


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

    The list follows BIND's vocabulary: ``["none"]`` (or empty) denies,
    ``any`` allows, anything else is treated as a network ACL.

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
    if ztype != "Primary":
        return {}
    opts = bundle.get("options") or {}
    zone_acl = (zone or {}).get("allow_transfer")
    source = zone_acl if zone_acl is not None else opts.get("allow_transfer")
    acl = [str(a) for a in (source or []) if a]
    lowered = {a.lower() for a in acl}
    names = _tsig_key_names(bundle)

    payload: dict[str, Any] = {}
    if not acl or lowered == {"none"}:
        payload["zoneTransfer"] = "Allow" if names else "Deny"
    elif "any" in lowered:
        payload["zoneTransfer"] = "Allow"
    else:
        payload["zoneTransfer"] = "UseSpecifiedNetworkACL"
        payload["zoneTransferNetworkACL"] = [a for a in acl if a.lower() != "none"]

    # Naming keys here is what makes a transfer TSIG-*authenticated* rather
    # than merely address-filtered.
    #
    # ALWAYS sent, including empty. Technitium treats an absent parameter as
    # "leave unchanged" and an empty one as "clear" (verified in upstream
    # ``WebServiceZonesApi.cs``: ``Length == 0`` sets the set to null). So
    # omitting it when the group's last key is deleted would strand the old
    # key names on every zone, and transfers from an otherwise-permitted
    # network would then fail forever, demanding a signature by a key that
    # no longer exists anywhere. The control plane is the source of truth for
    # this list, the same stance ``_sync_tsig_keys`` takes for the keys.
    #
    # On a Deny zone the list is necessarily empty (the branch above only
    # picks Deny when there are no keys), so this never reads as "signed
    # transfer enabled" on a zone that cannot transfer at all.
    payload["zoneTransferTsigKeyNames"] = names
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
            if mode in ("sinkhole", "redirect") and entry.get("target"):
                custom_addresses.add(str(entry["target"]))

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

    # One server-wide blocking type has to cover every entry. If the lists
    # disagree, prefer the address-answering mode: it is the more specific
    # intent (an operator asked for a sinkhole), and NxDomain would drop
    # the sinkhole silently.
    blocking_type = "CustomAddress" if "CustomAddress" in modes else "NxDomain"

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


def _record_params(rtype: str, value: str, rec: dict[str, Any]) -> dict[str, Any]:
    """Build the type-specific param dict for
    ``/api/zones/records/{add,delete}`` — shared by both endpoints since
    ``delete`` requires the exact same value params to identify the record.
    """
    if rtype == "TXT":
        # Text, not a name: it keeps a trailing full stop (#1694).
        return _txt_params(value)
    value = value.rstrip(".")
    if rtype in ("A", "AAAA"):
        # Canonicalised (#1513) so the desired side matches the daemon's
        # canonical read-back regardless of how the operator typed it.
        return {"ipAddress": _canonical_ip(value)}
    # Name-valued targets are folded to lower case on BOTH sides of the
    # fingerprint (#1513); DNS names are case-insensitive.
    if rtype == "CNAME":
        return {"cname": value.lower()}
    if rtype == "DNAME":
        return {"dname": value.lower()}
    if rtype == "NS":
        return {"nameServer": value.lower()}
    if rtype == "PTR":
        return {"ptrName": value.lower()}
    if rtype == "MX":
        # Absence, not falsiness — preference 0 is the highest priority
        # (Microsoft 365 publishes it), and ``or 10`` silently promoted
        # it to a backup. Issue #1518.
        return {
            "exchange": value.lower(),
            "preference": rec.get("priority") if rec.get("priority") is not None else 10,
        }
    if rtype == "SRV":
        return {
            "target": value.lower(),
            "priority": rec.get("priority") if rec.get("priority") is not None else 0,
            "weight": rec.get("weight") if rec.get("weight") is not None else 0,
            "port": rec.get("port") if rec.get("port") is not None else 0,
        }
    if rtype == "CAA":
        # value shape: "<flags> <tag> <target>", e.g. '0 issue "letsencrypt.org"'
        tokens = shlex.split(value)
        flags = int(tokens[0]) if tokens and tokens[0].isdigit() else 0
        tag = tokens[1] if len(tokens) > 1 else "issue"
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
        tokens = shlex.split(value)
        return {
            "naptrOrder": tokens[0] if len(tokens) > 0 else "0",
            "naptrPreference": tokens[1] if len(tokens) > 1 else "0",
            "naptrFlags": tokens[2] if len(tokens) > 2 else "",
            "naptrServices": tokens[3] if len(tokens) > 3 else "",
            "naptrRegexp": tokens[4] if len(tokens) > 4 else "",
            "naptrReplacement": tokens[5] if len(tokens) > 5 else ".",
        }
    if rtype == "URI":
        tokens = shlex.split(value)
        return {
            "uriPriority": tokens[0] if len(tokens) > 0 else "1",
            "uriWeight": tokens[1] if len(tokens) > 1 else "1",
            # Only a bare-authority trailing slash is stripped (#1513) —
            # Technitium appends one there when it stores the record,
            # but a path's trailing slash is part of the target.
            "uri": (
                _strip_bare_authority_slash(tokens[2]) if len(tokens) > 2 else ""
            ),
        }
    if rtype in ("SVCB", "HTTPS"):
        priority, target, params = _svcb_params(value)
        out: dict[str, Any] = {"svcPriority": priority, "svcTargetName": target}
        if params:
            out["svcParams"] = params
        return out
    # Unrecognised type — pass the raw value through under a best-guess key
    # so the API's own error message tells us what's missing, rather than
    # silently dropping the record.
    return {"value": value}


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

    def _note_apply_failure(self, what: str) -> None:
        if self._apply_failures is not None:
            self._apply_failures.append(what)


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
                            **_record_params(rtype, rec.get("value") or "", rec),
                        }
                    )

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
            if forwarders:
                entry["forwarders"] = forwarders
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
                for k in (bundle.get("tsig_keys") or [])
                if (k.get("name") or "").rstrip(".")
            ],
            "catalog": catalog,
            "bundle_zone_names": bundle_zone_names,
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
            failures = list(self._apply_failures)
        finally:
            self._apply_failures = None
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
            if not name or not secret:
                continue
            if algorithm not in _TSIG_ALGORITHMS:
                log.warning(
                    "technitium_tsig_algorithm_unsupported",
                    key=name,
                    algorithm=algorithm,
                    supported=sorted(_TSIG_ALGORITHMS),
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
        # Absence, not falsiness — a TTL of 0 is legal ("never cache this") and
        # ``or`` silently turned it into an hour. Matches bind9's driver, which
        # has always tested for None here.
        _op_ttl = rec.get("ttl")
        ttl = 3600 if _op_ttl is None else _op_ttl
        params = {
            "domain": name,
            "zone": zone,
            "type": rtype,
            **_record_params(rtype, rec.get("value") or "", rec),
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
                            **_record_params(rtype, member.get("value") or "", member),
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
        msg = (body.get("errorMessage") or "").lower()
        if "already exists" in msg or "no such record" in msg:
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

    def _apply_forwarders(self, token: str, options: dict[str, Any]) -> None:
        """Set the upstream forwarders and the protocol to reach them with.

        ``forwarderProtocol`` is SILENTLY IGNORED unless ``forwarders`` is
        set in the SAME call (verified: setting the protocol alone returns
        ok and leaves it at Udp). So the two always go together, or not at
        all.

        For DoT/DoH/DoQ, Technitium wants a **domain name** — an IP address
        is rejected outright ("Address must be a domain name"), because
        there would be no name to validate the upstream certificate
        against. That is a real mismatch with the neutral model, which
        carries a list of forwarder IPs plus one ``forward_tls_hostname``:
        over an encrypted transport the hostname is the only usable
        address, so it wins and the IPs are dropped with a warning.
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
                if forwarders != [hostname]:
                    log.info(
                        "technitium_forwarder_hostname_substituted",
                        transport=transport,
                        hostname=hostname,
                        dropped=forwarders,
                        reason="encrypted transports need a name to validate against",
                    )
                forwarders = [str(hostname)]
            else:
                log.error(
                    "technitium_forwarder_hostname_missing",
                    transport=transport,
                    hint="forward_tls_hostname is required for tls/https/quic",
                )
                self._note_apply_failure(
                    f"forwarders: no forward_tls_hostname for {transport}"
                )
                return

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
        for zone_payload in payload:
            zone = zone_payload["zone"]
            self._ensure_zone_exists(token, zone_payload)
            self._apply_zone_options(token, zone, zone_payload.get("options") or {})

            # Records belong to us only on a Primary. A Secondary/Stub is
            # filled by the transfer and a Forwarder holds none, so diffing
            # them would delete whatever the daemon just pulled down.
            if zone_payload.get("type", "Primary") not in _RECORD_MANAGED_ZONE_TYPES:
                continue

            existing = self._get_zone_records(token, zone)
            desired = zone_payload.get("records") or []

            def _fingerprint(rec: dict[str, Any]) -> tuple[Any, ...]:
                extra = tuple(
                    sorted(
                        (k, str(v))
                        for k, v in rec.items()
                        if k not in ("domain", "type", "ttl", "zone")
                    )
                )
                # TTL participates: a TTL-only edit is a real desired-state
                # change, and this reconcile is the only path that can
                # converge it (the incremental op path can't see the old
                # value). Compared as int so a JSON "300" from the daemon
                # doesn't read as different from a rendered 300. Values are
                # str()-normalised for the same reason — Technitium returns
                # some rdata fields as numbers/enums where our add-params
                # are strings, and a bare type mismatch would make every
                # such record look "changed" on every single pass.
                ttl = rec.get("ttl")
                return (
                    rec.get("domain"),
                    rec.get("type"),
                    int(ttl) if ttl is not None else None,
                    extra,
                )

            existing_by_fp = {_fingerprint(r): r for r in existing}
            desired_by_fp = {_fingerprint(r): r for r in desired}

            to_delete = [r for fp, r in existing_by_fp.items() if fp not in desired_by_fp]
            to_add = [r for fp, r in desired_by_fp.items() if fp not in existing_by_fp]

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
                        **{
                            k: v
                            for k, v in rec.items()
                            if k not in ("domain", "type", "ttl", "zone")
                        },
                    },
                )
                body = resp.json()
                if body.get("status") == "error":
                    # "no such record" means it was already gone — a no-op,
                    # not a deletion. Counting it (or the failure case) would
                    # report churn that never happened, which is the same
                    # phantom the apex-NS filter above exists to prevent.
                    if "no such record" not in (body.get("errorMessage") or "").lower():
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
                    if "already exists" not in (body.get("errorMessage") or "").lower():
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
            if added or deleted:
                log.info(
                    "technitium_zone_reconciled",
                    zone=zone,
                    added=added,
                    deleted=deleted,
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

        soa_changed = False
        desired_soa = apex.get("soa") or {}
        ttl = apex.get("ttl")
        if soa is not None and (desired_soa or ttl):
            current = soa.get("rData") or {}
            current_fields: dict[str, Any] = {
                key: str(current.get(key) or "").rstrip(".").lower()
                for key in ("primaryNameServer", "responsiblePerson")
            }
            current_fields.update({f: current.get(f) for f in _SOA_TIMERS})
            differs = any(current_fields.get(k) != v for k, v in desired_soa.items())
            if ttl and soa.get("ttl") != ttl:
                differs = True
            if differs:
                params: dict[str, Any] = {
                    "zone": zone,
                    "domain": zone,
                    "type": "SOA",
                    "serial": current.get("serial"),
                    "ttl": ttl or soa.get("ttl"),
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
        desired_ns = apex.get("ns") or []
        if desired_ns:
            for target in desired_ns:
                if target in live_ns:
                    continue
                body = self._call(
                    token,
                    "POST",
                    "zones/records/add",
                    {
                        "zone": zone,
                        "domain": zone,
                        "type": "NS",
                        "ttl": ttl or 3600,
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
        if soa_changed or added or removed:
            log.info(
                "technitium_zone_apex_reconciled",
                zone=zone,
                soa_updated=soa_changed,
                ns_added=added,
                ns_removed=removed,
            )

    def _ensure_zone_exists(self, token: str, entry: dict[str, Any]) -> None:
        """Create the zone if absent, with the params its type requires.

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
        if ztype in ("Secondary", "Stub", "SecondaryCatalog"):
            params["primaryNameServerAddresses"] = ",".join(
                _technitium_master(m) for m in entry.get("masters") or []
            )
        elif ztype == "Forwarder":
            forwarders = entry.get("forwarders") or []
            # Technitium's Forwarder zone takes a single upstream; BIND's
            # takes a list. Use the first and say so, rather than silently
            # dropping the rest.
            params["forwarder"] = forwarders[0]
            if len(forwarders) > 1:
                log.warning(
                    "technitium_forwarder_extra_upstreams_ignored",
                    zone=zone,
                    used=forwarders[0],
                    ignored=forwarders[1:],
                )

        resp = self._call(token, "POST", "zones/create", params)
        body = resp.json()
        if body.get("status") == "error":
            if "already exists" in (body.get("errorMessage") or "").lower():
                # The create params carry the zone's UPSTREAM (a
                # secondary/stub's primaries, a forwarder's target), and
                # create is a no-op once the zone exists. Without this,
                # retargeting a secondary at a new primary would be a
                # permanent silent no-op: the operator edits it, the
                # bundle changes, and the daemon keeps transferring from
                # the old address forever.
                self._reapply_zone_upstream(token, zone, ztype, params)
                return
            log.error(
                "technitium_zone_create_failed",
                zone=zone,
                zone_type=ztype,
                error=body.get("errorMessage"),
            )
            self._note_apply_failure(
                f"{zone}: zone create: {body.get('errorMessage')}"
            )

    def _reapply_zone_upstream(
        self, token: str, zone: str, ztype: str, params: dict[str, Any]
    ) -> None:
        """Push a existing zone's upstream through ``zones/options/set``."""
        opts: dict[str, Any] = {"zone": zone}
        if "primaryNameServerAddresses" in params:
            opts["primaryNameServerAddresses"] = params["primaryNameServerAddresses"]
        elif "forwarder" in params:
            opts["forwarder"] = params["forwarder"]
        else:
            return
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

    def _apply_zone_options(
        self, token: str, zone: str, options: dict[str, Any]
    ) -> None:
        """Push per-zone options, validating enums before we send them.

        ``zones/options/set`` answers ``{"status": "ok"}`` for a value it
        does not recognise and leaves the existing setting untouched
        (verified live with ``zoneTransfer="Bogus"``). So an unvalidated
        typo would not fail — it would quietly leave zone transfer at
        whatever it was, which for a zone we meant to lock down is a
        security regression that no log line would report. Refuse to send
        anything not in the known set.
        """
        if not options:
            return
        transfer = options.get("zoneTransfer")
        if transfer is not None and transfer not in _ZONE_TRANSFER_VALUES:
            log.error(
                "technitium_zone_transfer_value_invalid",
                zone=zone,
                value=transfer,
                supported=sorted(_ZONE_TRANSFER_VALUES),
            )
            self._note_apply_failure(f"{zone}: zone options: bad zoneTransfer {transfer}")
            return

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
            log.error(
                "technitium_create_token_rejected", error=body.get("errorMessage")
            )
            return None
        token = body["token"]
        self._write_secret(self._api_token_path(), token)
        log.info("technitium_api_token_created")
        return token

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
