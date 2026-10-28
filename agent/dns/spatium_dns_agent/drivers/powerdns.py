"""PowerDNS agent driver (issue #127, Phase 1).

Runs alongside ``pdns_server`` inside the dns-powerdns container. Where
the BIND9 driver renders ``named.conf`` + RFC 1035 zone files and reloads
via ``rndc``, this driver:

* Renders ``pdns.conf`` once at first boot using the API key the
  entrypoint generated and shared with us via ``/var/lib/spatium-dns-
  agent/pdns-api.key``. Subsequent renders only rewrite the file if
  the bundle changed materially (loglevel, listen address, etc.).
* Applies zones + records via the local PowerDNS REST API
  (``http://127.0.0.1:8081/api/v1/servers/localhost``). Each
  ``apply_record_op`` call becomes one PATCH to the relevant zone's
  rrsets endpoint; full-bundle config sync diffs zone state and
  reconciles per-zone via the same REST surface.
* Validates by smoke-testing the API on the agent's loopback before
  signalling the daemon to reload (``pdns_control reload``).

Backend storage in Phase 1 is LMDB (``launch=lmdb``), embedded under
``/var/lib/powerdns/pdns.lmdb``. The gpgsql-backed configuration that
shares Postgres with the control plane is deferred to Phase 4 — the
extra cross-process database coupling isn't worth the complexity for
the first ship.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
import structlog

from ..secure_io import harden_mode, write_private
from ._process import (
    find_running_daemon,
    is_zombie,
    spawn_guard,
    wait_for_daemon,
)
from ._caa import caa_presentation
from ._txt import quote_txt as _quote_txt
from .base import RRSET_OP_KINDS, DriverBase

log = structlog.get_logger(__name__)


_PDNS_API_BASE = "http://127.0.0.1:8081/api/v1/servers/localhost"
_PDNS_API_TIMEOUT = 10.0
_API_KEY_FILE = "pdns-api.key"

# ``resolver=`` takes ``ip``, ``ip:port`` or ``[v6]:port``, comma-separated.
_ALIAS_RESOLVER_PORTED_RE = re.compile(
    r"^(?:\[([0-9A-Fa-f:.]+)\]|([0-9.]+)):([0-9]{1,5})$"
)


def _alias_resolver_entry_ok(entry: str) -> bool:
    """One ``resolver=`` element: an address, optionally with a port."""
    ported = _ALIAS_RESOLVER_PORTED_RE.fullmatch(entry)
    host = (ported.group(1) or ported.group(2)) if ported else entry
    if ported and not 1 <= int(ported.group(3)) <= 65535:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    # A bracketed host must be v6 and an unbracketed ``ip:port`` must be v4;
    # a zone index (``%eth0``) is not something ``resolver=`` can parse.
    if ported and (addr.version == 6) != bool(ported.group(1)):
        return False
    return "%" not in entry


def _read_text_or_none(path: Path) -> str | None:
    try:
        return path.read_text()
    except OSError:
        return None


def _safe_alias_resolver(value: Any) -> str:
    """The ALIAS resolver list to write into pdns.conf, or "" for ALIAS off.

    The control plane builds the list from validated forwarders (#1353), but
    it lands in pdns.conf, where a newline would start a new directive and a
    value pdns cannot parse stops it starting, so every element is checked
    again here. Anything that is not an address list turns ALIAS off rather
    than reaching the file.
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    entries = value.strip().split(",")
    if not all(_alias_resolver_entry_ok(e) for e in entries):
        log.warning("powerdns_alias_resolver_refused", value=value[:200])
        return ""
    return ",".join(entries)


def _qualify_target(target: str, zone: str | None) -> str:
    """A record's target name as PowerDNS must be sent it: absolute (#2060).

    PowerDNS's API refuses a name target with no trailing dot outright
    (``422 Not in expected format (parsed as 'db1.example.com.')``,
    verified against 5.0.7), so a dot-less target stored in the control
    plane is qualified here the way a zone file reads it — relative to the
    zone's origin, which is what a BIND9 agent serves for the same row and
    what the control plane's drift / IPAM readings assume for this driver
    (``targets_are_relative`` / ``zone_target_readings``). ``@`` (or an
    empty target) is the apex; ``.`` (null MX, SVCB "the owner") and any
    name already ending in a dot are left alone. With no zone in hand the
    target is returned unchanged.
    """
    if zone is None or target.endswith("."):
        return target
    origin = zone.rstrip(".") + "."
    if target in ("", "@"):
        return origin
    return f"{target}.{origin}"


# The last whitespace-separated token of rdata (MX / SRV target, NAPTR
# replacement), with whatever precedes it kept byte for byte.
_LAST_TOKEN_RE = re.compile(r"^(.*?)(\S+)(\s*)$", re.DOTALL)
# An SVCB / HTTPS ``priority target …`` head.
_SVCB_HEAD_RE = re.compile(r"^(\s*\d+\s+)([^\s\"=]+)(?=\s|$)")


def _qualify_last_token(content: str, zone: str | None) -> str:
    m = _LAST_TOKEN_RE.match(content)
    if m is None or m.group(2).startswith('"'):
        return content
    return f"{m.group(1)}{_qualify_target(m.group(2), zone)}{m.group(3)}"


def _record_content(rec: dict[str, Any], zone: str | None = None) -> str:
    """Stitch wire-format content for a single record dict.

    ``zone`` is the zone the record lives in; a dot-less name target is
    qualified against it (#2060), since PowerDNS refuses the dot-less
    spelling — and a refused rrset refuses the whole PATCH carrying it.
    """
    rtype = rec["type"].upper()
    value = rec.get("value") or ""
    if rtype == "TXT":
        return _quote_txt(value)
    if rtype == "CAA":
        return caa_presentation(value)
    if rtype in ("CNAME", "DNAME", "NS", "PTR", "ALIAS"):
        return _qualify_target(value.strip(), zone)
    if rtype == "MX":
        prio = rec.get("priority")
        if prio is None:
            prio = 10
        # Operators sometimes paste the priority into value already.
        first = value.lstrip().split(" ", 1)[0]
        if first.isdigit():
            return _qualify_last_token(value, zone)
        return f"{prio} {_qualify_target(value.strip(), zone)}"
    if rtype == "SRV":
        prio = rec.get("priority", 0) or 0
        weight = rec.get("weight", 0) or 0
        port = rec.get("port", 0) or 0
        if len(value.split()) >= 4:
            return _qualify_last_token(value, zone)
        return f"{prio} {weight} {port} {_qualify_target(value.strip(), zone)}"
    if rtype in ("SVCB", "HTTPS"):
        m = _SVCB_HEAD_RE.match(value)
        if m is None:
            return value
        return f"{m.group(1)}{_qualify_target(m.group(2), zone)}{value[m.end():]}"
    if rtype == "NAPTR":
        return _qualify_last_token(value, zone)
    return value


def _qualified_name(zone_name: str, name: str) -> str:
    """Compose the FQDN PowerDNS expects for an rrset name."""
    zone = zone_name.rstrip(".") + "."
    if name in ("", "@") or name.rstrip(".") == zone.rstrip("."):
        return zone
    return f"{name.rstrip('.')}.{zone}"


# Rdata that is, or ends in, a domain name. PowerDNS compares those
# case-insensitively, so two records whose targets differ only in case are the
# same record to it (#1379). Content reaching the dedupe is already absolute
# (``_record_content`` qualifies a dot-less target against the zone, #2060), so
# the trailing-dot fold below only matters for content built without a zone.
_NAME_RDATA_TYPES = frozenset({"ALIAS", "CNAME", "DNAME", "MX", "NS", "PTR", "SRV"})


def _content_key(rtype: str, content: str) -> str:
    """What PowerDNS would consider the same record content, for dedupe.

    Deliberately conservative: only addresses and name-shaped rdata are
    normalised. Free text (TXT, CAA values, …) is compared as written, since
    folding case there could merge two records PowerDNS keeps apart and
    silently drop one of them.
    """
    text = " ".join(content.split())
    if rtype in ("A", "AAAA"):
        try:
            return ipaddress.ip_address(text).compressed
        except ValueError:
            return text
    if rtype in _NAME_RDATA_TYPES:
        return text.lower().rstrip(".")
    return text


def _dedupe_contents(rtype: str, contents: list[str]) -> list[str]:
    """``contents`` with repeats dropped, first spelling kept (#1379).

    PowerDNS refuses a whole rrset — and so the whole zone PATCH — that
    carries the same record twice ("Duplicate record in RRset"). The control
    plane can legitimately ship one: a manual A record and the A record IPAM
    generates for the same address are two rows with one value. Both are the
    same answer, so serving it once is exactly what was asked for.
    """
    seen: set[str] = set()
    out: list[str] = []
    for content in contents:
        key = _content_key(rtype, content)
        if key in seen:
            continue
        seen.add(key)
        out.append(content)
    return out


# Never deleted by the reconcile's absent-rrset sweep (#1380). The apex SOA
# and NS are the zone's own skeleton: deleting either leaves not a smaller zone
# but a broken one. PowerDNS creates a default SOA with the zone but no apex
# NS; the agent renders both for a primary zone (``_soa_content`` #1522,
# ``_default_apex_ns`` #1985), so on those the bundle's rrset replaces what is
# held. The kept types still matter for a zone the bundle carries no rrsets for
# (a secondary's transferred apex) and for a name the bundle does not know: an
# NS the operator declared is never swept. The DNSSEC types are PowerDNS's
# to manage, not the bundle's.
_APEX_KEPT_TYPES = frozenset({"SOA", "NS"})
_DNSSEC_RRSET_TYPES = frozenset(
    {"CDNSKEY", "CDS", "DNSKEY", "NSEC", "NSEC3", "NSEC3PARAM", "RRSIG"}
)

# HTTP statuses with which PowerDNS refuses a zone's DATA (a CNAME beside
# other records, a malformed record, a duplicate in an rrset). Anything else —
# a 5xx, an auth failure, a dropped connection — says nothing about the zone
# and fails the whole apply as before.
_ZONE_REFUSAL_STATUSES = frozenset({400, 409, 422})
# The refusals that can be about one rrset among many — a malformed record,
# a CNAME beside other data — and so are worth retrying one rrset at a time
# (#2060). A 409 on a create is the zone itself, not its data.
_RRSET_REFUSAL_STATUSES = frozenset({400, 422})
# The most PATCHes one zone's piecemeal retry may send (#2060). Bisection finds
# a few bad rrsets in a handful; this only bounds the case where everything is
# refused, which says the refusal was about the zone rather than its data.
_PIECEMEAL_PATCH_BUDGET = 256


def _absent_rrsets(
    zone_name: str, desired: list[dict[str, Any]], current: dict[str, Any]
) -> list[dict[str, Any]]:
    """``DELETE`` changes for rrsets PowerDNS holds and the bundle no longer
    does (#1380).

    The reconcile used to REPLACE only the rrsets the bundle carried, so a
    record deleted while its op never reached the agent (a views group,
    where ops are retired by the render, or an op skipped by a failed apply)
    stayed live for good. Names are compared case-insensitively.
    """
    apex = zone_name.rstrip(".").lower() + "."
    wanted = {(str(rs["name"]).lower(), str(rs["type"]).upper()) for rs in desired}
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for rs in current.get("rrsets") or []:
        if not isinstance(rs, dict):
            continue
        name = str(rs.get("name") or "")
        rtype = str(rs.get("type") or "").upper()
        key = (name.lower(), rtype)
        if not name or not rtype or key in wanted or key in seen:
            continue
        if rtype in _DNSSEC_RRSET_TYPES:
            continue
        if key[0] == apex and rtype in _APEX_KEPT_TYPES:
            continue
        seen.add(key)
        out.append({"name": name, "type": rtype, "changetype": "DELETE"})
    return out


def _render_catalog_zone_payload(catalog: dict[str, Any]) -> dict[str, Any]:
    """Build the zones.json payload entry for an RFC 9432 catalog zone.

    PowerDNS accepts the canonical catalog-zone shape verbatim: SOA + NS
    + a ``version`` TXT pinned to ``"2"`` (the only schema PowerDNS
    accepts) + one PTR per member zone. The PTR label is the SHA-1 of
    the wire-format member zone name, exactly as BIND9's catalog-zone
    renderer produces (RFC 9432 §4.1) — keeping the format identical
    means a SpatiumDDI-managed catalog can be served by either driver
    without consumers needing to special-case the producer kind.

    Returns a dict in the same shape as the regular zones_payload
    entries so the existing reconciler creates / patches it through
    the same code path.
    """
    zname = (catalog.get("zone_name") or "").rstrip(".") + "."
    if not zname or zname == ".":
        return {"name": "invalid.", "kind": "Native", "rrsets": []}

    serial = int(time.time())
    rrsets: list[dict[str, Any]] = [
        {
            "name": zname,
            "type": "SOA",
            "ttl": 86400,
            "records": [
                {
                    "content": (f"invalid. invalid. {serial} 86400 3600 86400 86400"),
                    "disabled": False,
                }
            ],
        },
        {
            "name": zname,
            "type": "NS",
            "ttl": 86400,
            "records": [{"content": "invalid.", "disabled": False}],
        },
        {
            "name": f"version.{zname}",
            "type": "TXT",
            "ttl": 86400,
            "records": [{"content": '"2"', "disabled": False}],
        },
    ]

    for member in catalog.get("members") or []:
        member_name = (member.get("zone_name") or "").rstrip(".")
        if not member_name:
            continue
        # RFC 9432 §4.1 — SHA-1 over the wire-format zone name (each
        # label prefixed with its length byte, root null at the end).
        wire = (
            b"".join(
                bytes([len(label)]) + label.encode("ascii")
                for label in member_name.split(".")
                if label
            )
            + b"\x00"
        )
        digest = hashlib.sha1(wire).hexdigest()
        rrsets.append(
            {
                "name": f"{digest}.zones.{zname}",
                "type": "PTR",
                "ttl": 86400,
                "records": [{"content": f"{member_name}.", "disabled": False}],
            }
        )

    return {
        "name": zname,
        "kind": "Native",
        "serial": serial,
        # The catalog's serial is the agent's own (a timestamp, bumped by
        # PowerDNS's SOA-EDIT-API DEFAULT on every change), not the control
        # plane's: it keeps that rule (#1965).
        "serial_managed": False,
        "rrsets": rrsets,
    }


# ── Encrypted transports (issue #50) ────────────────────────────────────────
# The dnsdist front runs in its OWN container and mounts the PowerDNS agent's
# state dir read-only. So paths baked into the rendered rules must be
# dnsdist-side paths, not agent-side ones: the agent writes
# ``<state_dir>/tls/listener.crt``, dnsdist reads
# ``/agent-state/tls/listener.crt``. Both images create ``spatium`` as
# uid 101, so the 0600 key the agent writes is readable by dnsdist.
DNSDIST_STATE_MOUNT = os.environ.get("DNSDIST_STATE_MOUNT", "/agent-state")
TLS_DIR_NAME = "tls"
TLS_CERT_FILENAME = "listener.crt"
TLS_KEY_FILENAME = "listener.key"


def _ipv6_available() -> bool:
    """True when this host/container can open an AF_INET6 socket.

    Distinct from "has an IPv6 address": ``net.ipv6.conf.*.disable_ipv6=1``
    still lets pdns bind ``::`` (verified), but a kernel booted with
    ``ipv6.disable=1`` has no AF_INET6 at all, and pdns then dies with
    ``Unable to acquire TCP socket`` on a ``::`` entry. BIND skips such a
    listener and carries on; this is the same tolerance.
    """
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
    except OSError:
        return False
    return True


def _pdns_local_address() -> str:
    """``local-address`` for pdns.conf: both families where the host has IPv6.

    Setting the option replaces pdns's own default (which includes ``::``),
    so IPv4 only has to be undone explicitly (#2307).
    """
    return "0.0.0.0, ::" if _ipv6_available() else "0.0.0.0"


def _dnsdist_cert_paths() -> tuple[str, str]:
    base = f"{DNSDIST_STATE_MOUNT.rstrip('/')}/{TLS_DIR_NAME}"
    return f"{base}/{TLS_CERT_FILENAME}", f"{base}/{TLS_KEY_FILENAME}"


# Files inside the rendered tree that embed a credential and therefore need
# 0600 + redaction before the snapshot pusher ships them (#869). Keep this in
# step with anything new that render() writes under ``rendered.new``.
_SECRET_RENDERED_FILES: tuple[str, ...] = ("pdns.conf", "zones.json")


def _pdns_error(resp: httpx.Response) -> str:
    """PowerDNS's own error text for a refused call (``{"error": "..."}``),
    or the start of the body when it is not JSON."""
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:150]
    if isinstance(body, dict) and body.get("error"):
        return str(body["error"])[:200]
    return resp.text[:150]


def _harden_legacy_rendered_modes(state_dir: Path) -> None:
    """Fix 0644 secret files left by a pre-#869 agent build.

    Upgrading the agent does not re-mode what is already on disk: the live
    ``rendered/`` tree survives until the next structural render replaces it,
    and then lingers as ``rendered.prev/`` for one more cycle. Without this,
    a still-valid API key and TSIG secrets stay world-readable for two
    renders' worth of uptime after the fix ships — on a stable install, that
    could be indefinitely.
    """
    for tree in ("rendered", "rendered.prev"):
        for name in _SECRET_RENDERED_FILES:
            harden_mode(state_dir / tree / name)


def render_dnsdist_conf(opts: dict[str, Any], has_cert: bool = False) -> str:
    """Render the dnsdist RULES + encrypted listeners from bundle options.

    Two things ride this file, both composed by the dnsdist container's
    entrypoint onto its env-configured base (setLocal + newServer → pdns
    backend). It is fully decoupled from pdns.conf — pdns never moves port.
    Pure + unit-testable.

    * **Rate limiting** (issue #146 Phase 2) — PowerDNS Authoritative has no
      RRL, so MaxQPSIPRule → TC/Drop + optional exceedQRate dynamic block
      live here.
    * **DoT / DoH listeners** (issue #50) — pdns auth speaks neither, so the
      dnsdist front terminates TLS and forwards plaintext to pdns over the
      container network.

    Note there is deliberately no upstream-transport handling: PowerDNS
    Authoritative doesn't recurse or forward, so ``forward_transport`` is a
    BIND9-only concept. The only hop dnsdist makes is to the local pdns
    backend, where encryption buys nothing.

    Returns "" when nothing is configured → the front runs as a plain
    pass-through, which is a safe no-op.
    """
    dot = bool(opts.get("dot_enabled")) and has_cert
    doh = bool(opts.get("doh_enabled")) and has_cert
    if not opts.get("dnsdist_enabled") and not (dot or doh):
        return ""

    lines = ["-- generated by SpatiumDDI — do not edit by hand"]

    if dot or doh:
        cert_path, key_path = _dnsdist_cert_paths()
        lines.append("-- encrypted transports (issue #50)")
        if dot:
            port = int(opts.get("dot_port", 853))
            for bind in (f"0.0.0.0:{port}", f"[::]:{port}"):
                lines.append(f'addTLSLocal("{bind}", "{cert_path}", "{key_path}")')
        if doh:
            port = int(opts.get("doh_port", 443))
            path = (opts.get("doh_path") or "/dns-query").strip()
            for bind in (f"0.0.0.0:{port}", f"[::]:{port}"):
                lines.append(
                    f'addDOHLocal("{bind}", "{cert_path}", "{key_path}", {{"{path}"}})'
                )

    if opts.get("dnsdist_enabled"):
        lines.append("-- rate-limit rules (issue #146 Phase 2)")
        max_qps = opts.get("dnsdist_max_qps_per_client")
        if max_qps is not None:
            action = (
                "DropAction()" if opts.get("dnsdist_action") == "drop" else "TCAction()"
            )
            lines.append("-- per-source-IP QPS cap")
            lines.append(f"addAction(MaxQPSIPRule({int(max_qps)}), {action})")
        dyn = opts.get("dnsdist_dynblock_qps")
        if dyn is not None:
            secs = int(opts.get("dnsdist_dynblock_seconds", 60))
            lines.append("-- dynamic per-source blocking on sustained query rate")
            lines.append("local dbr = dynBlockRulesGroup()")
            lines.append(
                f'dbr:setQueryRate({int(dyn)}, 10, "exceeded query rate", {secs})'
            )
            lines.append("function maintenance() dbr:apply() end")

    return "\n".join(lines) + "\n"


# ── Zone kinds, masters and the apex SOA (#1521, #1522) ─────────────────────

#: SpatiumDDI zone type → PowerDNS zone kind. PowerDNS has no stub kind:
#: a stub's closest served equivalent is a secondary that transfers the
#: whole zone from its primaries, which is what ``Slave`` does. ``forward``
#: is absent on purpose — pdns auth cannot forward, and render() drops
#: those zones loudly rather than serving or reporting them.
_KIND_BY_ZONE_TYPE = {
    "primary": "Native",
    "master": "Native",
    "secondary": "Slave",
    "slave": "Slave",
    "stub": "Slave",
}

#: PowerDNS 5.1 renamed the kinds Master→Primary / Slave→Secondary and
#: both spellings read back depending on version, so kind comparisons go
#: through this normalisation.
_KIND_CATEGORY = {
    "native": "native",
    "master": "primary",
    "primary": "primary",
    "slave": "secondary",
    "secondary": "secondary",
}


def _kind_category(kind: Any) -> str:
    return _KIND_CATEGORY.get(str(kind or "").strip().lower(), "native")


def _pdns_masters(entries: Any) -> list[str]:
    """Bundle ``masters`` entries → PowerDNS ``masters`` strings.

    The bundle wire shape is ``ip`` or ``ip@port`` (the control-plane
    convention the BIND9 renderer also consumes); the PowerDNS API wants
    ``ip`` or ``ip:port`` (``[v6]:port`` when ported). Anything that is
    not an IP address, or carries a non-numeric port, is dropped — a
    master pdns cannot parse would fail the whole zone write.
    """
    out: list[str] = []
    for entry in entries or []:
        text = str(entry).strip()
        if not text:
            continue
        host, port = text, None
        if "@" in text:
            host, _, port_s = text.partition("@")
            host = host.strip()
            if not port_s.strip().isdigit() or not 1 <= int(port_s) <= 65535:
                continue
            port = int(port_s)
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            continue
        if port is None:
            out.append(str(addr))
        elif addr.version == 6:
            out.append(f"[{addr}]:{port}")
        else:
            out.append(f"{addr}:{port}")
    return out


#: The ``notify`` value grammar (control-plane validator, #1316).
_NOTIFY_VALUES = frozenset({"yes", "no", "explicit", "master-only", "primary-only"})


def _axfr_payload(
    acl: Any, bundle_keys: dict[str, dict[str, Any]], zone: str
) -> dict[str, Any]:
    cidrs, keys = _axfr_grants(acl, bundle_keys, zone)
    return {"axfr_from": cidrs, "axfr_tsig_keys": keys}


def _also_notify_targets(entries: Any) -> list[str]:
    """Bundle also-notify entries → PowerDNS ``ALSO-NOTIFY`` values (#1523).

    The stored shape is BIND grammar, ``<ip> [port <n>] [key <name>]``
    (#1316); the PowerDNS metadata wants ``ip`` / ``ip:port`` and has no
    per-target TSIG key, so a key token is dropped. Unusable entries are
    dropped by the same conversion the masters list goes through.
    """
    out: list[str] = []
    for entry in entries or []:
        tokens = str(entry).split()
        if not tokens:
            continue
        port: str | None = None
        if "port" in tokens:
            idx = tokens.index("port")
            if idx + 1 < len(tokens) and tokens[idx + 1].isdigit():
                port = tokens[idx + 1]
        host = tokens[0]
        out.extend(_pdns_masters([f"{host}@{port}" if port else host]))
    return out


def _axfr_grants(
    acl: Any, bundle_keys: dict[str, dict[str, Any]], zone: str
) -> tuple[list[str], list[dict[str, Any]]]:
    """Who may AXFR a zone from this server: ``(ALLOW-AXFR-FROM, keys)``.

    PowerDNS answers an AXFR only to ``allow-axfr-ips`` (default: loopback),
    a zone's ``ALLOW-AXFR-FROM`` subnets, a TSIG key named in the zone's
    ``TSIG-ALLOW-AXFR``, or an address it notified seconds earlier. None of
    the per-zone grants was rendered, so a secondary on another host could be
    NOTIFY-ed (#1967) and then had its transfer REFUSED at its next refresh.

    The source is the one BIND9 renders ``allow-transfer`` from (#734): the
    zone's ``allow_transfer`` when set, else the server options', in BIND's
    vocabulary, plus every TSIG key in the bundle, granted unconditionally —
    the same keys the BIND9 agent grants, so ``resolve_group_transfer_key``
    signs with a key this server accepts. PowerDNS's ``ALLOW-AXFR-FROM`` is a
    list of subnets with no negation and no named ACLs, so:

    * ``any`` → ``0.0.0.0/0`` and ``::/0``; ``none`` grants nothing;
    * an address or prefix is granted as one;
    * ``key <name>`` grants that bundle key;
    * a named ACL cannot be expressed and is dropped, which narrows;
    * a negated entry (``!10.0.0.5``) cannot be expressed either, and dropping
      only it would WIDEN what the rest grants, so the whole address list is
      dropped (keys still apply) — failing closed.
    """
    cidrs: list[str] = []
    keys: dict[str, dict[str, Any]] = {
        str(name): k for name, k in bundle_keys.items() if name and k.get("secret")
    }
    dropped: list[str] = []
    negated = False
    for entry in acl or []:
        token = str(entry).strip().rstrip(";").strip()
        if not token or token.lower() == "none":
            continue
        if token.startswith("!"):
            negated = True
            continue
        if token.lower() == "any":
            cidrs += ["0.0.0.0/0", "::/0"]
            continue
        parts = token.split()
        if len(parts) == 2 and parts[0].lower() == "key":
            name = parts[1].strip('"')
            if name in bundle_keys and bundle_keys[name].get("secret"):
                keys.setdefault(name, bundle_keys[name])
            else:
                dropped.append(token)
            continue
        try:
            cidrs.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            dropped.append(token)
    if negated:
        log.warning(
            "powerdns_allow_transfer_negation_unsupported",
            zone=zone,
            hint=(
                "PowerDNS ALLOW-AXFR-FROM cannot express a negated entry; no "
                "address is granted transfers for this zone (TSIG keys still "
                "are). Use keys or plain prefixes on a PowerDNS group."
            ),
        )
        cidrs = []
    if dropped:
        log.warning(
            "powerdns_allow_transfer_entries_dropped",
            zone=zone,
            entries=dropped[:5],
            hint="named ACLs and unknown keys cannot be granted on PowerDNS",
        )
    return list(dict.fromkeys(cidrs)), list(keys.values())


# Characters a zone-file / SOA name cannot carry unescaped — the same set
# the BIND9 apex renderer guards (backend ``contains_zonefile_unsafe``
# mirrors it on write; rows written before that guard still reach here).
_NAME_UNSAFE_RE = re.compile(r'[\s;$()"@\\]|[\x00-\x1f\x7f]')


def _absolute_name(value: Any) -> str | None:
    """``value`` as an absolute domain name, or None if it cannot be one.

    Same rule as the BIND9 apex renderer: ``primary_ns`` / ``admin_email``
    are stored in SOA form with or without the trailing dot, and both
    spellings are absolute names.
    """
    if not isinstance(value, str):
        return None
    name = value.strip()
    if (
        not name
        or name == "."
        or not name.isascii()
        or name.startswith(".")
        or ".." in name
        or _NAME_UNSAFE_RE.search(name)
    ):
        return None
    return name if name.endswith(".") else name + "."


def _name_in_zone(value: Any, zone: str) -> str:
    """How a stored name reads on the wire: absolute when it ends in a
    dot, the apex for ``@`` / empty, otherwise relative to the apex."""
    v = str(value or "").strip()
    if v in ("", "@"):
        return zone
    return v if v.endswith(".") else f"{v}.{zone}"


#: SOA timers served when a zone carries none (or an unusable one) —
#: the same fallbacks the BIND9 renderer uses (#1171). The bundle ships
#: ``refresh`` / ``retry`` / ``expire`` / ``minimum`` on every zone: the
#: zone's own once its group serves them, else this same literal
#: (``backend/app/services/dns/soa_timers.py``), so a group mixing
#: PowerDNS and BIND9 agents serves one SOA per serial either way.
_SOA_TIMER_FALLBACKS = (
    ("refresh", 3600),
    ("retry", 600),
    ("expire", 86400),
    ("minimum", 300),
)


def _soa_content(zone: dict[str, Any], zname: str) -> str:
    """The apex SOA rdata for a PowerDNS-served primary zone (#1522).

    MNAME from the zone's Primary NS, else its first declared apex NS,
    else the ``ns1.<zone>`` placeholder the BIND9 renderer also serves;
    RNAME from Admin Email, else ``admin.<zone>``. The serial is the
    bundle's — the one the control plane stamped — and the timers are
    the zone's own when the bundle carries usable ones.
    """
    declared_ns: list[str] = []
    for rec in zone.get("records") or []:
        if str(rec.get("type") or "").upper() != "NS":
            continue
        if _name_in_zone(rec.get("name") or "@", zname).lower() != zname.lower():
            continue
        target = _name_in_zone(rec.get("value") or "", zname)
        if target != zname:
            declared_ns.append(target)

    mname = (
        _absolute_name(zone.get("primary_ns"))
        or (declared_ns[0] if declared_ns else None)
        or f"ns1.{zname}"
    )
    rname = _absolute_name(zone.get("admin_email")) or f"admin.{zname}"
    try:
        serial = int(zone.get("serial") or 1)
    except (TypeError, ValueError):
        serial = 1
    timers: list[int] = []
    for field, fallback in _SOA_TIMER_FALLBACKS:
        value = zone.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            timers.append(fallback)
        else:
            timers.append(value)
    return f"{mname} {rname} {serial} {timers[0]} {timers[1]} {timers[2]} {timers[3]}"


def _default_apex_ns(zone: dict[str, Any], zname: str, addressed: set[str]) -> str:
    """The apex NS a PowerDNS-served primary zone gets when the operator
    declared none (#1985), by the BIND9 renderer's rule (``_zone_apex``): the
    zone's Primary NS when it can resolve (outside the zone, or inside it with
    an A/AAAA record; ``addressed`` holds the absolute, lowercased owners that
    have one), else the ``ns1.<zone>`` placeholder.

    Unlike BIND9's file the placeholder gets no loopback glue. BIND9 needs it
    only to LOAD a primary zone (``integrity_checks`` is primary-only); a BIND9
    secondary transferring the zone counts an unaddressed in-zone NS as a
    warning and accepts it (``zone_get_from_db`` in lib/dns/zone.c, 9.20: the
    ``errors != 0`` refusal is gated on ``dns_zone_primary``; only
    ``nscount == 0`` refuses a transfer). Glue to 127.0.0.1 would send every
    resolver that follows the zone's NS set to its own loopback.
    """
    origin = zname if zname.endswith(".") else zname + "."
    primary = _absolute_name(zone.get("primary_ns"))
    if primary is not None:
        low = primary.lower()
        inside = low == origin.lower() or low.endswith("." + origin.lower())
        if not inside or low in addressed:
            return primary
    return f"ns1.{origin}"


# ── SOA serial ownership (#1965, #1968) ─────────────────────────────────────
#
# The control plane owns a primary zone's serial. PowerDNS must serve exactly
# the serial the agent sends, so a zone is created with ``soa_edit_api`` empty:
# left at the API's default (``DEFAULT``) PowerDNS REWRITES the serial of every
# change made through the API (below ``YYYYMMDD01`` it becomes ``YYYYMMDD01``,
# else serial + 1), so the zone never served the control plane's number and an
# SOA-only edit could keep the serial a secondary already held.
#
# A serial is never sent LOWER than the one PowerDNS already serves (RFC 1982):
# before this fix a zone served PowerDNS's own, higher number, so the first
# reconcile after the upgrade (and any later one) would publish a smaller serial
# and every secondary that holds the larger one would keep its stale copy.


def _serial_later(new: int, old: int) -> bool:
    """RFC 1982: ``new`` is later than ``old``."""
    return 0 < (new - old) % 2**32 < 2**31


def _soa_parts(content: str) -> list[str] | None:
    parts = str(content).split()
    if len(parts) != 7:
        return None
    try:
        int(parts[2])
    except ValueError:
        return None
    return parts


def _soa_serial(content: str) -> int | None:
    parts = _soa_parts(content)
    return int(parts[2]) if parts else None


def _soa_with_serial(content: str, serial: int) -> str:
    parts = _soa_parts(content)
    if parts is None:
        return content
    parts[2] = str(serial % 2**32)
    return " ".join(parts)


def _soa_same_ignoring_serial(a: str, b: str) -> bool:
    pa, pb = _soa_parts(a), _soa_parts(b)
    if pa is None or pb is None:
        return False
    def norm(p: list[str]) -> list[str]:
        return [x.lower().rstrip(".") for i, x in enumerate(p) if i != 2]

    return norm(pa) == norm(pb)


def _floor_soa_content(desired: str, served: str | None) -> str:
    """The SOA content to REPLACE with: ``desired`` (the control plane's
    serial), except that it never goes backwards from ``served``.

    * ``desired`` is later than ``served``: sent as it is.
    * Otherwise, with the same Primary NS / Admin Email / timers: the served
      content (nothing to publish, and no serial creep per reconcile).
    * Otherwise (the fields differ, e.g. PowerDNS's default SOA on the
      upgrade): the served serial + 1, so a secondary sees a change.
    """
    want, have = _soa_serial(desired), _soa_serial(served or "")
    if want is None or have is None or served is None:
        return desired
    if _serial_later(want, have):
        return desired
    if _soa_same_ignoring_serial(desired, served):
        return served
    return _soa_with_serial(desired, have + 1)


def _soa_from_zone_doc(doc: Any, zone: str) -> tuple[str, int] | None:
    """The apex SOA ``(content, ttl)`` out of a ``GET /zones/{z}`` document."""
    if not isinstance(doc, dict):
        return None
    for rs in doc.get("rrsets") or []:
        if (
            isinstance(rs, dict)
            and rs.get("type") == "SOA"
            and str(rs.get("name") or "").lower().rstrip(".") == zone.lower().rstrip(".")
        ):
            for rec in rs.get("records") or []:
                content = rec.get("content") if isinstance(rec, dict) else None
                if isinstance(content, str) and not rec.get("disabled"):
                    ttl = rs.get("ttl")
                    return content, int(ttl) if isinstance(ttl, int) else 3600
    return None


class PowerDNSDriver(DriverBase):
    """PowerDNS agent driver — Phase 1."""

    #: Set for the length of ``_restart_daemon``; read by the supervisor's
    #: liveness check on another thread (see ``daemon_restarting``).
    _restarting: bool = False
    #: A changed ``pdns.conf`` that the running daemon has not loaded yet.
    #: Cleared only by a restart that succeeded: once the render is swapped
    #: in, a retry compares the new file with itself and would otherwise
    #: never restart, leaving pdns on the old settings for good.
    _conf_restart_owed: bool = False

    # ── Render / validate / swap ────────────────────────────────────────────

    def render(self, bundle: dict[str, Any]) -> None:
        """Write ``pdns.conf`` + the desired-state JSON the agent uses
        to drive the API on the next sync.

        ``pdns.conf`` is largely static after first boot — listen
        addresses, the API key, and the LMDB filename don't change at
        runtime. We still rewrite it on every render so operators
        editing options through the UI (loglevel, query logging, the
        ALIAS resolver) see the change: ``swap_and_reload`` restarts
        pdns when the rendered file differs, since pdns reads it only
        at startup.
        """
        # Re-mode anything a pre-#869 build left world-readable before we
        # render over it — the old trees outlive the upgrade (see the helper).
        _harden_legacy_rendered_modes(self.state_dir)

        new_dir = self.state_dir / "rendered.new"
        if new_dir.exists():
            shutil.rmtree(new_dir)
        new_dir.mkdir(parents=True)

        api_key = self._load_or_generate_api_key()
        opts = bundle.get("options", {}) or {}
        # ``query_log_enabled`` toggles ``log-dns-queries=yes`` in the
        # rendered pdns.conf so the daemon emits one stderr line per
        # incoming query. The agent's ``QueryLogShipper`` thread tails
        # the captured stderr file and ships parsed lines to the
        # control plane (matching the BIND9 flow under the same
        # ``DNSServerOptions.query_log_enabled`` gate).
        query_log_enabled = bool(opts.get("query_log_enabled", False))
        # PowerDNS gates ``log-dns-queries`` output at ``loglevel=6``
        # (Info) — at the default 4 (Warning) the lines are filtered
        # out before they reach stderr. Bump to 6 only when query
        # logging is enabled so quiet operators don't get noisy logs
        # for free; otherwise stick with the configured level (or 4
        # default) so startup banners + errors still show through.
        log_level = int(opts.get("log_level", 4))
        if query_log_enabled and log_level < 6:
            log_level = 6

        # The ALIAS resolver is the group's own plain-DNS forwarders,
        # computed by the control plane (#1353); "" turns ALIAS expansion
        # off. There is no built-in fallback: the old ``1.1.1.1,8.8.8.8``
        # default sent every ALIAS target to Cloudflare and Google, an
        # outbound connection nobody configured. The value is written into
        # pdns.conf, so anything but an address list is refused here too.
        alias_resolver = _safe_alias_resolver(opts.get("alias_resolver"))
        conf_path = new_dir / "pdns.conf"
        # 0600, not write_text: this file embeds ``api-key=`` in cleartext,
        # and that key grants zone CRUD + DNSSEC over the pdns REST API
        # (#869). ``pdns_server`` and the dnsdist front both run as uid 101,
        # the same owner, so the owner bit is all either of them needs —
        # what 0600 removes is group/other, i.e. any OTHER uid that can see
        # this path (a differently-run sidecar, a host bind-mount, a future
        # image that stops running everything as 101).
        # ``atomic=False``: this lands in a freshly-created ``rendered.new``
        # that no reader can see; the directory rename in swap_and_reload is
        # the atomic step.
        write_private(
            conf_path,
            self._render_conf(
                api_key=api_key,
                log_level=log_level,
                query_log_enabled=query_log_enabled,
                alias_resolver=str(alias_resolver),
            ),
            atomic=False,
        )

        # dnsdist rate-limit RULES (issue #146 Phase 2). Written to a STABLE
        # path under state_dir that the (separate) dnsdist front container
        # mounts read-only + watches; its entrypoint composes these rules onto
        # an env-configured base (setLocal + newServer→pdns:53). This is
        # rules-ONLY and fully decoupled from pdns.conf: pdns never moves port,
        # so writing/removing this file can't affect pdns serving. Removed when
        # dnsdist is disabled → the front becomes a plain pass-through.
        #
        # Since #50 the same file also carries the DoT/DoH listeners, whose
        # cert material is written below — write the cert FIRST so the
        # dnsdist front can never see a rules file pointing at a PEM that
        # isn't on disk yet (it polls the rules mtime and restarts on
        # change; a missing cert fails --check-config and it would keep the
        # old instance until the next poll).
        tls_cert = bundle.get("tls_cert") or None
        has_cert = bool(
            isinstance(tls_cert, dict)
            and tls_cert.get("cert_pem")
            and tls_cert.get("key_pem")
        )
        if (opts.get("dot_enabled") or opts.get("doh_enabled")) and not has_cert:
            log.warning(
                "powerdns_encrypted_listener_skipped_no_cert",
                dot_enabled=bool(opts.get("dot_enabled")),
                doh_enabled=bool(opts.get("doh_enabled")),
            )
        self._write_listener_cert(tls_cert if has_cert else None)

        rules_path = self.state_dir / "dnsdist-rules.conf"
        rules = render_dnsdist_conf(opts, has_cert=has_cert)
        if rules:
            rules_path.write_text(rules)
        elif rules_path.exists():
            rules_path.unlink()

        # Stash the desired-state JSON for the API reconciler. The
        # supervisor calls ``apply_config`` (default impl) which calls
        # render → validate → swap_and_reload; the actual REST PATCH
        # work happens in ``swap_and_reload`` so the daemon is up
        # before we try to reach its API.
        # TSIG keys shipped in the bundle, indexed by name — the reconciler
        # imports the ones a zone's dynamic-update ACL references into pdns
        # (issue #641). Secrets stay agent-private (same as the api-key in
        # pdns.conf); they never leave the appliance.
        bundle_keys = {
            k.get("name"): k for k in (bundle.get("tsig_keys") or []) if k.get("name")
        }
        zones_payload = []
        for zone in bundle.get("zones", []) or []:
            zname = (zone.get("name") or "").rstrip(".") + "."
            if not zname or zname == ".":
                continue
            ztype = str(zone.get("type", "primary") or "primary").lower()
            if ztype == "forward":
                # PowerDNS Authoritative cannot serve a forward zone —
                # forwarding is a recursor concept. Drop it LOUDLY
                # (#1521): before, the zone vanished silently here while
                # its serial was still reported to the control plane as
                # if it were live. The zone-state reporter now reads the
                # served serials back from pdns, so a forward zone is no
                # longer reported either.
                log.warning(
                    "powerdns_forward_zone_not_served",
                    zone=zname,
                    hint=(
                        "PowerDNS authoritative does not serve forward "
                        "zones; use a BIND9 group for this zone."
                    ),
                )
                continue
            kind = _KIND_BY_ZONE_TYPE.get(ztype, "Native")
            masters = _pdns_masters(zone.get("masters")) if kind == "Slave" else []
            if kind == "Slave" and not masters:
                # A secondary with no usable primaries can never
                # transfer; pdns would serve an empty copy
                # authoritatively. Skip it loudly, as the BIND9
                # renderer skips a masters-less secondary stanza.
                log.warning(
                    "powerdns_secondary_zone_no_masters_skipped",
                    zone=zname,
                    zone_type=ztype,
                )
                continue
            # NOTIFY behaviour (#1523): the zone's own override wins,
            # else the server options'. A primary that may notify must
            # be kind Master — Native never sends NOTIFY at all, which
            # is why also-notify targets configured in SpatiumDDI were
            # never notified. The targets ride the payload and the
            # reconciler applies them as ALSO-NOTIFY metadata.
            zone_notify = str(zone.get("notify_enabled") or "").strip().lower()
            server_notify = str(opts.get("notify_enabled") or "yes").strip().lower()
            eff_notify = (
                zone_notify
                if zone_notify in _NOTIFY_VALUES
                else (
                    server_notify
                    if server_notify in _NOTIFY_VALUES
                    else "yes"
                )
            )
            eff_also = zone.get("also_notify")
            if eff_also is None:
                eff_also = opts.get("also_notify") or []
            if kind == "Native" and eff_notify != "no":
                kind = "Master"
            if zone.get("allow_query"):
                # pdns auth has no per-zone query ACL (no metadata kind
                # expresses it) — say so loudly instead of letting the
                # saved setting look applied (#1523).
                log.warning(
                    "powerdns_zone_allow_query_unsupported",
                    zone=zname,
                    hint=(
                        "PowerDNS authoritative cannot enforce a per-zone "
                        "allow-query; the restriction is not applied on "
                        "this group. Use a BIND9 group if it is required."
                    ),
                )
            # Dynamic-update ACL (issue #641). PowerDNS is coarse-only:
            # ALLOW-DNSUPDATE-FROM (IP grants) + TSIG-ALLOW-DNSUPDATE (key
            # grants); name-scope / per-type / deny are rejected at the
            # control plane. Referenced keys ride along so the reconciler can
            # import them into pdns before setting the metadata.
            acl = (
                (zone.get("update_acl") or [])
                if zone.get("dynamic_update_enabled")
                else []
            )
            referenced_keys = [
                bundle_keys[e["tsig_key_name"]]
                for e in acl
                if e.get("match_kind") == "tsig_key"
                and e.get("tsig_key_name") in bundle_keys
            ]
            # Keyed case-insensitively, as PowerDNS compares names: ``Host``
            # and ``host`` are one rrset to it, and two rrsets for one name
            # and type in a single PATCH are refused. The first spelling seen
            # is the one sent.
            rrsets: dict[tuple[str, str], list[str]] = {}
            rrset_names: dict[tuple[str, str], str] = {}
            # Each rrset's TTL from its own records (#1225). This path used to
            # stamp the ZONE TTL on every rrset, so each structural reconcile
            # (agent start, any structural change) REPLACEd every rrset at the
            # zone default and PowerDNS served TTLs nobody configured, while
            # the record-op path honoured them — the two disagreed.
            zone_ttl = zone.get("ttl")
            default_ttl = 3600 if zone_ttl is None else int(zone_ttl)
            rrset_ttls: dict[tuple[str, str], list[int]] = {}
            # A secondary's records come from the transfer, not the bundle
            # (#1521): shipping the bundle's copy would have pdns serve it
            # authoritatively if the transfer never lands.
            records = (zone.get("records") or []) if kind != "Slave" else []
            for rec in records:
                qname = _qualified_name(zname, rec.get("name") or "@")
                rtype = rec["type"].upper()
                if rtype == "SOA" and qname.lower() == zname.lower():
                    # The apex SOA is synthesised from the zone below.
                    continue
                key = (qname.lower(), rtype)
                rrset_names.setdefault(key, qname)
                rrsets.setdefault(key, []).append(_record_content(rec, zname))
                # Absence, not falsiness: a TTL of 0 is legal ("do not cache").
                # A duplicate's TTL still counts towards the rrset's lowest,
                # so dropping the repeat below never raises the served TTL.
                rec_ttl = rec.get("ttl")
                rrset_ttls.setdefault(key, []).append(
                    default_ttl if rec_ttl is None else int(rec_ttl)
                )
            default_ns: str | None = None
            if kind != "Slave":
                # The apex SOA is synthesised from the zone itself (#1522):
                # Primary NS / Admin Email / timers / serial. Zones used to
                # be created with only the bundle's records, so pdns filled
                # in its default SOA and the zone's own SOA fields never
                # reached the wire. The reconcile REPLACEs this rrset like
                # every other, so a later edit re-renders it too. Served at
                # the zone TTL, as the BIND9 renderer's ``$TTL`` does.
                soa_key = (zname.lower(), "SOA")
                rrset_names[soa_key] = zname
                rrsets[soa_key] = [_soa_content(zone, zname)]
                rrset_ttls[soa_key] = [default_ttl]
                # The apex NS (#1985). The zone's own apex NS records, when
                # it has any, are the whole set; otherwise the default. Both
                # are decided from the rrsets this render serves, so "the
                # operator declared an apex NS" and "this name has an address"
                # mean what PowerDNS will serve, however a record's name was
                # spelled. Rendered on every reconcile, so a zone created
                # before this fix gets it too. The default also rides the
                # payload: a record op deleting the zone's last apex NS puts it
                # back in the same PATCH (``apply_record_op``).
                default_ns = _default_apex_ns(
                    zone,
                    zname,
                    {owner for owner, rtype in rrsets if rtype in ("A", "AAAA")},
                )
                ns_key = (zname.lower(), "NS")
                if ns_key not in rrsets:
                    rrset_names[ns_key] = zname
                    rrsets[ns_key] = [default_ns]
                    rrset_ttls[ns_key] = [default_ttl]
            deduped: dict[tuple[str, str], list[str]] = {}
            duplicates: list[str] = []
            for key, contents in rrsets.items():
                deduped[key] = _dedupe_contents(key[1], contents)
                if len(deduped[key]) != len(contents):
                    duplicates.append(f"{rrset_names[key]} {key[1]}")
            if duplicates:
                # Info, not warning: a manual record beside the identical one
                # IPAM generates is ordinary seed data, and this fires on
                # every render.
                log.info(
                    "powerdns_rrset_duplicates_dropped",
                    zone=zname,
                    count=len(duplicates),
                    sample=sorted(duplicates)[:5],
                    detail="identical records at one name and type are served once; "
                    "PowerDNS refuses an rrset that repeats a record",
                )
            mixed = sorted(k for k, ttls in rrset_ttls.items() if len(set(ttls)) > 1)
            if mixed:
                # RFC 2181: an rrset has ONE TTL. The lowest wins, the rule the
                # control plane applies to the rrset it ships with a record op
                # (``_rrset_payload`` in backend/app/services/dns/rrset.py), so
                # a full reconcile and an incremental write agree rather than
                # flapping the served TTL between them.
                # Info, not warning: a round-robin set whose members were given
                # different TTLs is a legitimate configuration, and this fires on
                # every render, so a warning would be permanent noise.
                log.info(
                    "powerdns_rrset_ttl_mixed",
                    zone=zname,
                    count=len(mixed),
                    sample=[f"{n} {t}" for n, t in mixed[:5]],
                    detail="records at one name and type have different TTLs; "
                    "the lowest is served for the whole rrset",
                )
            zones_payload.append(
                {
                    "name": zname,
                    "kind": kind,
                    # Primaries the zone transfers from (secondary/stub
                    # only; #1521). The reconciler PUTs kind/masters on
                    # an existing zone whose type or primaries changed.
                    "masters": masters,
                    # Effective NOTIFY behaviour (#1523) — the zone's
                    # override already folded over the server options;
                    # applied as ALSO-NOTIFY metadata by the reconciler.
                    "notify_enabled": eff_notify,
                    "also_notify": [str(e) for e in eff_also or []],
                    "serial": zone.get("serial") or 1,
                    # The apex NS a record op restores when it deletes the
                    # zone's last one (#1985); None on a secondary.
                    "default_apex_ns": default_ns,
                    "default_apex_ns_ttl": default_ttl,
                    "rrsets": [
                        {
                            "name": rrset_names[key],
                            "type": key[1],
                            "ttl": min(rrset_ttls[key]),
                            "records": [
                                {"content": content, "disabled": False} for content in contents
                            ],
                        }
                        for key, contents in sorted(deduped.items())
                    ],
                    # Dynamic-update ACL (issue #641) — applied as zone
                    # metadata by the reconciler. Empty list = disabled.
                    "update_acl": acl,
                    "update_tsig_keys": referenced_keys,
                    # Zone transfers out (#1967): ALLOW-AXFR-FROM +
                    # TSIG-ALLOW-AXFR, from the same source BIND9's
                    # ``allow-transfer`` is rendered from (#734).
                    **_axfr_payload(
                        zone.get("allow_transfer")
                        if zone.get("allow_transfer") is not None
                        else opts.get("allow_transfer"),
                        bundle_keys,
                        zname,
                    ),
                }
            )

        # Catalog zones (RFC 9432, Phase 3d). Producer mode renders the
        # catalog itself as a regular zone with the canonical record
        # structure; PowerDNS authoritative serves it like any other
        # zone, and operators can stand up secondaries via AXFR
        # (PowerDNS-native catalog-consumer mode needs additional config
        # we'll add in a follow-up — see the warning branch below).
        catalog = bundle.get("catalog") or None
        if catalog and catalog.get("mode") == "producer":
            catalog_payload = _render_catalog_zone_payload(catalog)
            # Consumers transfer the catalog like any zone, under the
            # server's transfer policy.
            catalog_payload.update(
                _axfr_payload(
                    opts.get("allow_transfer"), bundle_keys, catalog_payload["name"]
                )
            )
            zones_payload.append(catalog_payload)
        elif catalog and catalog.get("mode") == "consumer":
            log.warning(
                "powerdns_catalog_consumer_unsupported",
                zone=catalog.get("zone_name"),
                hint=(
                    "This agent does not wire up PowerDNS catalog-consumer "
                    "mode. Use AXFR-based secondaries against the producer "
                    "instead."
                ),
            )

        # Server-wide allow-query (#1523): pdns auth serves any client
        # and has no equivalent of BIND's options allow-query — warn
        # loudly when an operator configured a restriction here, rather
        # than letting it look applied.
        server_allow_query = [str(a).strip() for a in (opts.get("allow_query") or ["any"])]
        if server_allow_query != ["any"]:
            log.warning(
                "powerdns_allow_query_unsupported",
                allow_query=server_allow_query,
                hint=(
                    "PowerDNS authoritative cannot restrict which clients "
                    "may query it; the server allow-query is not applied "
                    "on this group."
                ),
            )

        # Group blackhole (#2263): BIND9-only. The API refuses to set it on a
        # group with a PowerDNS server; a value stored before that (or a
        # server joining a group that holds one) is said out loud here.
        blackhole = [str(a).strip() for a in (opts.get("blackhole") or []) if str(a).strip()]
        if blackhole:
            log.warning(
                "powerdns_blackhole_unsupported",
                blackhole=blackhole,
                hint=(
                    "PowerDNS authoritative cannot drop queries by client "
                    "address; the group blackhole is not applied on this group."
                ),
            )

        # Issue #247 — blocklists. The BIND9 driver renders these as
        # RPZ zones + a `response-policy` directive in named.conf;
        # PowerDNS auth doesn't have an equivalent inline RPZ surface
        # (recursor has Lua hooks but the appliance ships pdns auth
        # only). For now, log a clear warning so operators on
        # PowerDNS see why their blocklist UI doesn't actually
        # block — pre-#247 the entries were silently dropped from
        # render() and pdns answered normally.
        blocklists = bundle.get("blocklists") or []
        if blocklists:
            log.warning(
                "powerdns_blocklists_unsupported",
                blocklist_count=len(blocklists),
                hint=(
                    "PowerDNS authoritative server does not support "
                    "RPZ-style blocklists; the appliance ships pdns "
                    "auth only (no recursor + Lua hooks). Use the "
                    "BIND9 driver if blocklist enforcement matters, "
                    "or move blocking upstream to a recursor / "
                    "dnsdist tier. See issue #247 for the roadmap."
                ),
            )

        # 0600 for the same reason as pdns.conf (#869), and this one is not
        # obvious: ``update_tsig_keys`` carries whole key dicts including
        # ``secret`` (see ``_ensure_tsigkey``), so zones.json holds the TSIG
        # material that authorises dynamic updates. CodeQL flagged only
        # pdns.conf; this file was the same defect one write call away.
        write_private(
            new_dir / "zones.json",
            json.dumps(zones_payload, indent=2),
            atomic=False,
        )

    def _write_listener_cert(self, tls_cert: dict[str, Any] | None) -> None:
        """Write (or remove) the DoT/DoH listener cert for the dnsdist front.

        Lives at a STABLE path outside the ``rendered.new`` swap — the
        dnsdist container mounts the state dir and polls the rules file, so
        the PEM has to be readable at a fixed location the whole time.

        Written 0600 via O_NOFOLLOW like the BIND9 driver's TSIG key: the
        private key must never exist world-readable, not even between
        create and chmod. Both images run ``spatium`` as uid 101, so 0600
        is still readable by the dnsdist process.

        Removing the pair when the listeners are off matters — a stale key
        on disk is exactly the kind of thing that outlives the feature that
        put it there.
        """
        tls_dir = self.state_dir / TLS_DIR_NAME
        if tls_cert is None:
            for filename in (TLS_CERT_FILENAME, TLS_KEY_FILENAME):
                stale = tls_dir / filename
                if stale.exists():
                    stale.unlink()
            return

        tls_dir.mkdir(parents=True, exist_ok=True)
        for filename, material in (
            (TLS_CERT_FILENAME, str(tls_cert.get("cert_pem") or "")),
            (TLS_KEY_FILENAME, str(tls_cert.get("key_pem") or "")),
        ):
            write_private(tls_dir / filename, material)

    def validate(self) -> None:
        """``pdns_server --config-check`` if the binary supports it.

        Recent PowerDNS versions carry a ``--no-config`` smoke. Falling
        back to "config file exists and parses as text" is acceptable
        — invalid LMDB-backend config is caught when the daemon
        actually starts (the supervisor exits non-zero and the
        orchestrator restarts us).
        """
        new_dir = self.state_dir / "rendered.new"
        conf = new_dir / "pdns.conf"
        if not conf.exists():
            raise RuntimeError("pdns.conf was not written")
        if shutil.which("pdns_server"):
            # pdns_server uses ``--option=value`` syntax (the binary
            # rejects space-separated form with "perhaps a
            # '--setting=123' statement missed the '='?"). ``--config=
            # check`` parses the config + exits; non-zero means a
            # parse error in our file. We pass ``--config-name=`` (no
            # name) so it reads ``pdns.conf`` directly out of the
            # config-dir rather than expecting a ``pdns-<name>.conf``
            # variant.
            res = subprocess.run(
                [
                    "pdns_server",
                    f"--config-dir={new_dir}",
                    "--config-name=",
                    "--config=check",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode != 0:
                stderr = (res.stderr or res.stdout).strip()
                raise RuntimeError(f"pdns_server config-check failed: {stderr}")

    def swap_and_reload(self) -> None:
        """Promote the new render into place and reconcile via REST.

        Cold-boot ordering: at first boot the supervisor calls
        ``start_daemon`` BEFORE ``apply_config`` runs, so pdns.conf
        doesn't exist yet and the daemon-start no-ops with
        ``pdns_conf_missing_startup_deferred``. Once we render the
        config here, kick the daemon explicitly + wait briefly for
        the REST API to come up before reconciling — otherwise the
        first PATCH dies on Connection refused, the reconcile silently
        gives up, and the structural_etag advances so the sync loop
        never retries.
        """
        new_dir = self.state_dir / "rendered.new"
        current = self.state_dir / "rendered"
        backup = self.state_dir / "rendered.prev"
        old_conf = _read_text_or_none(current / "pdns.conf")
        if current.exists():
            if backup.exists():
                shutil.rmtree(backup)
            current.rename(backup)
        new_dir.rename(current)

        # Cold-boot fix: kick start_daemon now that pdns.conf exists.
        # ``daemon_running`` is the simplest "is pdns alive?" probe.
        # On warm reload the daemon is already up; start_daemon's
        # already-running check (added in #704) makes this a no-op.
        # Before that check existed this comment was simply wrong —
        # start_daemon only verified the config file and the binary,
        # and would happily spawn a second daemon.
        if old_conf is not None and old_conf != _read_text_or_none(current / "pdns.conf"):
            self._conf_restart_owed = True
        if not self.daemon_running():
            log.info("powerdns_daemon_starting_after_first_render")
            self.start_daemon()
            self._wait_for_api_up()
            # A fresh daemon reads the current render, so nothing is owed.
            self._conf_restart_owed = False
        elif self._conf_restart_owed:
            # pdns reads pdns.conf only when it starts, so a changed one
            # (the ALIAS resolver from the group's forwarders, #1353; the log
            # level; query logging) is otherwise ignored until the container
            # restarts. Zones live in LMDB and survive; the reconcile below
            # runs against the new daemon. Costs a sub-second gap in answers,
            # and only when an operator changes a server option. A restart
            # that raises leaves the debt in place, so the sync loop's retry
            # of this apply restarts again rather than comparing the swapped-in
            # file with itself.
            log.info("powerdns_conf_changed_restarting", pid=self.daemon_pid)
            self._restart_daemon()
            self._conf_restart_owed = False

        api_key = self._load_or_generate_api_key()
        # ``render()`` always writes zones.json, so a missing or unreadable one
        # means the zones were NOT reconciled. That is a failed apply, not a
        # warning: returning here used to report the apply OK (#1225).
        zones_path = current / "zones.json"
        try:
            payload = json.loads(zones_path.read_text())
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"cannot read the rendered zones payload: {exc}") from exc

        # Let HTTPError propagate — the sync loop catches the
        # exception, logs ``sync_apply_failed``, and crucially does
        # NOT advance ``_current_structural_etag``, so the next
        # bundle (or the next 304 retry) re-runs the apply. Silent
        # failure here used to lose every record on cold-boot when
        # the timing race fired. A zone whose data PowerDNS refuses does NOT
        # raise: it lands in ``refused_zones()`` for the sync loop to report.
        self._reconcile_zones(api_key, payload)

    def daemon_restarting(self) -> bool:
        return self._restarting

    def _restart_daemon(self, *, stop_timeout_s: float = 15.0) -> None:
        """Stop ``pdns_server`` and start it from the current render.

        Runs on the sync thread while the supervisor checks liveness every
        second on its own, so ``_restarting`` covers the whole stop/start:
        without it a tick between the SIGTERM and the new spawn read the old
        pid as a dead daemon and the agent exited 2 (#1402's gate walk: 2 of 3
        forwarder changes, DNS down ~13 s through kubelet's back-off).

        A daemon that outlives the stop timeout is NOT adopted: the start
        below would find it running and keep it, the reconcile would succeed
        against the old process, and the apply would be recorded although
        pdns never loaded the new file. Raising fails the apply instead, and
        ``_conf_restart_owed`` makes the retry restart again.
        """
        self._restarting = True
        try:
            pid = self.daemon_pid or find_running_daemon("pdns_server")
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pid = None
            deadline = time.monotonic() + stop_timeout_s
            while pid is not None and time.monotonic() < deadline:
                # We spawned it, so once it exits it is our zombie until reaped.
                try:
                    if os.waitpid(pid, os.WNOHANG)[0] == pid:
                        break
                except ChildProcessError:
                    # Not our child (adopted after an agent restart): poll instead.
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                time.sleep(0.1)
            else:
                if pid is not None:
                    log.warning("pdns_server_stop_timed_out", pid=pid)
                    raise RuntimeError(
                        f"pdns_server (pid {pid}) did not stop within {stop_timeout_s:g}s "
                        "of SIGTERM, so it is still serving the previous pdns.conf"
                    )
            self.daemon_pid = None
            self.start_daemon()
            self._wait_for_api_up()
        finally:
            self._restarting = False

    def _wait_for_api_up(self, *, timeout_s: float = 10.0) -> None:
        """Poll the local PowerDNS REST API until it answers (or
        we exceed ``timeout_s``). Used after ``start_daemon`` to
        avoid racing the daemon's UDP/53 + HTTP/8081 bring-up
        before the first reconcile. Best-effort: a still-down API
        after the timeout falls through to the reconcile attempt
        which then surfaces the real error to the sync loop.
        """
        api_key = self._load_or_generate_api_key()
        deadline = time.monotonic() + timeout_s
        with httpx.Client(timeout=1.0) as client:
            while time.monotonic() < deadline:
                try:
                    resp = client.get(
                        f"{_PDNS_API_BASE}/zones",
                        headers={"X-API-Key": api_key},
                    )
                    if resp.status_code < 500:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.2)
        log.warning("powerdns_api_wait_timeout", timeout_s=timeout_s)

    # ── Record ops (REST PATCH against loopback API) ───────────────────────

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        """Apply a single record op via the PowerDNS REST API.

        Returns an optional result dict the sync loop can pipe back
        upstream — DNSSEC ops use this to ship the new DS rrset to
        the control plane in the same tick the agent signed the zone.
        ``None`` for ordinary record ops (the existing fire-and-forget
        contract).
        """
        api_key = self._load_or_generate_api_key()
        zone_raw = op["zone_name"]
        zone = zone_raw.rstrip(".") + "."
        op_kind = op["op"]
        self._forget_reached(zone)

        # DNSSEC operations (Phase 3c) are zone-level, not rrset-
        # shaped. They flow through the same record-op queue but
        # branch off here rather than building a rrset PATCH.
        if op_kind == "dnssec_sign":
            ds_records = self._dnssec_sign(api_key, zone)
            return {
                "dnssec_state": {
                    "zone_name": zone,
                    "ds_records": ds_records,
                }
            }
        if op_kind == "dnssec_unsign":
            self._dnssec_unsign(api_key, zone)
            return {
                "dnssec_state": {
                    "zone_name": zone,
                    "ds_records": [],
                }
            }

        rec = op["record"]
        name = _qualified_name(zone, rec.get("name") or "@")
        rtype = rec["type"].upper()
        # Absence, not falsiness — a TTL of 0 is legal ("never cache this") and
        # ``or`` silently turned it into an hour. Matches bind9's driver, which
        # has always tested for None here.
        _op_ttl = rec.get("ttl")
        ttl = 3600 if _op_ttl is None else _op_ttl

        url = f"{_PDNS_API_BASE}/zones/{zone}"
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        # The content is computed for deletes too (#1520): a ``delete_value``
        # op has to splice exactly this value out of the live rrset, and
        # computing ``None`` for every delete made the fallback filter keep
        # every record and PATCH the unchanged set back, acked as applied.
        new_content = _record_content(rec, zone)

        # PowerDNS rrset PATCH semantics: ``REPLACE`` swaps the entire
        # rrset contents and ``DELETE`` drops it. There is no
        # ``INSERT`` / ``REMOVE-MEMBER`` granularity. Multiple records
        # at the same (name, type) — round-robin A pools, multi-MX
        # priorities, multi-NS apex — therefore need the whole set in
        # hand before the PATCH.
        #
        # #773 — the control plane now ships that set on the op, because it
        # is the only place the complete desired state is known. When it is
        # present the write is one PATCH, no read: no zone GET, no merge, and
        # an ``update`` that CHANGES a value no longer strands the old one
        # (the fallback below could not remove it, and says so).
        #
        # Every member goes out as ``disabled: False``. The control plane has
        # no notion of a disabled record, so its desired set means "these
        # values, served" — a record an operator disabled in PowerDNS's own UI
        # is re-enabled by the next write to that name. The merge below used to
        # preserve the flag on members it did not touch; a full-zone reconcile
        # would have clobbered it regardless, so this makes the behaviour
        # consistent rather than introducing a new way to lose it.
        rrset_payload = rec.get("rrset") if isinstance(rec.get("rrset"), dict) else None
        rrset_members = (
            rrset_payload.get("members") if rrset_payload is not None else None
        )
        if (
            rrset_payload is not None
            and rrset_members is not None
            and op_kind in RRSET_OP_KINDS
        ):
            if rrset_members:
                # Absence, not falsiness — a TTL of 0 is legal and meaningful.
                _rrset_ttl = rrset_payload.get("ttl")
                desired: dict[str, Any] = {
                    "name": name,
                    "type": rtype,
                    "ttl": int(ttl if _rrset_ttl is None else _rrset_ttl),
                    "changetype": "REPLACE",
                    # Deduped for the same reason as the full render
                    # (#1379): one repeated member refuses the whole rrset.
                    "records": [
                        {"content": content, "disabled": False}
                        for content in _dedupe_contents(
                            rtype,
                            [_record_content({**m, "type": rtype}, zone) for m in rrset_members],
                        )
                    ],
                }
            else:
                desired = {"name": name, "type": rtype, "changetype": "DELETE"}
            desired = self._keep_apex_ns(zone, desired)
            with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
                soa_rrsets, notify = self._soa_for_op(
                    client, headers, zone, rtype, name, op.get("target_serial")
                )
                soa_rrsets, notify = self._unless_already_served(
                    client, headers, zone, desired, soa_rrsets, notify
                )
                resp = client.patch(url, headers=headers, json={"rrsets": [desired, *soa_rrsets]})
                if resp.status_code < 400 and soa_rrsets and notify:
                    self._send_notify(client, headers, zone)
            if resp.status_code >= 400:
                self._forget_reached(zone)
                raise RuntimeError(
                    f"PowerDNS PATCH {zone}/{name}/{rtype} returned "
                    f"{resp.status_code}: {resp.text[:200]}"
                )
            log.info(
                "powerdns_rrset_applied",
                zone=zone,
                name=name,
                type=rtype,
                op=op_kind,
                members=len(rrset_members),
            )
            return None

        # Fallback for an op that carries no ``rrset`` payload. That is an
        # op enqueued by a control plane that predates the payload — and,
        # deliberately, every DNS-pool op: pools opt out of the stamping
        # (#773) because a pool re-points a member as a delete-then-create
        # pair on one serial, which only per-RR semantics make
        # order-independent. Read the current rrset, splice the op's content
        # in (or out), and PATCH the merged set back. Without this, two
        # consecutive ``create www A`` calls collide (the second overwrites
        # the first), which broke GSLB pool fan-out among other things.
        rrset_action = (rec.get("rrset_action") or "").lower()
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            zone_resp = client.get(url, headers=headers)
            existing_records: list[dict[str, Any]] = []
            if zone_resp.status_code == 200:
                zone_doc = zone_resp.json()
                for rs in zone_doc.get("rrsets", []) or []:
                    if rs.get("name") == name and rs.get("type") == rtype:
                        for rec_entry in rs.get("records") or []:
                            content = rec_entry.get("content")
                            if isinstance(content, str):
                                existing_records.append(
                                    {
                                        "content": content,
                                        "disabled": bool(
                                            rec_entry.get("disabled", False)
                                        ),
                                    }
                                )
                        break
            # update = delete-the-old-content + add-the-new-content; we don't
            # know the previous value here so update is treated as "ensure the
            # new value is present + remove any duplicate of the same
            # content". A separate explicit remove for the OLD value would
            # need the op payload to carry it, so without ``rrset`` a value
            # *change* leaves the old IP in the rrset until a delete op fires
            # for the prior content.
            merged: list[dict[str, Any]] = []
            if op_kind == "delete" and rrset_action == "delete_value":
                # Pool member removal (#1520): splice exactly this value
                # out; sibling members at the same (name, type) survive.
                # Nothing left ⇒ delete the rrset rather than REPLACE it
                # with an empty set (PowerDNS rejects that as malformed).
                merged = [r for r in existing_records if r["content"] != new_content]
                if not merged:
                    rrset: dict[str, Any] = {
                        "name": name,
                        "type": rtype,
                        "changetype": "DELETE",
                    }
                else:
                    rrset = {
                        "name": name,
                        "type": rtype,
                        "ttl": ttl,
                        "changetype": "REPLACE",
                        "records": merged,
                    }
            elif op_kind == "delete":
                # A plain delete clears the whole rrset by (name, type) —
                # the same value-blind semantics the BIND9 driver uses for
                # an op with no ``rrset_action`` override.
                rrset = {
                    "name": name,
                    "type": rtype,
                    "changetype": "DELETE",
                }
            else:  # create | update
                merged = [r for r in existing_records if r["content"] != new_content]
                merged.append({"content": new_content, "disabled": False})
                rrset = {
                    "name": name,
                    "type": rtype,
                    "ttl": ttl,
                    "changetype": "REPLACE",
                    "records": merged,
                }

            rrset = self._keep_apex_ns(zone, rrset)
            soa_rrsets, notify = self._soa_for_op(
                client, headers, zone, rtype, name, op.get("target_serial")
            )
            soa_rrsets, notify = self._unless_already_served(
                client, headers, zone, rrset, soa_rrsets, notify
            )
            body = {"rrsets": [rrset, *soa_rrsets]}
            resp = client.patch(url, headers=headers, json=body)
            if resp.status_code < 400 and soa_rrsets and notify:
                self._send_notify(client, headers, zone)
            if resp.status_code >= 400:
                self._forget_reached(zone)
                raise RuntimeError(
                    f"PowerDNS PATCH {zone}/{name}/{rtype} returned "
                    f"{resp.status_code}: {resp.text[:200]}"
                )
        # LUA records: the global ``enable-lua-records=yes`` knob in
        # pdns.conf (set in ``_render_conf`` above) makes every LUA
        # rrset live at query time. We deliberately do NOT set the
        # per-zone ``ENABLE-LUA-RECORDS`` metadata here — the REST API
        # rejects that key as "Unsupported metadata kind" via its
        # ``isValidMetadataKind`` filter, even though the docs claim it
        # works. Re-verified against pdns 5.0.5 while bumping the image
        # in #638: still HTTP 422, so the global flag stays. It is
        # portable across versions and zero-cost for non-LUA zones.
        log.info(
            "powerdns_record_op_applied",
            zone=zone,
            name=name,
            type=rtype,
            op=op_kind,
        )

    # ── DNSSEC ops (Phase 3c) ──────────────────────────────────────────────

    def _keep_apex_ns(self, zone: str, rrset: dict[str, Any]) -> dict[str, Any]:
        """``rrset``, unless it deletes the zone's apex NS (#1985): then a
        REPLACE with the zone's default apex NS, in the same PATCH.

        A record op deleting the zone's last apex NS record ships an empty
        rrset, i.e. a DELETE. Records are not structural, so no reconcile
        follows to put the default back, and the zone would serve no NS until
        some unrelated structural change: every BIND9 secondary's next
        transfer fails with "has no NS records". BIND9 itself never reaches
        that state (an UPDATE removing the last apex NS is ignored, RFC 2136
        3.4.2.4); here the default takes the operator's NS's place directly.

        The default is the one the last APPLIED render computed (the live
        ``zones.json``), so it follows the zone's Primary NS; with no such
        render on disk it is the ``ns1.<zone>`` placeholder, and the next
        reconcile corrects it.
        """
        if (
            rrset.get("type") != "NS"
            or rrset.get("changetype") != "DELETE"
            or str(rrset.get("name") or "").lower() != zone.lower()
        ):
            return rrset
        target, ttl = f"ns1.{zone}", 3600
        try:
            rendered = json.loads((self.state_dir / "rendered" / "zones.json").read_text())
        except (OSError, ValueError):
            rendered = []
        for entry in rendered if isinstance(rendered, list) else []:
            if (
                isinstance(entry, dict)
                and str(entry.get("name") or "").lower() == zone.lower()
                and entry.get("default_apex_ns")
            ):
                target = str(entry["default_apex_ns"])
                # Absence, not falsiness: a TTL of 0 is legal.
                if entry.get("default_apex_ns_ttl") is not None:
                    ttl = int(entry["default_apex_ns_ttl"])
                break
        log.info("powerdns_apex_ns_default_restored", zone=zone, target=target)
        return {
            "name": rrset["name"],
            "type": "NS",
            "ttl": ttl,
            "changetype": "REPLACE",
            "records": [{"content": target, "disabled": False}],
        }

    def _soa_for_op(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone: str,
        rtype: str,
        name: str,
        target_serial: Any,
    ) -> tuple[list[dict[str, Any]], bool]:
        """The SOA rrset a record op adds to its PATCH, and whether the zone is
        a primary (a NOTIFY is due after it).

        PowerDNS no longer bumps the serial itself (``SOA-EDIT-API`` is empty,
        #1965), so the op carries the zone to the serial the control plane
        stamped on it (``target_serial``) in the same PATCH. When PowerDNS
        already serves that serial or a later one (the control plane has not
        yet adopted the served serial), the zone moves to the served serial + 1
        instead, and so does an op from a control plane that sends no
        ``target_serial`` (#1968: a serial is never sent lower than the one
        served, and a change is never published under a serial already
        served). A stale-target op whose change PowerDNS already serves is
        left alone by ``_unless_already_served``.
        """
        problem, doc = self._read_soa(client, headers, zone)
        if problem:
            raise RuntimeError(f"PowerDNS {zone}: {problem}")
        kind = _kind_category(doc.get("kind"))
        if kind == "secondary":
            return [], False
        served = _soa_from_zone_doc(doc, zone)
        if doc.get("soa_edit_api"):
            # A zone the full reconcile has not reached yet (an op beating it
            # after the upgrade): clear it here, or PowerDNS rewrites ours.
            resp = client.put(
                f"{_PDNS_API_BASE}/zones/{zone}", headers=headers, json={"soa_edit_api": ""}
            )
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"PowerDNS {zone}: clear SOA-EDIT-API returned "
                    f"{resp.status_code}: {resp.text[:200]}"
                )
        notify = kind == "primary"
        if served is None or (rtype == "SOA" and name.lower() == zone.lower()):
            return [], notify
        have = _soa_serial(served[0])
        if have is None:
            return [], notify
        key = zone.rstrip(".").lower()
        reached = getattr(self, "_op_reached", None)
        if reached is None:
            reached = self._op_reached = {}
        stale = getattr(self, "_op_stale", None)
        if stale is None:
            stale = self._op_stale = {}
        stale.pop(key, None)
        if isinstance(target_serial, int) and not isinstance(target_serial, bool):
            if _serial_later(target_serial, have):
                new = target_serial
            else:
                # The control plane is behind what PowerDNS serves (an op made
                # before it adopted the served serial, #1968). Leaving the SOA
                # alone would publish the change under a serial the
                # secondaries already hold, so they would never transfer it:
                # move forward of the served one instead, unless the change is
                # already served (a retried op), which
                # ``_unless_already_served`` decides once it has the rrset.
                new = (have + 1) % 2**32
                stale[key] = have
        else:
            new = (have + 1) % 2**32
        reached[key] = new
        return [
            {
                "name": zone,
                "type": "SOA",
                "ttl": served[1],
                "changetype": "REPLACE",
                "records": [{"content": _soa_with_serial(served[0], new), "disabled": False}],
            }
        ], notify

    def _unless_already_served(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone: str,
        rrset: dict[str, Any],
        soa_rrsets: list[dict[str, Any]],
        notify: bool,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Drop the SOA move ``_soa_for_op`` planned for a stale-target op when
        PowerDNS already serves exactly what ``rrset`` asks for.

        That is a retried op (its ack was lost) or one a full reconcile beat:
        the change is already published, so moving the serial again would only
        make every secondary transfer the same data. Any doubt (an unreadable
        rrset, contents spelled differently) keeps the move, which is the safe
        direction: a redundant transfer, never a change the secondaries miss.
        """
        key = zone.rstrip(".").lower()
        have = getattr(self, "_op_stale", {}).pop(key, None)
        if have is None or not soa_rrsets:
            return soa_rrsets, notify
        name = str(rrset.get("name") or "")
        rtype = str(rrset.get("type") or "")
        try:
            resp = client.get(
                f"{_PDNS_API_BASE}/zones/{zone}",
                params={"rrset_name": name, "rrset_type": rtype},
                headers=headers,
            )
            doc = resp.json() if resp.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return soa_rrsets, notify
        if not isinstance(doc, dict):
            return soa_rrsets, notify
        served = next(
            (
                rs
                for rs in doc.get("rrsets") or []
                if isinstance(rs, dict)
                and str(rs.get("name") or "").lower() == name.lower()
                and rs.get("type") == rtype
            ),
            None,
        )
        served_records = (served or {}).get("records") or []
        if rrset.get("changetype") == "DELETE":
            unchanged = not served_records
        else:
            want = sorted(str(r.get("content")) for r in rrset.get("records") or [])
            unchanged = (
                served is not None
                and served.get("ttl") == rrset.get("ttl")
                and not any(r.get("disabled") for r in served_records)
                and sorted(str(r.get("content")) for r in served_records) == want
            )
        if not unchanged:
            return soa_rrsets, notify
        getattr(self, "_op_reached", {})[key] = have
        return [], False

    def _dnssec_sign(self, api_key: str, zone: str) -> list[str]:
        """Generate KSK + ZSK, set PRESIGNED metadata, rectify zone.

        Returns the DS rrset string list so the caller can ship it to the
        control plane (operator pastes the DS into their parent registrar).
        Empty list means we couldn't extract DS — log-only, not fatal,
        operator can re-trigger sign to retry.

        Idempotent — if keys already exist for the zone, pdns refuses with
        a 409 / 422 and we treat that as success. Operators expect the
        result of repeated 'Sign zone' clicks to converge to "signed",
        not error out.
        """
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            existing = client.get(
                f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys", headers=headers
            )
            if existing.status_code == 200 and existing.json():
                # Keys already there — nothing to create. Just rectify
                # (idempotent) so NSEC/NSEC3 chains stay current. This
                # covers the "operator clicked twice" case + the
                # "agent restart, redo state" case.
                self._rectify(client, headers, zone)
                log.info("powerdns_dnssec_already_signed", zone=zone)
                return self._extract_ds_records(existing.json())

            for kind, key_type in (("ksk", "ksk"), ("zsk", "zsk")):
                # PowerDNS 4.9 picks a sensible default algorithm for
                # KSK creation when ``algorithm`` is omitted, but the
                # ZSK default-picker resolves to algorithm -1
                # (Unallocated) and the API rejects with "Creating an
                # algorithm -1 (Unallocated/Reserved) key requires the
                # size (in bits) to be passed." Pin both keys to
                # ECDSAP256SHA256 (algorithm 13) — RFC 6605, the
                # current online-signing default in pdns docs — so the
                # call is portable across KSK/ZSK iterations.
                resp = client.post(
                    f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys",
                    headers=headers,
                    json={
                        "keytype": key_type,
                        "active": True,
                        "published": True,
                        "algorithm": "ecdsa256",
                    },
                )
                if resp.status_code >= 400:
                    raise RuntimeError(
                        f"PowerDNS create {kind.upper()} for {zone} returned "
                        f"{resp.status_code}: {resp.text[:200]}"
                    )

            # Note: we deliberately do NOT set the ``PRESIGNED`` zone
            # metadata for online-signing zones. ``PRESIGNED`` is for
            # zones signed by an external signer (e.g. via
            # ``dnssec-signzone``) and loaded as already-signed; for
            # online signing pdns derives signing intent from the
            # presence of cryptokeys + active/published flags. Setting
            # it actually trips the API's metadata-kind filter
            # ("Unsupported metadata kind 'PRESIGNED'"), and the
            # resulting warning is misleading. Re-verified against pdns
            # 5.0.5 while bumping the image in #638: still HTTP 422.
            self._rectify(client, headers, zone)

            # Re-fetch after creation so we get the freshly-rendered DS
            # rrset (PowerDNS computes DS from the KSK we just made).
            after = client.get(
                f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys", headers=headers
            )
            log.info("powerdns_dnssec_signed", zone=zone)
            if after.status_code == 200:
                return self._extract_ds_records(after.json())
            return []

    @staticmethod
    def _extract_ds_records(cryptokeys: list[dict[str, Any]]) -> list[str]:
        """Walk the PowerDNS cryptokeys response and pull out every DS
        rrset string.

        PowerDNS includes a ``ds`` field on each KSK entry (and not on
        ZSKs — DS records only attest the KSK to the parent zone).
        Each KSK typically yields one DS per supported digest algorithm
        (SHA-1 + SHA-256 + SHA-384 by default), all of which the
        operator should publish to cover validators of varying
        sophistication.
        """
        out: list[str] = []
        for k in cryptokeys or []:
            if k.get("keytype") != "ksk":
                continue
            for ds in k.get("ds") or []:
                if isinstance(ds, str) and ds.strip():
                    out.append(ds.strip())
        return out

    def _dnssec_unsign(self, api_key: str, zone: str) -> None:
        """Delete every cryptokey + clear PRESIGNED metadata.

        Idempotent — missing keys / metadata are a no-op. Same convergence
        semantic as ``_dnssec_sign``.
        """
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            existing = client.get(
                f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys", headers=headers
            )
            if existing.status_code == 200:
                for key in existing.json() or []:
                    key_id = key.get("id")
                    if key_id is None:
                        continue
                    del_resp = client.delete(
                        f"{_PDNS_API_BASE}/zones/{zone}/cryptokeys/{key_id}",
                        headers=headers,
                    )
                    if del_resp.status_code >= 400 and del_resp.status_code != 404:
                        log.warning(
                            "powerdns_dnssec_key_delete_failed",
                            zone=zone,
                            key_id=key_id,
                            status=del_resp.status_code,
                            body=del_resp.text[:200],
                        )

            # Note: PRESIGNED metadata is intentionally NOT touched
            # here — see _dnssec_sign for the full reason. With keys
            # gone, pdns is back to serving unsigned answers
            # automatically.
        log.info("powerdns_dnssec_unsigned", zone=zone)

    def _rectify(
        self, client: httpx.Client, headers: dict[str, str], zone: str
    ) -> None:
        """Re-sign + re-NSEC3 the zone after a key change. PowerDNS requires
        an explicit rectify call after cryptokey changes; otherwise old
        signatures linger until the next zone PATCH.
        """
        resp = client.put(
            f"{_PDNS_API_BASE}/zones/{zone}/rectify",
            headers=headers,
        )
        if resp.status_code >= 400:
            log.warning(
                "powerdns_dnssec_rectify_failed",
                zone=zone,
                status=resp.status_code,
                body=resp.text[:200],
            )

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start_daemon(self) -> None:
        """Spawn ``pdns_server`` from the rendered config dir.

        The container entrypoint already created the LMDB directory
        and seeded the API key. We don't drop privileges further —
        the entrypoint dropped to the unprivileged ``spatium`` user
        before invoking the agent.
        """
        current = self.state_dir / "rendered"
        if not (current / "pdns.conf").exists():
            log.warning("pdns_conf_missing_startup_deferred")
            return
        if not shutil.which("pdns_server"):
            log.error("pdns_server_binary_missing")
            return
        # Idempotent against the SYSTEM, not this object's state (#704).
        # ``daemon_pid`` is per-instance and only ``daemon_running()``
        # guards the two ``start_daemon()`` call sites from racing into
        # a duplicate spawn. Unlike
        # BIND9 — which uses SO_REUSEPORT and quietly runs two servers —
        # pdns_server has no ``reuseport`` set, so the duplicate fails to
        # bind :53 and exits. The damage is subtler for it: the ``Popen``
        # handle is discarded, so the corpse is never reaped, and
        # ``daemon_pid`` is left pointing at a ZOMBIE. Because
        # ``os.kill(zombie, 0)`` succeeds, the driver then reports a
        # healthy daemon while tracking a dead process, and any signal it
        # sends goes nowhere.
        # The system look-up is necessary but not sufficient: it matches on
        # ``/proc/<pid>/comm``, and a forked-but-not-yet-``execve``'d child
        # still carries the parent's name, so a concurrent caller sees no
        # daemon and spawns a duplicate anyway. Serialise check-and-spawn on
        # an exclusive lock instead (see ``_process.spawn_guard``).
        with spawn_guard(self.state_dir, "pdns_server"):
            existing = find_running_daemon("pdns_server")
            if existing is not None:
                self.daemon_pid = existing
                log.info(
                    "pdns_already_running_adopted",
                    pid=existing,
                    note="did not spawn a second daemon",
                )
                return
            # ``--daemon=no`` + foreground; pdns logs to stderr.
            # All flags use ``--name=value`` form — pdns_server rejects
            # space-separated args with "perhaps a '--setting=123'
            # statement missed the '='?".
            #
            # We redirect pdns_server stderr into a file the agent's
            # ``QueryLogShipper`` thread can tail, gated on
            # ``log-dns-queries=yes`` being set in pdns.conf. The file
            # lives inside the agent's own state dir
            # (``/var/lib/spatium-dns-agent/pdns.log``) — the ``spatium``
            # user owns that path, which avoids the permission denied
            # we'd hit trying to write to ``/var/log/pdns/`` (owned by
            # root inside the container). The supervisor's
            # ``QueryLogShipper`` is configured against the same path
            # in ``supervisor.run``.
            log_path = self.state_dir / "pdns.log"
            # Open append-mode so log rotates are non-destructive and the
            # tail can resume across daemon restarts (the shipper handles
            # inode-change rotation separately).
            log_fh = log_path.open("ab", buffering=0)
            self.daemon_pid = subprocess.Popen(
                [
                    "pdns_server",
                    "--daemon=no",
                    "--guardian=no",
                    f"--config-dir={current}",
                    "--config-name=",
                ],
                stdout=log_fh,
                stderr=subprocess.STDOUT,
            ).pid
            wait_for_daemon("pdns_server", self.daemon_pid)
        # Track the path so a future health-check / observability
        # surface can find it without re-deriving.
        self._daemon_log_path = log_path
        log.info(
            "pdns_server_started",
            pid=self.daemon_pid,
            log_path=str(log_path),
        )

    def daemon_running(self) -> bool:
        # Falls back to a system-wide look-up when this object has no pid
        # of its own — another driver instance may legitimately own the
        # running daemon, and answering "not running" spawns a duplicate.
        # The shared helper skips zombies, so a corpse is never mistaken
        # for a live daemon (#704).
        if self.daemon_pid is None:
            found = find_running_daemon("pdns_server")
            if found is None:
                return False
            self.daemon_pid = found
            return True
        try:
            os.kill(self.daemon_pid, 0)
        except OSError:
            return False
        # ``os.kill(pid, 0)`` succeeds for a zombie, so liveness needs
        # the state check too — this is exactly how a dead pdns_server
        # was being reported as healthy.
        return not is_zombie(str(self.daemon_pid))

    def daemon_version(self) -> str | None:
        """Running ``pdns_server`` version, e.g. ``"5.0.5"``.

        Read off the binary rather than the REST API on purpose: the version
        matters most when the daemon is NOT healthy (a pdns that just refused
        to open a migrated LMDB answers no API calls, and that is exactly the
        situation #638's preflight is trying to warn about beforehand).

        The output format differs between majors — 4.9 prefixes a syslog-style
        timestamp, 5.0 does not — so match on the product string, not position:

            Jul 28 12:56:47 PowerDNS Authoritative Server 4.9.5 (C) …
            PowerDNS Authoritative Server 5.0.5 (C) …
        """
        exe = shutil.which("pdns_server")
        if exe is None:
            return None
        try:
            proc = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("pdns_version_probe_failed", error=str(e))
            return None
        m = re.search(
            r"Authoritative Server\s+([0-9]+(?:\.[0-9]+)*)",
            f"{proc.stdout}\n{proc.stderr}",
        )
        return m.group(1) if m else None

    # ── Internals ───────────────────────────────────────────────────────────

    def _api_key_path(self) -> Path:
        return self.state_dir / _API_KEY_FILE

    def _load_or_generate_api_key(self) -> str:
        """Return the local PowerDNS REST API key.

        The container entrypoint usually pre-creates this file. If
        the agent boots in a fresh state dir (volume not mounted),
        we generate one ourselves so the first config sync has
        something to use — pdns will read the same file when the
        entrypoint copies it into place at startup.

        Issue #249 — atomic write via ``.new`` sibling + ``replace``
        so a crash between ``write_text`` and ``chmod`` doesn't
        leave a world-readable key on disk (or a 0-byte partial
        file if the crash lands mid-write).

        Issue #253 — refuse to overwrite an existing file we can't
        read. If the entrypoint wrote the key as root with mode 600
        before chown'ing to spatium, the agent's previous logic
        treated the unreadable file as "missing" and silently wrote
        its own value while ``pdns_server`` was already running
        with the original. New behaviour: if the path exists but
        is unreadable, raise rather than overwrite — the operator
        sees a clear error in the agent log + can fix permissions
        rather than chase a mismatched-key 401 storm.
        """
        path = self._api_key_path()
        if path.exists():
            try:
                return path.read_text().strip()
            except PermissionError as exc:
                raise RuntimeError(
                    f"PowerDNS API key file at {path} exists but is "
                    "unreadable by the agent. Fix ownership/perms "
                    "(should be spatium:spatium 0600) instead of "
                    "letting the agent overwrite — pdns may already "
                    "be running with the original value."
                ) from exc
        key = secrets.token_urlsafe(32)
        # Shared primitive (#869): 0600 at creation via O_NOFOLLOW, complete
        # write, atomic replace. Was open-coded here; the copies had drifted.
        write_private(path, key + "\n")
        return key

    def _render_conf(
        self,
        *,
        api_key: str,
        log_level: int,
        query_log_enabled: bool = False,
        alias_resolver: str = "",
    ) -> str:
        # Mirrors backend/app/drivers/dns/powerdns.py::render_pdns_conf.
        # Agent and control plane render the same shape; the agent
        # owns the API key while the control plane sees only the
        # placeholder.
        log_queries_value = "yes" if query_log_enabled else "no"
        return "\n".join(
            [
                "# pdns.conf — generated by SpatiumDDI DNS agent",
                "# Do not edit by hand; the agent rewrites this file on every config sync.",
                "",
                "launch=lmdb",
                "lmdb-filename=/var/lib/powerdns/pdns.lmdb",
                "lmdb-shards=64",
                "lmdb-sync-mode=sync",
                "",
                # pdns always listens on :53. The dnsdist front (#146 Phase 2)
                # is a SEPARATE container that forwards to this :53 over the
                # network — pdns never moves port, so there's no restart race
                # and toggling the front is decoupled from pdns's lifecycle.
                f"local-address={_pdns_local_address()}",
                "local-port=53",
                "",
                "api=yes",
                f"api-key={api_key}",
                "webserver=yes",
                "webserver-address=127.0.0.1",
                "webserver-port=8081",
                "webserver-allow-from=127.0.0.1,::1",
                "",
                f"loglevel={log_level}",
                # ``log-dns-details`` adds the question + answer detail
                # we need to parse client_ip / qname / qtype out of the
                # log; ``log-dns-queries`` is the toggle that emits one
                # line per incoming query. Both gate on the operator-
                # facing ``DNSServerOptions.query_log_enabled`` flag.
                f"log-dns-details={log_queries_value}",
                f"log-dns-queries={log_queries_value}",
                "",
                # PowerDNS polls a TXT record under secpoll.powerdns.com at
                # startup and periodically to learn whether its version has
                # a security advisory. That query leaves through ``resolver=``
                # (once hardcoded public resolvers, see below) or the system
                # resolver, naming the version; it is an outbound connection
                # nobody configured (non-negotiable #17). An empty suffix
                # turns it off (#1353). PowerDNS fixes arrive with
                # SpatiumDDI releases instead. A startup setting: takes effect on
                # pdns's next start, like ``dnsupdate`` below.
                "security-poll-suffix=",
                # #2935 — what pdns says about itself over CHAOS queries.
                # By default ``version.bind`` names the exact build and
                # ``id.server`` (and NSID) the container hostname, a
                # container id on Compose. Version and stack details are for
                # signed-in users only. Literal "none" rather than
                # ``version-string=anonymous``: that one answers SERVFAIL,
                # which reads as a fault on a monitor, while "none" keeps both
                # queries answered — so the chart's readiness probe and the
                # image HEALTHCHECK (``dig id.server CH TXT``) still get a
                # reply. Startup settings, like ``dnsupdate`` below.
                "version-string=none",
                "server-id=none",
                # ALIAS-record resolution requires both ``expand-alias=yes``
                # and a ``resolver=`` upstream. PowerDNS Authoritative
                # synthesises A/AAAA at query time by recursing through
                # the configured resolver: the group's forwarders, or none
                # and ALIAS off (#1353).
                *(
                    ["expand-alias=yes", f"resolver={alias_resolver}"]
                    if alias_resolver.strip()
                    else ["expand-alias=no"]
                ),
                # LUA records (PowerDNS-only computed responses —
                # ``pickrandom`` / ``ifportup`` / ``createReverse`` etc.)
                # are GLOBALLY enabled here rather than per-zone via
                # ENABLE-LUA-RECORDS metadata. The per-zone metadata
                # path is rejected by the pdns REST filter as an
                # "unsupported kind" (re-verified on 5.0.5 in #638);
                # enabling globally is portable
                # across versions and harmless for non-LUA zones (zones
                # with zero LUA records simply don't trigger the LUA
                # engine at query time).
                "enable-lua-records=yes",
                # RFC 2136 dynamic updates (issue #641). Enabled globally so
                # the feature is available; per-zone acceptance is gated by the
                # ``ALLOW-DNSUPDATE-FROM`` / ``TSIG-ALLOW-DNSUPDATE`` metadata
                # the reconciler sets — a zone with neither rejects every
                # update, so this is a no-op for zones without an ACL.
                # ``dnsupdate`` is a startup setting, like every line here;
                # ``swap_and_reload`` restarts pdns when this file changes.
                "dnsupdate=yes",
                "",
                # NOTIFY and zone transfers are OFF in PowerDNS until the
                # server declares its role (#1967). A zone of kind Master
                # with ALSO-NOTIFY metadata is not enough while ``primary``
                # is ``no`` (the default): nothing is ever sent. Likewise a
                # kind Slave zone is never checked or transferred while
                # ``secondary`` is ``no``. Both are per-zone no-ops for a
                # zone of the other kind, so they are always on; a changed
                # file restarts pdns (``swap_and_reload``), once. Verified
                # against pdns-auth 5.0.7: with ``primary=yes`` a change to
                # a Master zone is NOTIFY-ed to its ALSO-NOTIFY targets, and
                # a Slave zone transfers only with ``secondary=yes``.
                "primary=yes",
                "secondary=yes",
                "",
            ]
        )

    def _reconcile_zones(self, api_key: str, payload: list[dict[str, Any]]) -> None:
        """Idempotently bring the local PowerDNS zone set in line with
        ``payload``: per-zone create-or-update. Zones present in PowerDNS
        that aren't in the bundle are NOT deleted — that's a control-plane
        safety call (operators should explicitly delete a zone, not have it
        disappear because a sync glitched). Within a zone the bundle IS the
        whole truth: an rrset PowerDNS holds and the bundle no longer does is
        deleted in the same PATCH (#1380), except the apex SOA / NS and the
        DNSSEC types, and except in a zone that accepts RFC 2136 updates,
        whose clients write records the bundle never carries.

        Every zone is attempted and the verdict is per zone. A zone whose
        DATA PowerDNS refuses (400 / 409 / 422 — a CNAME beside other
        records, a malformed record) is recorded with PowerDNS's reason in
        ``refused_zones()``. Its rrsets are then sent piecemeal (#2060,
        halves split until the refused rrsets are isolated), so only the
        refused ones keep what PowerDNS held — one bad rrset no
        longer strands every other change to the zone; the apply still succeeds,
        so every zone PowerDNS accepted is served and nothing is rolled back.
        Rolling back could not help: the last-known-good bundle usually
        carries the same refused data, so it used to keep the whole server
        ``revert_failed`` over one zone.

        Anything that is not a verdict on a zone's data — the zone listing,
        a zone that cannot be read back, a 5xx, a dropped connection, the
        dynamic-update ACL or TSIG keys — still fails the whole apply (#1225).
        """
        headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
        failures: list[str] = []
        refused: list[str] = []
        self._refused_zones = ()
        # TSIG keys already imported this pass. A group key is referenced by
        # every zone that grants it, so importing it per zone cost two calls
        # per zone and repeated one refusal once per zone, filling the
        # five-failure summary with a single key and hiding the rest.
        tsig_seen: set[str] = set()
        with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
            # Not knowing which zones exist is a failure, not an empty list:
            # an empty list sent every existing zone down the CREATE path,
            # where PowerDNS answers 409, which was logged and skipped.
            try:
                resp = client.get(f"{_PDNS_API_BASE}/zones", headers=headers)
                resp.raise_for_status()
                existing = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise RuntimeError(f"cannot list PowerDNS zones: {exc}") from exc
            # Compared case-insensitively, as DNS names are: PowerDNS stores a
            # zone lowercased, so an exact match missed ``Case.Test.`` on every
            # reconcile after the first and re-POSTed it, which answers 409.
            # Verified against a real pdns, which also accepts either case in
            # the PATCH URL.
            # Kept per zone (#1521): the kind and masters PowerDNS holds,
            # compared below with the payload's.
            existing_by_name = {
                z["name"].lower(): z for z in existing if isinstance(z, dict) and z.get("name")
            }
            existing_names = set(existing_by_name)

            for zone_payload in payload:
                zone_name = zone_payload["name"]
                if zone_name.lower() not in existing_names:
                    # Create — POST /zones with the full rrset list.
                    create_body: dict[str, Any] = {
                        "name": zone_name,
                        "kind": zone_payload.get("kind", "Native"),
                        "rrsets": zone_payload.get("rrsets") or [],
                    }
                    # The zone's serial goes on create (#1522) — it was
                    # in the payload but never sent, so a fresh zone
                    # started at pdns's default serial whatever the
                    # control plane had stamped.
                    try:
                        create_body["serial"] = int(zone_payload.get("serial") or 1)
                    except (TypeError, ValueError):
                        create_body["serial"] = 1
                    if zone_payload.get("masters"):
                        create_body["masters"] = zone_payload["masters"]
                    if _kind_category(create_body["kind"]) != "secondary" and zone_payload.get(
                        "serial_managed", True
                    ):
                        # The API default (``DEFAULT``) rewrites the serial of
                        # every change made through it, so the zone would
                        # never serve the control plane's (#1965). Empty means
                        # PowerDNS serves the serial the agent sends.
                        create_body["soa_edit_api"] = ""
                    resp = client.post(
                        f"{_PDNS_API_BASE}/zones",
                        headers=headers,
                        json=create_body,
                    )
                    if resp.status_code in _RRSET_REFUSAL_STATUSES and create_body["rrsets"]:
                        # One refused rrset refuses the whole create, so the
                        # zone would not exist at all (#2060). Create it empty
                        # and send its rrsets piecemeal, so only the
                        # refused ones are missing.
                        first = resp
                        resp = client.post(
                            f"{_PDNS_API_BASE}/zones",
                            headers=headers,
                            json={**create_body, "rrsets": []},
                        )
                        if resp.status_code < 400:
                            if (
                                self._apply_rrsets_singly(
                                    client,
                                    headers,
                                    zone_name,
                                    "create",
                                    first,
                                    create_body["rrsets"],
                                    refused,
                                    failures,
                                )
                                is None
                            ):
                                continue
                        else:
                            resp = first
                    if resp.status_code >= 400:
                        self._zone_not_applied(zone_name, "create", resp, refused, failures)
                        continue
                    log.info("powerdns_zone_created", zone=zone_name)
                    if _kind_category(zone_payload.get("kind")) == "secondary":
                        # Do not wait for the next refresh cycle (up to a
                        # minute) for the first transfer (#1967).
                        self._request_axfr(client, headers, zone_name)
                else:
                    # Zone type / primaries drift (#1521): a zone
                    # converted primary↔secondary, or whose masters
                    # changed, keeps its original kind forever if only
                    # rrsets are PATCHed. PUT the kind/masters when the
                    # live zone differs from the payload's.
                    desired_kind = zone_payload.get("kind", "Native")
                    desired_masters = [str(m) for m in zone_payload.get("masters") or []]
                    current = existing_by_name.get(zone_name.lower()) or {}
                    current_masters = [str(m) for m in current.get("masters") or []]
                    if _kind_category(current.get("kind")) != _kind_category(
                        desired_kind
                    ) or {m.lower() for m in current_masters} != {
                        m.lower() for m in desired_masters
                    }:
                        resp = client.put(
                            f"{_PDNS_API_BASE}/zones/{zone_name}",
                            headers=headers,
                            json={
                                "name": zone_name,
                                "kind": desired_kind,
                                "masters": desired_masters,
                            },
                        )
                        if resp.status_code >= 400:
                            self._zone_not_applied(
                                zone_name, "kind_update", resp, refused, failures
                            )
                            continue
                        log.info(
                            "powerdns_zone_kind_updated",
                            zone=zone_name,
                            kind=desired_kind,
                            masters=desired_masters,
                        )
                    # Update — PATCH /zones/{zone}: DELETE what the bundle
                    # dropped, then REPLACE every rrset it carries. One PATCH,
                    # which PowerDNS applies as one transaction.
                    desired = zone_payload.get("rrsets") or []
                    serial_changed = False
                    if _kind_category(desired_kind) != "secondary" and zone_payload.get(
                        "serial_managed", True
                    ):
                        # Own the serial (#1965) and never send a lower one
                        # than PowerDNS serves (#1968) — before the PATCH, since
                        # the replacement SOA is in it.
                        problem, serial_changed = self._own_soa_serial(
                            client, headers, zone_name, desired
                        )
                        if problem:
                            log.error("powerdns_soa_serial_failed", zone=zone_name, error=problem)
                            failures.append(f"{zone_name} soa serial: {problem}")
                            continue
                    rrsets: list[dict[str, Any]] = []
                    if _kind_category(desired_kind) == "secondary":
                        # A secondary's rrsets are the transfer's (#1521):
                        # the payload carries none, so a sweep would DELETE
                        # every transferred rrset.
                        log.debug("powerdns_absent_rrset_sweep_skipped_secondary", zone=zone_name)
                    elif zone_payload.get("update_acl"):
                        # RFC 2136 clients write straight into this zone, and
                        # their records are not in the bundle; sweeping
                        # absent rrsets here would delete every one of them.
                        log.debug("powerdns_absent_rrset_sweep_skipped_dynamic", zone=zone_name)
                    else:
                        resp = client.get(f"{_PDNS_API_BASE}/zones/{zone_name}", headers=headers)
                        try:
                            current = resp.json() if resp.status_code == 200 else None
                        except ValueError:
                            current = None
                        if not isinstance(current, dict):
                            log.error(
                                "powerdns_zone_read_failed",
                                zone=zone_name,
                                status=resp.status_code,
                                body=resp.text[:200],
                            )
                            failures.append(
                                f"{zone_name} read: HTTP {resp.status_code} {_pdns_error(resp)}"
                            )
                            continue
                        rrsets.extend(_absent_rrsets(zone_name, desired, current))
                    deleted = len(rrsets)
                    for rs in desired:
                        rrsets.append(
                            {
                                "name": rs["name"],
                                "type": rs["type"],
                                "ttl": rs.get("ttl", 3600),
                                "changetype": "REPLACE",
                                "records": rs.get("records") or [],
                            }
                        )
                    # An empty change list still falls through to the
                    # dynamic-update metadata below — a DDNS-only zone may
                    # have no control-plane-managed records yet (issue #641).
                    if rrsets:
                        resp = client.patch(
                            f"{_PDNS_API_BASE}/zones/{zone_name}",
                            headers=headers,
                            json={"rrsets": rrsets},
                        )
                        soa_landed = True
                        if resp.status_code in _RRSET_REFUSAL_STATUSES:
                            # PowerDNS applies a PATCH as one transaction, so
                            # one refused rrset used to strand every other
                            # change to the zone (#2060). Send them piecemeal:
                            # the rest land, the refused ones are named.
                            first = resp
                            not_landed = self._apply_rrsets_singly(
                                client, headers, zone_name, "update", first, rrsets, refused, failures
                            )
                            if not_landed is None:
                                continue
                            soa_landed = all(t != "SOA" for _, t in not_landed)
                        elif resp.status_code >= 400:
                            self._zone_not_applied(zone_name, "update", resp, refused, failures)
                            continue
                        log.info(
                            "powerdns_zone_reconciled",
                            zone=zone_name,
                            rrset_count=len(rrsets) - deleted,
                            deleted=deleted,
                        )
                        if (
                            serial_changed
                            and soa_landed
                            and _kind_category(desired_kind) == "primary"
                        ):
                            self._send_notify(client, headers, zone_name)

                # Dynamic-update (RFC 2136) ACL metadata (issue #641).
                failures.extend(
                    f"{zone_name} dynamic-update ACL: {problem}"
                    for problem in self._apply_dynamic_update(
                        client, headers, zone_payload, tsig_seen=tsig_seen
                    )
                )

                # Zone transfers out (#1967) — ALLOW-AXFR-FROM +
                # TSIG-ALLOW-AXFR metadata.
                failures.extend(
                    f"{zone_name} transfer ACL: {problem}"
                    for problem in self._apply_transfer_acl(
                        client, headers, zone_payload, tsig_seen=tsig_seen
                    )
                )

                # NOTIFY targets (issue #1523) — ALSO-NOTIFY metadata.
                notify_problem = self._apply_notify_settings(client, headers, zone_payload)
                if notify_problem:
                    failures.append(f"{zone_name} also-notify: {notify_problem}")

                # LUA records are enabled globally via
                # ``enable-lua-records=yes`` in pdns.conf (see
                # ``_render_conf``). Earlier code attempted a per-zone
                # ``ENABLE-LUA-RECORDS`` metadata PUT here, but pdns
                # rejects that key via ``isValidMetadataKind`` as
                # "Unsupported metadata kind" (still true on 5.0.5,
                # re-verified in #638) — which spammed a
                # ``powerdns_lua_metadata_failed`` warning on every
                # bulk reconcile of a LUA-bearing zone. The global
                # knob makes the per-zone PUT unnecessary.

        self._refused_zones = tuple(refused)
        if refused:
            log.warning(
                "powerdns_zones_refused",
                count=len(refused),
                zones=refused[:5],
                detail="every other zone is served; in a refused zone every rrset "
                "PowerDNS accepted is served and a refused one keeps what it held",
            )
        if failures:
            problems = failures + [f"refused {r}" for r in refused]
            more = f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""
            raise RuntimeError(
                "PowerDNS did not accept every zone: " + "; ".join(problems[:5]) + more
            )

    def _own_soa_serial(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone_name: str,
        desired: list[dict[str, Any]],
    ) -> tuple[str | None, bool]:
        """Make the zone serve the control plane's serial, and never a lower
        one than it serves now (#1965, #1968).

        Clears ``SOA-EDIT-API`` on a zone that still carries one (every zone
        created before this fix has ``DEFAULT``, which would rewrite the serial
        the PATCH below sends), then floors the SOA rrset in ``desired``
        against the SOA PowerDNS serves. Returns ``(problem, changed)``:
        what went wrong, or None, and whether the serial that will be served
        differs from the one served now (a NOTIFY is due).
        """
        problem, doc = self._read_soa(client, headers, zone_name)
        if problem:
            return problem, False
        served = _soa_from_zone_doc(doc, zone_name)
        # The key is always present on a real zone ("" once cleared); a reader
        # that does not carry it is not asked to clear anything.
        edit_api = doc.get("soa_edit_api") if isinstance(doc, dict) else None
        if edit_api:
            try:
                resp = client.put(
                    f"{_PDNS_API_BASE}/zones/{zone_name}",
                    headers=headers,
                    json={"soa_edit_api": ""},
                )
            except httpx.HTTPError as exc:
                return f"clear SOA-EDIT-API: {exc}", False
            if resp.status_code >= 400:
                return (
                    f"clear SOA-EDIT-API: HTTP {resp.status_code} {_pdns_error(resp)}",
                    False,
                )
            log.info("powerdns_soa_edit_api_cleared", zone=zone_name, was=edit_api)
        soa = next(
            (
                rs
                for rs in desired
                if rs.get("type") == "SOA"
                and str(rs.get("name") or "").lower().rstrip(".") == zone_name.lower().rstrip(".")
            ),
            None,
        )
        if soa is None or served is None:
            return None, False
        records = soa.get("records") or []
        if not records:
            return None, False
        want = records[0].get("content", "")
        sent = _floor_soa_content(want, served[0])
        if sent != want:
            log.info(
                "powerdns_soa_serial_floored",
                zone=zone_name,
                control_plane_serial=_soa_serial(want),
                served_serial=_soa_serial(served[0]),
                sent_serial=_soa_serial(sent),
            )
            records[0]["content"] = sent
        return None, _soa_serial(sent) != _soa_serial(served[0])

    def _read_soa(
        self, client: httpx.Client, headers: dict[str, str], zone_name: str
    ) -> tuple[str | None, Any]:
        """The zone as PowerDNS holds it, with only its apex SOA rrset."""
        try:
            resp = client.get(
                f"{_PDNS_API_BASE}/zones/{zone_name}?rrset_name={zone_name}&rrset_type=SOA",
                headers=headers,
            )
            doc = resp.json() if resp.status_code == 200 else None
        except (httpx.HTTPError, ValueError) as exc:
            return f"read SOA: {exc}", None
        if not isinstance(doc, dict):
            return f"read SOA: HTTP {resp.status_code} {_pdns_error(resp)}", None
        return None, doc

    def _send_notify(self, client: httpx.Client, headers: dict[str, str], zone: str) -> None:
        """Queue a NOTIFY now (#1967). PowerDNS sends one on its own cycle
        (``xfr-cycle-interval``, 60 s) once ``primary=yes``; this makes a
        change reach a secondary in seconds. Best-effort: the cycle is the
        safety net."""
        try:
            resp = client.put(f"{_PDNS_API_BASE}/zones/{zone}/notify", headers=headers)
            if resp.status_code >= 400:
                log.info(
                    "powerdns_notify_not_queued",
                    zone=zone,
                    status=resp.status_code,
                    body=resp.text[:200],
                )
        except httpx.HTTPError as exc:
            log.info("powerdns_notify_failed", zone=zone, error=str(exc))

    def _request_axfr(self, client: httpx.Client, headers: dict[str, str], zone: str) -> None:
        """Ask a secondary to transfer now rather than at its next refresh
        cycle (#1967). Best-effort, like ``_send_notify``."""
        try:
            resp = client.put(f"{_PDNS_API_BASE}/zones/{zone}/axfr-retrieve", headers=headers)
            if resp.status_code >= 400:
                log.info(
                    "powerdns_axfr_retrieve_not_queued",
                    zone=zone,
                    status=resp.status_code,
                    body=resp.text[:200],
                )
        except httpx.HTTPError as exc:
            log.info("powerdns_axfr_retrieve_failed", zone=zone, error=str(exc))

    def _forget_reached(self, zone: str) -> None:
        getattr(self, "_op_reached", {}).pop(zone.rstrip(".").lower(), None)

    def reached_serial(self, zone_name: str) -> int | None:
        """The serial a record op last brought ``zone_name`` to, or None.

        The sync loop reports this instead of the op's ``target_serial``:
        when PowerDNS already served a higher serial the zone moved on from
        THAT one (#1968), and the control plane learns it from the report."""
        return getattr(self, "_op_reached", {}).get(zone_name.rstrip(".").lower())

    def _apply_rrsets_singly(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone_name: str,
        action: str,
        first: httpx.Response,
        rrsets: list[dict[str, Any]],
        refused: list[str],
        failures: list[str],
    ) -> list[tuple[str, str]] | None:
        """Apply ``rrsets`` piecemeal, after PowerDNS refused them as one PATCH
        (#2060). Returns the ``(name, type)`` of each rrset that did not land
        (refused, or not attempted once the PATCH budget ran out), or None when
        the zone could not be applied at all (a status that is not a verdict on
        its data); the caller then skips the rest of that zone, as for any
        failed apply.

        The list is split in half and each half PATCHed; a half PowerDNS
        refuses is split again, down to single rrsets. So one bad rrset in a
        zone of N costs about ``2·log2(N)`` PATCHes rather than N — a reconcile
        re-sends every rrset of the zone, and this runs on every structural
        apply until the bad row is fixed. :data:`_PIECEMEAL_PATCH_BUDGET` caps
        the worst case (every rrset refused, i.e. the refusal was about the
        zone and not its data, costs ``2N``); what is left when it runs out is
        reported as not attempted.

        Order is kept — halves are applied left first — and the list is
        ordered deletes first, so a name changing type (A → CNAME) is free
        before its new rrset arrives, and the apex SOA last, so the serial
        moves only once the data it announces is there (in the same PATCH as
        the last of it at the earliest). A rrset that is only REPLACEd is one
        change, never a delete and an add, so no name is ever briefly absent.
        A refused rrset is recorded under the zone with PowerDNS's reason —
        the zone is still reported as refused, so the partial apply is
        visible — and every other rrset is served. If nothing is refused
        piecemeal, the zone is fully applied and nothing is reported.
        """
        url = f"{_PDNS_API_BASE}/zones/{zone_name}"
        deletes = [rs for rs in rrsets if rs.get("changetype") == "DELETE"]
        soas = [
            rs for rs in rrsets if rs.get("changetype") != "DELETE" and rs.get("type") == "SOA"
        ]
        rest = [
            rs for rs in rrsets if rs.get("changetype") != "DELETE" and rs.get("type") != "SOA"
        ]
        ordered = [
            rs if "changetype" in rs else {**rs, "changetype": "REPLACE"}
            for rs in [*deletes, *rest, *soas]
        ]
        refused_here: list[str] = []
        not_landed: list[tuple[str, str]] = []
        unattempted = 0
        patches = 0
        # Halves still to try, leftmost on top. The whole list was already
        # refused as one PATCH, so the first try is its two halves.
        stack: list[list[dict[str, Any]]] = []
        if len(ordered) > 1:
            mid = len(ordered) // 2
            stack = [ordered[mid:], ordered[:mid]]
        elif ordered:
            refused_here.append(
                f"{ordered[0].get('name')} {ordered[0].get('type')} ({_pdns_error(first)})"
            )
            not_landed.append(
                (str(ordered[0].get("name") or ""), str(ordered[0].get("type") or ""))
            )
        while stack:
            chunk = stack.pop()
            if patches >= _PIECEMEAL_PATCH_BUDGET:
                unattempted += len(chunk)
                not_landed.extend(
                    (str(rs.get("name") or ""), str(rs.get("type") or "")) for rs in chunk
                )
                continue
            patches += 1
            resp = client.patch(url, headers=headers, json={"rrsets": chunk})
            if resp.status_code < 400:
                continue
            if resp.status_code not in _ZONE_REFUSAL_STATUSES:
                self._zone_not_applied(zone_name, action, resp, refused, failures)
                return None
            if len(chunk) == 1:
                rs = chunk[0]
                not_landed.append((str(rs.get("name") or ""), str(rs.get("type") or "")))
                refused_here.append(f"{rs.get('name')} {rs.get('type')} ({_pdns_error(resp)})")
                continue
            mid = len(chunk) // 2
            stack.append(chunk[mid:])
            stack.append(chunk[:mid])
        log.warning(
            "powerdns_zone_applied_piecemeal",
            zone=zone_name,
            action=action,
            rrset_count=len(rrsets),
            patches=patches,
            refused=refused_here[:5],
            unattempted=unattempted,
            first_error=_pdns_error(first),
        )
        if refused_here or unattempted:
            more = f" (and {len(refused_here) - 5} more)" if len(refused_here) > 5 else ""
            skipped = (
                f"; {unattempted} not attempted (stopped after {patches} PATCHes)"
                if unattempted
                else ""
            )
            refused.append(
                f"{zone_name} {action}: HTTP {first.status_code} {_pdns_error(first)}; "
                f"applied the other {len(rrsets) - len(not_landed)} of {len(rrsets)} "
                "rrset change(s) piecemeal, refused: "
                + ("; ".join(refused_here[:5]) or "none")
                + more
                + skipped
            )
        return not_landed

    @staticmethod
    def _zone_not_applied(
        zone_name: str,
        action: str,
        resp: httpx.Response,
        refused: list[str],
        failures: list[str],
    ) -> None:
        """Sort a refused create / PATCH into a per-zone refusal of its data
        or a failure of the apply (see ``_ZONE_REFUSAL_STATUSES``)."""
        log.error(
            f"powerdns_zone_{action}_failed",
            zone=zone_name,
            status=resp.status_code,
            body=resp.text[:200],
        )
        if resp.status_code in _ZONE_REFUSAL_STATUSES:
            refused.append(f"{zone_name} {action}: HTTP {resp.status_code} {_pdns_error(resp)}")
        else:
            failures.append(f"{zone_name} {action}: HTTP {resp.status_code} {_pdns_error(resp)}")

    # ── NOTIFY settings (issue #1523) ─────────────────────────────────────

    def _apply_notify_settings(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone_payload: dict[str, Any],
    ) -> str | None:
        """Set (or clear) a primary zone's ALSO-NOTIFY metadata (#1523).

        The kind decision (Master vs Native) happens in render(); this is
        the target list. An empty effective list clears the metadata so
        removed targets stop being notified. Secondaries do not notify
        their primaries, so they are skipped. Returns what went wrong, or
        None, so a target list PowerDNS refused fails the apply like the
        dynamic-update metadata does (#1225) instead of looking applied.
        """
        if _kind_category(zone_payload.get("kind")) not in ("native", "primary"):
            return None
        targets = _also_notify_targets(zone_payload.get("also_notify"))
        return self._put_metadata(client, headers, zone_payload["name"], "ALSO-NOTIFY", targets)

    # ── Zone transfers out (issue #1967) ───────────────────────────────────

    def _apply_transfer_acl(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone_payload: dict[str, Any],
        *,
        tsig_seen: set[str] | None = None,
    ) -> list[str]:
        """Set (or clear) who may AXFR the zone from this server.

        ``ALLOW-AXFR-FROM`` (subnets) + ``TSIG-ALLOW-AXFR`` (key names, each
        imported first). A payload without the keys — one rendered before
        this existed — is left alone. Returns what PowerDNS refused, so a
        grant that did not land fails the apply instead of looking applied.
        """
        if "axfr_from" not in zone_payload:
            return []
        zone = zone_payload["name"]
        problems: list[str] = []
        key_names: list[str] = []
        for k in zone_payload.get("axfr_tsig_keys") or []:
            key_name = (k.get("name") or "").rstrip(".")
            if not key_name:
                continue
            key_names.append(key_name)
            if tsig_seen is not None:
                if key_name in tsig_seen:
                    continue
                tsig_seen.add(key_name)
            problem = self._ensure_tsigkey(client, headers, k)
            if problem:
                problems.append(problem)
        for kind, values in (
            ("ALLOW-AXFR-FROM", list(zone_payload.get("axfr_from") or [])),
            ("TSIG-ALLOW-AXFR", key_names),
        ):
            problem = self._put_metadata(client, headers, zone, kind, values)
            if problem:
                problems.append(problem)
        return problems

    # ── Dynamic-update ACLs (issue #641) ───────────────────────────────────

    def _apply_dynamic_update(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone_payload: dict[str, Any],
        *,
        tsig_seen: set[str] | None = None,
    ) -> list[str]:
        """Set (or clear) a zone's RFC 2136 dynamic-update metadata.

        PowerDNS is coarse-only: ``ALLOW-DNSUPDATE-FROM`` (grant IP/CIDRs) +
        ``TSIG-ALLOW-DNSUPDATE`` (grant TSIG key names, imported first). An
        empty ACL clears both so a zone whose dynamic updates were turned off
        stops accepting them.

        Returns what PowerDNS refused, for the caller to fail the apply with
        after the other zones are done (#1225). This used to be best-effort,
        which meant a failed CLEAR left a zone accepting updates the operator
        had turned off while the apply reported ``ok``.

        ``tsig_seen`` names keys already imported during this reconcile; they
        are skipped here, and so is their outcome, which was reported once.
        """
        zone = zone_payload["name"]
        acl = zone_payload.get("update_acl") or []
        ip_from = [
            e["ip_cidr"]
            for e in acl
            if e.get("action") == "grant"
            and e.get("match_kind") == "ip"
            and e.get("ip_cidr")
        ]
        key_names = [
            e["tsig_key_name"].rstrip(".")
            for e in acl
            if e.get("action") == "grant"
            and e.get("match_kind") == "tsig_key"
            and e.get("tsig_key_name")
        ]
        problems: list[str] = []
        for k in zone_payload.get("update_tsig_keys") or []:
            key_name = (k.get("name") or "").rstrip(".")
            if tsig_seen is not None:
                if key_name in tsig_seen:
                    continue
                tsig_seen.add(key_name)
            problem = self._ensure_tsigkey(client, headers, k)
            if problem:
                problems.append(problem)
        for kind, values in (
            ("ALLOW-DNSUPDATE-FROM", ip_from),
            ("TSIG-ALLOW-DNSUPDATE", key_names),
        ):
            problem = self._put_metadata(client, headers, zone, kind, values)
            if problem:
                problems.append(problem)
        return problems

    def _ensure_tsigkey(
        self, client: httpx.Client, headers: dict[str, str], key: dict[str, Any]
    ) -> str | None:
        """Import a TSIG key into pdns (idempotent). Returns what went wrong,
        or None."""
        name = (key.get("name") or "").rstrip(".")
        secret = key.get("secret")
        if not name or not secret:
            return None
        body = {
            "name": name,
            "algorithm": key.get("algorithm") or "hmac-sha256",
            "key": secret,
        }
        try:
            post = client.post(f"{_PDNS_API_BASE}/tsigkeys", headers=headers, json=body)
            resp = post
            if post.status_code in (409, 422):
                # Already present — PUT in case the secret rotated. pdns keys
                # the TSIG key by its (dot-stripped) name, so no trailing dot.
                resp = client.put(
                    f"{_PDNS_API_BASE}/tsigkeys/{name}", headers=headers, json=body
                )
            if resp.status_code >= 400:
                log.warning(
                    "powerdns_tsigkey_import_failed",
                    key=name,
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                problem = f"TSIG key {name}: HTTP {resp.status_code} {_pdns_error(resp)}"
                if resp is not post and post.status_code == 422:
                    # A 422 is also how pdns refuses a key it will not store
                    # (bad algorithm, bad secret); the PUT then answers 404
                    # for a key that does not exist, which hides that reason.
                    problem += f" (create: HTTP 422 {_pdns_error(post)})"
                return problem
        except httpx.HTTPError as exc:
            log.warning("powerdns_tsigkey_import_error", key=name, error=str(exc))
            return f"TSIG key {name}: {exc}"
        return None

    def _put_metadata(
        self,
        client: httpx.Client,
        headers: dict[str, str],
        zone: str,
        kind: str,
        values: list[str],
    ) -> str | None:
        """PUT (replace) or DELETE (when empty) a zone metadata kind.
        Returns what went wrong, or None."""
        try:
            if values:
                resp = client.put(
                    f"{_PDNS_API_BASE}/zones/{zone}/metadata/{kind}",
                    headers=headers,
                    json={"kind": kind, "metadata": values},
                )
            else:
                resp = client.delete(
                    f"{_PDNS_API_BASE}/zones/{zone}/metadata/{kind}", headers=headers
                )
            # 404 on DELETE (metadata absent) is a benign no-op.
            if resp.status_code >= 400 and resp.status_code != 404:
                log.warning(
                    "powerdns_metadata_failed",
                    zone=zone,
                    kind=kind,
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                return f"{kind}: HTTP {resp.status_code} {_pdns_error(resp)}"
        except httpx.HTTPError as exc:
            log.warning("powerdns_metadata_error", zone=zone, kind=kind, error=str(exc))
            return f"{kind}: {exc}"
        return None

    # ── Reload (compatibility with bind9 daemon-pid signal pattern) ────────

    def unconverged_zones(self) -> set[str]:
        """Zones (lowercase, no trailing dot) the last apply could not serve
        whole: every zone in :meth:`refused_zones` (#2060).

        Since a refused zone's other rrsets land piecemeal, SOA last, such a
        zone can serve the bundle's serial with a record missing; the sync
        loop leaves these out of the zone-state report so they do not read
        converged. Each refusal this driver records starts with the zone's
        name (``"<zone> <action>: …"``), and a zone name holds no space.
        """
        return {r.split(" ", 1)[0].rstrip(".").lower() for r in self._refused_zones if r}

    def served_zone_serials(self, bundle: dict[str, Any]) -> dict[str, int]:
        """Zone name (no trailing dot, lowercased) → the serial pdns serves.

        The sync loop's zone-state reporter uses this instead of the
        bundle's serials (#1522): reporting the bundle serial made
        per-server sync status read "in sync" whatever pdns served, and
        it reported zones the agent never served at all (forward zones,
        #1521). A zone absent from the map is simply not reported. An
        unreadable API returns an empty map — report nothing rather
        than something unverified.
        """
        api_key = self._load_or_generate_api_key()
        try:
            with httpx.Client(timeout=_PDNS_API_TIMEOUT) as client:
                resp = client.get(
                    f"{_PDNS_API_BASE}/zones", headers={"X-API-Key": api_key}
                )
            if resp.status_code >= 400:
                log.warning("powerdns_served_serials_http", status=resp.status_code)
                return {}
            zones = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("powerdns_served_serials_failed", error=str(exc))
            return {}
        out: dict[str, int] = {}
        for z in zones or []:
            if not isinstance(z, dict) or not z.get("name"):
                continue
            serial = z.get("serial")
            if isinstance(serial, bool) or not isinstance(serial, int):
                continue
            # Lowercased: PowerDNS stores zone names lowercased, and the
            # bundle may carry another spelling (``Case.Test.``).
            out[str(z["name"]).rstrip(".").lower()] = serial
        return out

    def _reload_via_api(self) -> None:
        """Optional — issue a notify on every zone after a bulk
        change. PowerDNS is master-only by default; this only matters
        when secondaries are configured. Currently unused but kept
        as a hook for Phase 2 supermaster wiring.
        """
        if self.daemon_pid:
            try:
                os.kill(self.daemon_pid, signal.SIGUSR1)
            except OSError as exc:
                log.warning("pdns_sigusr1_failed", error=str(exc))
