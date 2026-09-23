"""BIND9 agent driver.

Renders ``named.conf`` and zone files under ``/var/lib/spatium-dns-agent/rendered``,
validates with ``named-checkconf``, atomically swaps, and reloads via ``rndc``.
Record ops are applied via ``nsupdate`` over loopback, authenticated with the
TSIG key carried in the config bundle.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import structlog

try:
    import dns.query
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.tsigkeyring
    import dns.update
except ImportError:  # pragma: no cover - runtime-optional
    dns = None  # type: ignore[assignment]

from ._process import (
    find_running_daemon,
    is_zombie,
    spawn_guard,
    wait_for_daemon,
)
from .base import RRSET_OP_KINDS, DriverBase

log = structlog.get_logger(__name__)

NAMED_CONF_SKELETON = """\
{acl_statements}{tls_statements}options {{
    directory "/var/cache/bind";
    listen-on {{ any; }};
    listen-on-v6 {{ any; }};
{encrypted_listeners}    recursion {recursion};
    allow-query {{ {allow_query}; }};
    {allow_transfer}
    dnssec-validation {dnssec};
    key-directory "/var/cache/bind/keys";
    check-integrity no;
{response_log}{forwarders}{response_policy}{rate_limit}
}};
statistics-channels {{
    inet 127.0.0.1 port 8053 allow {{ 127.0.0.1; }};
}};
{logging_block}{tsig_include}"""

# Query-log channel + category block. Path matches the QueryLogShipper
# default (``/var/log/named/queries.log``) so the shipper can tail the
# same file the daemon writes — the entrypoint script chowns this
# directory to the unprivileged ``spatium`` user at boot. Severity +
# print-* defaults match ``DNSServerOptions``' column defaults; we
# don't plumb the per-field overrides through the agent yet because
# the operator-facing UI surfaces the boolean toggle only.
_QUERY_LOG_HEAD = """\
logging {
    channel queries_channel {
        file "/var/log/named/queries.log" versions 5 size 50m;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    };
    category queries { queries_channel; };
    category query-errors { queries_channel; };
"""

# RPZ policy hits (issue #699). named logs a rewrite to its OWN ``rpz``
# category, never to ``queries`` — so without these two lines a blocked
# lookup is invisible to the control plane and every per-client
# attribution the feature exists for reports nothing. The control-plane
# Jinja template has carried them since #699; this renderer, which is
# what every agent-managed BIND9 server actually runs, did not, so the
# ingest's RPZ branch had nothing to parse (issue #914).
#
# PASSTHRU — an exception firing, i.e. an explicit ALLOW — goes to a
# SEPARATE category, so it needs its own line or the passthru half of
# the attribution stays dark and the ``policy != PASSTHRU`` filters in
# services/dns_threat/rpz.py are dead code. Verified against BIND 9.20.
_RPZ_LOG_CATEGORIES = """\
    category rpz { queries_channel; };
    category rpz-passthru { queries_channel; };
"""

# Response logging (issue #914) — the RCODE and section counts, on a
# second line per query. Routed to the same channel for the same reason
# RPZ is: the shipper already tails this file, so no second thread, file
# or bind mount is needed, and the control plane tells the shapes apart
# at ingest.
_RESPONSE_LOG_CATEGORY = """\
    category responses { queries_channel; };
"""


def _render_logging_block(opts: dict[str, Any]) -> str:
    """The ``logging { ... }`` statement, or empty when logging is off.

    Response logging is nested inside the query-log gate rather than
    standing on its own: the responses ride the ``queries_channel`` this
    block defines, and the shipper tails the file that channel writes —
    so enabling responses without queries would define nothing to log to
    and ship nothing. The control plane refuses that combination with a
    422; this is the renderer-side half of the same rule.
    """
    if not bool(opts.get("query_log_enabled")):
        return ""
    block = _QUERY_LOG_HEAD + _RPZ_LOG_CATEGORIES
    if bool(opts.get("response_log_enabled")):
        block += _RESPONSE_LOG_CATEGORY
    return block + "};\n"


def _render_response_log_option(opts: dict[str, Any]) -> str:
    """``responselog yes;`` inside ``options``, or nothing.

    Two switches, not one: the ``responses`` category says WHERE the
    lines go, ``responselog`` says whether named emits them at all.
    Rendering only the category would leave the operator with a toggle
    that changes named.conf and produces no data.
    """
    if bool(opts.get("query_log_enabled")) and bool(opts.get("response_log_enabled")):
        return "    responselog yes;\n"
    return ""


def _render_allow_update(zone: dict[str, Any], group_key_name: str | None) -> str:
    """Build the ``allow-update { ... };`` clause for a primary zone (issue #641).

    The internal agent loopback grant (the group TSIG key) is ALWAYS
    included so control-plane record ops keep flowing over loopback. When
    the operator enabled dynamic updates, the per-zone ACL entries — source
    CIDRs and named TSIG keys — are appended. P1 renders the coarse
    address-match-list only: ``grant`` entries by ``ip_cidr`` / key name.
    ``deny`` + name-scoped + per-type entries belong to the P2
    ``update-policy`` path and are skipped here (the control plane blocks
    them from ever reaching a coarse render via the driver capability gate).

    Returns "" (no clause) only when there's no group key AND no operator
    grants — i.e. a zone with dynamic updates off and no loopback key.
    """
    items: list[str] = []
    seen_keys: set[str] = set()
    if group_key_name:
        items.append(f'key "{group_key_name}";')
        seen_keys.add(group_key_name)
    if zone.get("dynamic_update_enabled"):
        for e in zone.get("update_acl") or []:
            if e.get("action") != "grant":
                continue
            if e.get("name_scope") or e.get("name_pattern") or e.get("record_types"):
                continue
            kind = e.get("match_kind")
            if kind == "ip" and e.get("ip_cidr"):
                items.append(f'{e["ip_cidr"]};')
            elif kind == "tsig_key" and e.get("tsig_key_name"):
                name = e["tsig_key_name"]
                if name in seen_keys:
                    continue
                seen_keys.add(name)
                items.append(f'key "{name}";')
    if not items:
        return ""
    return f'allow-update {{ {" ".join(items)} }}; '


def _transfer_key_grants(tsig_keys: list[dict[str, Any]]) -> list[str]:
    """``key "name";`` items for every TSIG key in the bundle (issue #734).

    These are what make a zone transfer possible at all on an appliance.
    ``allow-transfer`` defaults to ``none``, and the control plane cannot be
    granted by address — behind an HA VIP the request can arrive from any
    control-plane node, and on the appliance the address isn't knowable at
    render time. So the grant is by key, which is also strictly narrower:
    an address ACL admits anyone who can spoof/occupy the address, a key
    admits only a holder of the secret.

    Every key is granted rather than just the first, so the control plane's
    choice of which one to sign with (``resolve_group_transfer_key``) can
    never disagree with what was granted.
    """
    out: list[str] = []
    seen: set[str] = set()
    for k in tsig_keys or []:
        name = (k.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(f'key "{name}";')
    return out


def _view_transfer_keys(views: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """``{view name: key}`` for every view the bundle gives a transfer key (#920).

    Under split-horizon BIND picks the view for a request BEFORE it looks at
    ``allow-transfer``, and it picks by ``match-clients`` — which the operator
    fills with the clients each view is for. The control plane's own zone
    transfers (the drift report, sync-with-servers) come from wherever the api
    runs, an address no operator lists and nobody can know at render time. So
    on a view that does not happen to admit that address the signed transfer
    selects no view at all, and BIND answers it BADKEY — "the key is unknown",
    for a key that is loaded and granted. On a broad view that does admit it,
    the transfer is answered from that view's copy, which is the wrong copy
    whenever the zone lives in another view.

    ``match-clients`` can select by TSIG key as well as by address, so each
    view carries a key of its own (derived by the control plane from the
    group's key, never typed by anyone) that selects exactly that view. A view
    without one — a bundle from a control plane that predates it — renders as
    before.
    """
    out: dict[str, dict[str, Any]] = {}
    for view in views or []:
        name = view.get("name") or ""
        key = view.get("transfer_key")
        if name and isinstance(key, dict) and key.get("name") and key.get("secret"):
            out[name] = key
    return out


def _render_match_clients(view: dict[str, Any], view_keys: dict[str, dict[str, Any]]) -> str:
    """The body of one view's ``match-clients { … }`` (#920).

    Order is the whole point, because BIND takes the first element that
    matches. This view's own transfer key selects it. Every OTHER view's
    transfer key is refused, so an earlier view whose client list happens to
    match the control plane's address (an ``any`` catch-all, a 10/8) cannot
    capture a transfer meant for a later one. Then the operator's own list,
    exactly as before: a request carrying none of these keys — every client,
    every DDNS update, every transfer an operator runs — is decided by the
    operator's list alone, as it always was.
    """
    vname = view.get("name") or ""
    items: list[str] = []
    own = view_keys.get(vname)
    if own is not None:
        items.append(f'key "{own["name"]}"')
    items += [f'!key "{k["name"]}"' for name, k in view_keys.items() if name != vname]
    items += [str(c) for c in (view.get("match_clients") or ["any"])]
    return "; ".join(items)


def _render_allow_transfer(
    acl: list[Any] | None,
    key_grants: list[str],
) -> str:
    """Build an ``allow-transfer { ... };`` clause (issue #734).

    ``acl`` is the operator's own list in BIND's vocabulary (``["any"]``,
    ``["10.0.0.0/8", "192.0.2.1"]``, ``["none"]``, …) from
    ``DNSServerOptions.allow_transfer`` or a zone's override. Both were
    settable in the UI and persisted, but nothing ever rendered them — the
    operator got a 200 and silence.

    The key grants are unioned in unconditionally, INCLUDING when the ACL
    says ``none``. That is deliberate: ``none`` is the default, so honouring
    it literally would lock the control plane out of every zone on a stock
    install and re-break drift the moment this shipped. ``none`` is dropped
    from the rendered list when anything else is present — as an address
    match it never matches, so it is pure noise.
    """
    items = list(key_grants)
    for entry in acl or []:
        token = str(entry).strip()
        if not token or token.lower() == "none":
            continue
        items.append(f"{token};")
    if not items:
        return "allow-transfer { none; }; "
    return f'allow-transfer {{ {" ".join(items)} }}; '


_UPDATE_POLICY_NAMED_SCOPES = frozenset({"subdomain", "name", "wildcard", "self"})


def _zone_needs_update_policy(zone: dict[str, Any]) -> bool:
    """True when the ACL needs BIND's fine-grained ``update-policy`` clause
    (issue #641 P2) — any grant carries a name scope, a per-type restriction,
    or is a ``deny``. Otherwise the coarse ``allow-update`` clause is used.
    """
    if not zone.get("dynamic_update_enabled"):
        return False
    for e in zone.get("update_acl") or []:
        if (
            e.get("action") == "deny"
            or e.get("name_scope")
            or e.get("name_pattern")
            or e.get("record_types")
        ):
            return True
    return False


def _render_update_policy(zone: dict[str, Any], group_key_name: str | None) -> str:
    """Build the ``update-policy { ... };`` clause for a fine-grained zone.

    TSIG-identity only (IP entries can't be expressed and are rejected at the
    control plane, so they're skipped defensively here). The group loopback
    key is always granted the whole zone so the agent's own record ops keep
    flowing. Each operator entry renders as
    ``<grant|deny> <keyname> <ruletype> [<name>] [<types>];`` — the type list
    is omitted when unrestricted (BIND then allows the standard rrtype set).
    """
    lines: list[str] = []
    if group_key_name:
        lines.append(f"grant {group_key_name} zonesub;")
    for e in zone.get("update_acl") or []:
        if e.get("match_kind") != "tsig_key" or not e.get("tsig_key_name"):
            continue
        action = "deny" if e.get("action") == "deny" else "grant"
        identity = e["tsig_key_name"]
        scope = e.get("name_scope") or "zonesub"
        types = " ".join(str(t) for t in (e.get("record_types") or []) if t)
        type_suffix = f" {types}" if types else ""
        if scope in _UPDATE_POLICY_NAMED_SCOPES:
            name = (e.get("name_pattern") or "").strip()
            if not name:
                continue  # required by validation; skip defensively
            lines.append(f"{action} {identity} {scope} {name}{type_suffix};")
        else:  # zonesub (default) — whole zone, no name
            lines.append(f"{action} {identity} zonesub{type_suffix};")
    if not lines:
        return ""
    return f'update-policy {{ {" ".join(lines)} }}; '


def _redirect_rdata(target: str) -> str | None:
    """RPZ local-data for a ``redirect`` entry, chosen by target kind.

    A redirect target is "the IP or hostname to return instead", and the
    two need different record types: an IP has to be an A/AAAA, a name
    has to be a CNAME. Emitting ``CNAME 1.2.3.4.`` for an IP yields a
    CNAME pointing at a name that does not exist, so the redirect
    silently resolves to nothing — the failure mode is invisible until
    someone queries the domain.

    Returns None for a target that cannot be a domain name, so the
    caller can drop the entry. ``target`` is free-form on the API and
    reaches here unvalidated; whitespace would split the rdata into
    extra fields and an empty label is malformed, and either makes BIND
    refuse the whole zone rather than just that record. Same
    defend-at-the-render-boundary reasoning as ``strip_control_chars``
    on the domain side (#597). Note that odd-but-parseable targets — a
    pasted URL, ``host:8080`` — do load, so they are left alone here
    rather than second-guessed.

    Used by SafeSearch enforcement (#878), whose targets are hostnames,
    and by any operator redirect pointing at a sinkhole web server.
    """
    text = target.strip()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        name = text.rstrip(".")
        if not name or any(c.isspace() for c in name) or ".." in name:
            return None
        return f"CNAME {name}."
    return f"{'AAAA' if ip.version == 6 else 'A'} {ip}"


def _render_rate_limit_block(opts: dict[str, Any]) -> str:
    """Build the named.conf RRL + amplification directives from bundle opts
    (issue #146). Returns "" (no-op) unless something is enabled/set, so the
    options{} block is byte-identical for groups that haven't opted in.

    Emitted inside ``options {}``: ``minimal-responses``, ``tcp-clients``,
    ``clients-per-query``, ``max-clients-per-query`` (each only when set), and
    the ``rate-limit { … }`` stanza (only when ``rrl_enabled``)."""
    lines: list[str] = []
    if opts.get("minimal_responses"):
        lines.append("    minimal-responses yes;")
    for key, directive in (
        ("tcp_clients", "tcp-clients"),
        ("clients_per_query", "clients-per-query"),
        ("max_clients_per_query", "max-clients-per-query"),
    ):
        val = opts.get(key)
        if val is not None:
            lines.append(f"    {directive} {int(val)};")
    if opts.get("rrl_enabled"):
        rrl = [
            "    rate-limit {",
            f"        responses-per-second {int(opts.get('rrl_responses_per_second', 15))};",
            f"        window {int(opts.get('rrl_window', 15))};",
            f"        slip {int(opts.get('rrl_slip', 2))};",
        ]
        if opts.get("rrl_qps_scale") is not None:
            rrl.append(f"        qps-scale {int(opts['rrl_qps_scale'])};")
        exempt = [
            c.strip()
            for c in (opts.get("rrl_exempt_clients") or [])
            if isinstance(c, str) and c.strip()
        ]
        if exempt:
            rrl.append("        exempt-clients { " + "; ".join(exempt) + "; };")
        if opts.get("rrl_log_only"):
            rrl.append("        log-only yes;")
        rrl.append("    };")
        lines.extend(rrl)
    return ("\n" + "\n".join(lines)) if lines else ""


# ── Encrypted transports (issue #50) ────────────────────────────────────────
# Stable on-disk paths for the listener cert. Written outside ``rendered.new``
# (like the TSIG key) so the atomic rendered-dir swap can't leave named.conf
# pointing at a path that's mid-rename.
TLS_DIR_NAME = "tls"
TLS_CERT_FILENAME = "listener.crt"
TLS_KEY_FILENAME = "listener.key"

# named.conf identifiers for the tls/http statements we generate. Prefixed so
# they can't collide with anything an operator ever gets to name.
_LOCAL_TLS_ID = "spatium-local-tls"
_LOCAL_HTTP_ID = "spatium-local-http"
_UPSTREAM_TLS_ID = "spatium-upstream-tls"

# CA bundle shipped by Alpine's ca-certificates package (installed in the
# bind9 agent image) — used to validate the UPSTREAM's certificate when
# forwarding over DoT with verification on.
_CA_BUNDLE_PATH = "/etc/ssl/certs/ca-certificates.crt"

# Protocol floor applied to both the listener and the upstream statement.
# Also keeps the ``tls`` block non-empty in the opportunistic-DoT case
# (verification off ⇒ no ca-file / remote-hostname), which BIND rejects.
_TLS_PROTOCOLS_LINE = "    protocols { TLSv1.2; TLSv1.3; };"


def _dot_listener_active(opts: dict[str, Any], has_cert: bool) -> bool:
    return bool(opts.get("dot_enabled")) and has_cert


def _doh_listener_active(opts: dict[str, Any], has_cert: bool) -> bool:
    return bool(opts.get("doh_enabled")) and has_cert


def _forward_over_tls(opts: dict[str, Any]) -> bool:
    return (opts.get("forward_transport") or "do53") == "tls"


def _render_acl_statements(acls: list[dict[str, Any]] | None) -> str:
    """``acl "name" { … };`` blocks for the group's named ACLs (issue #899).

    These come FIRST in named.conf, ahead of ``options``, because BIND
    resolves an ``acl`` statement where it is written: a reference to one
    declared later in the file is an error, not a forward declaration. The
    control plane already emits the list dependency-ordered (an ACL may
    reference another), so this renders it as given.

    Until #899 the bundle carried ``{id, name}`` with no entries and this
    function did not exist — an ACL an operator created on the ACLs tab was
    stored, listed, editable, and applied to nothing. Worse, naming one
    anywhere that reached named.conf left an undefined symbol, so
    ``named-checkconf`` failed and the whole bundle was declined.

    An ACL with no usable entries renders as ``{ none; }`` rather than
    being skipped. Skipping looks tidier and is wrong: the name may already
    be cited by a view or another ACL, and dropping the definition
    re-creates the undefined-symbol outage this whole change exists to
    remove. ``none`` is also the honest meaning of an empty address-match
    list — it matches nothing.
    """
    out = []
    for acl in acls or []:
        name = str(acl.get("name") or "").strip()
        if not name:
            continue
        items = ""
        for e in acl.get("entries") or []:
            value = str(e.get("value", "")).strip()
            if not value:
                continue
            # The control plane stores negation as a flag, but an operator
            # pasting "!10.0.0.0/8" into the entry value is equally valid.
            # Rendering both would emit "!!10.0.0.0/8", which BIND rejects.
            negated = bool(e.get("negate")) or value.startswith("!")
            items += f"{'!' if negated else ''}{value.lstrip('!').strip()}; "
        out.append(f'acl "{name}" {{ {items or "none; "}}};\n')
    return "".join(out)


def _render_tls_statements(
    opts: dict[str, Any], state_dir: Path, has_cert: bool
) -> str:
    """Top-level ``tls`` / ``http`` statements for the encrypted transports.

    Returns "" when nothing is enabled so an install that never opted in
    renders a byte-identical named.conf.

    ``has_cert`` is deliberately separate from the operator's enable flags:
    the cert lives in ``appliance_certificate`` with ``ON DELETE SET NULL``,
    so it can vanish while the flags stay on. Emitting a ``tls`` block whose
    ``cert-file`` doesn't exist makes named refuse to start — losing Do53
    too. Degrading to Do53-only is the safe failure direction.
    """
    blocks: list[str] = []

    if _dot_listener_active(opts, has_cert) or _doh_listener_active(opts, has_cert):
        cert_path = state_dir / TLS_DIR_NAME / TLS_CERT_FILENAME
        key_path = state_dir / TLS_DIR_NAME / TLS_KEY_FILENAME
        blocks.append(
            f"tls {_LOCAL_TLS_ID} {{\n"
            f'    cert-file "{cert_path}";\n'
            f'    key-file "{key_path}";\n'
            f"{_TLS_PROTOCOLS_LINE}\n"
            f"}};\n"
        )

    if _doh_listener_active(opts, has_cert):
        path = (opts.get("doh_path") or "/dns-query").strip()
        blocks.append(
            f'http {_LOCAL_HTTP_ID} {{\n    endpoints {{ "{path}"; }};\n}};\n'
        )

    if _forward_over_tls(opts):
        lines = [f"tls {_UPSTREAM_TLS_ID} {{"]
        # Strict validation needs BOTH a trust store to chain against and a
        # name to match. The control plane refuses verify-on without a
        # hostname, but re-check here — the agent must never silently
        # downgrade a config it can't render faithfully.
        hostname = (opts.get("forward_tls_hostname") or "").strip()
        if opts.get("forward_tls_verify", True) and hostname:
            lines.append(f'    ca-file "{_CA_BUNDLE_PATH}";')
            lines.append(f'    remote-hostname "{hostname}";')
        lines.append(_TLS_PROTOCOLS_LINE)
        lines.append("};\n")
        blocks.append("\n".join(lines))

    return ("\n".join(blocks) + "\n") if blocks else ""


def _render_encrypted_listeners(opts: dict[str, Any], has_cert: bool) -> str:
    """``listen-on`` clauses for DoT / DoH, rendered inside ``options {}``.

    Additive — the plain ``listen-on { any; }`` pair above these stays, so
    Do53 clients are unaffected by turning an encrypted transport on.
    """
    lines: list[str] = []
    if _dot_listener_active(opts, has_cert):
        port = int(opts.get("dot_port", 853))
        for directive in ("listen-on", "listen-on-v6"):
            lines.append(f"    {directive} port {port} tls {_LOCAL_TLS_ID} {{ any; }};")
    if _doh_listener_active(opts, has_cert):
        port = int(opts.get("doh_port", 443))
        for directive in ("listen-on", "listen-on-v6"):
            lines.append(
                f"    {directive} port {port} tls {_LOCAL_TLS_ID} "
                f"http {_LOCAL_HTTP_ID} {{ any; }};"
            )
    return ("\n".join(lines) + "\n") if lines else ""


def _format_forwarder(entry: str, opts: dict[str, Any]) -> str:
    """Render one ``forwarders`` token, honouring the upstream transport.

    Accepts ``ip`` or ``ip@port`` (the control-plane wire shape, same as
    ``_format_master``). Previously the raw string was emitted verbatim,
    which rendered an unloadable ``1.1.1.1@853;`` for any entry that carried
    a port.

    Over DoT the port defaults to 853 (RFC 7858) rather than 53, so an
    operator who flips the transport without editing every forwarder gets a
    working config instead of a TLS handshake against a Do53 port.
    """
    ip, _, port = entry.strip().partition("@")
    ip = ip.strip()
    port = port.strip()
    over_tls = _forward_over_tls(opts)
    if not port.isdigit():
        port = "853" if over_tls else ""
    out = ip
    if port:
        out += f" port {port}"
    if over_tls:
        out += f" tls {_UPSTREAM_TLS_ID}"
    return out


def _lifetime(days: int) -> str:
    """BIND ``lifetime`` token — 0 ⇒ unlimited, else ``<days>d``."""
    return "unlimited" if not days else f"{int(days)}d"


def _format_master(entry: str) -> str:
    """Render one secondary/stub master entry as a BIND9 ``masters`` token.

    Accepts ``ip`` or ``ip@port`` (the control-plane wire shape, matching
    the forwarders convention) and emits ``<ip>`` or ``<ip> port <n>``.
    A non-numeric / malformed port suffix is dropped — better to AXFR
    from the default port 53 than to render an un-loadable stanza.
    """
    entry = entry.strip()
    if "@" in entry:
        ip, _, port = entry.partition("@")
        ip = ip.strip()
        port = port.strip()
        if port.isdigit():
            return f"{ip} port {port}"
        return ip
    return entry


def _parses_as_rdata(rtype: str, wire: str) -> bool:
    """Whether dnspython can read ``wire`` as rdata of ``rtype``.

    Used to keep one unreadable sibling from failing a whole-RRset write. Any
    exception counts as "no" — ``from_text`` raises a different type per rdata
    class (SyntaxError, ValueError, dns.exception.*), and the only thing worth
    knowing here is whether the value is usable.
    """
    try:
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), wire)
    except Exception:  # noqa: BLE001 — see docstring: any failure means unusable
        return False
    return True


def _wire_value(rtype: str, value: str, fields: dict[str, Any]) -> str:
    """Compose one RR's presentation form from a record-op payload.

    MX / SRV wire-format requires the priority (and weight+port) to appear
    inline before the target. The control plane stores those as separate
    columns and, historically, only forwarded ``value``. Prefer the explicit
    fields; fall back to the raw value if an already-composed wire string came
    through (legacy path + future-proofing).

    Shared by the op's own record and by every member of the RRset that op
    carries (#773), so a multi-value MX or SRV composes identically either way.
    """
    rtype_u = rtype.upper()
    if rtype_u == "MX":
        pri = fields.get("priority")
        if pri is not None and not value.lstrip().split(" ", 1)[0].isdigit():
            return f"{pri} {value}"
    elif rtype_u == "SRV":
        pri = fields.get("priority")
        wt = fields.get("weight")
        prt = fields.get("port")
        if (
            pri is not None
            and wt is not None
            and prt is not None
            and len(value.split()) < 4
        ):
            return f"{pri} {wt} {prt} {value}"
    return value


# DNSSEC algorithm name → IANA number (issue #49). Used when parsing
# ``rndc dnssec -status`` output, which prints the algorithm by name.
_DNSSEC_ALGO_NUM: dict[str, int] = {
    "RSASHA256": 8,
    "RSASHA512": 10,
    "ECDSAP256SHA256": 13,
    "ECDSAP384SHA384": 14,
    "ED25519": 15,
    "ED448": 16,
}


def _parse_dnssec_status(text: str) -> list[dict[str, Any]]:
    """Parse ``rndc dnssec -status <zone>`` into per-key state dicts.

    The header line ``key: <tag> (<ALGO>), <KSK|ZSK|CSK>`` is stable across
    BIND versions; the per-key body varies, so we derive a coarse state
    ("active" once the key is signing, else "published") + keep the raw
    timing lines. Pure + version-tolerant so it's unit-testable.
    """
    keys: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"key:\s+(\d+)\s+\(([^)]+)\),\s+(KSK|ZSK|CSK)", line)
        if m:
            if cur is not None:
                keys.append(cur)
            cur = {
                "key_tag": int(m.group(1)),
                "algorithm": _DNSSEC_ALGO_NUM.get(m.group(2).upper(), 0),
                "key_type": m.group(3).lower(),
                "state": "published",
                "ds_records": [],
                "timing": {},
            }
            continue
        if cur is None:
            continue
        low = line.lower()
        if ("key signing:" in low or "zone signing:" in low) and "yes" in low:
            cur["state"] = "active"
        mt = re.match(
            r"(published|active|retire|remove|key signing|zone signing):\s*(.+)", low
        )
        if mt:
            cur["timing"][mt.group(1).replace(" ", "_")] = mt.group(2).strip()
    if cur is not None:
        keys.append(cur)
    return keys


def _keyfile_is_ksk(path: str) -> bool:
    """True if a BIND ``K*.key`` file holds a KSK (DNSKEY flags SEP bit set)."""
    try:
        with open(path) as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith(";"):
                    continue
                m = re.search(r"\bDNSKEY\s+(\d+)\s", s)
                if m:
                    return bool(int(m.group(1)) & 1)  # SEP bit ⇒ KSK
    except OSError:
        return False
    return False


def _render_dnssec_policies(policies: list[dict[str, Any]]) -> str:
    """Render top-level ``dnssec-policy "<name>" { ... };`` blocks (issue #49).

    BIND's built-in ``default`` policy is never shipped here (zones that use
    it reference it by name without a definition). Each entry is a dict from
    the ConfigBundle: name / algorithm / ksk_lifetime_days / zsk_lifetime_days
    / nsec3 + nsec3_iterations / nsec3_salt_length / nsec3_optout.
    """
    out = ""
    for p in policies:
        name = p.get("name")
        if not name or name == "default":
            continue
        algo = p.get("algorithm") or "ecdsap256sha256"
        block = (
            f'dnssec-policy "{name}" {{\n'
            "    keys {\n"
            f"        ksk lifetime {_lifetime(p.get('ksk_lifetime_days', 0))} algorithm {algo};\n"
            f"        zsk lifetime {_lifetime(p.get('zsk_lifetime_days', 90))} algorithm {algo};\n"
            "    };\n"
        )
        if p.get("nsec3"):
            optout = "yes" if p.get("nsec3_optout") else "no"
            block += (
                f"    nsec3param iterations {int(p.get('nsec3_iterations', 0))} "
                f"optout {optout} salt-length {int(p.get('nsec3_salt_length', 0))};\n"
            )
        block += "};\n"
        out += block
    return out


class Bind9Driver(DriverBase):
    rendered_dir_name = "rendered"

    # ── Render / validate / swap ────────────────────────────────────────────

    def render(self, bundle: dict[str, Any]) -> None:
        new_dir = self.state_dir / "rendered.new"
        if new_dir.exists():
            shutil.rmtree(new_dir)
        (new_dir / "zones").mkdir(parents=True)

        opts = bundle.get("options", {})
        forwarders = opts.get("forwarders") or []
        recursion = "yes" if opts.get("recursion_enabled", True) else "no"
        allow_query = "; ".join(opts.get("allow_query") or ["any"])
        dnssec = opts.get("dnssec_validation", "auto")
        # RPZ rewrites break DNSSEC chain validation: even with
        # `break-dnssec yes`, BIND9 returns SERVFAIL to clients that set the
        # DO bit on DNSSEC-signed domains being blocked. For a blocking
        # appliance the user intent is "block, don't validate", so silently
        # disable validation when blocklists are present.
        if bundle.get("blocklists"):
            dnssec = "no"
        # Encrypted transports (issue #50). ``has_cert`` gates the listeners
        # on cert material actually being present in the bundle, not just on
        # the operator's intent flag — see _render_tls_statements.
        tls_cert = bundle.get("tls_cert") or None
        has_cert = bool(
            isinstance(tls_cert, dict)
            and tls_cert.get("cert_pem")
            and tls_cert.get("key_pem")
        )
        if (opts.get("dot_enabled") or opts.get("doh_enabled")) and not has_cert:
            log.warning(
                "bind9_encrypted_listener_skipped_no_cert",
                dot_enabled=bool(opts.get("dot_enabled")),
                doh_enabled=bool(opts.get("doh_enabled")),
            )

        fwd_block = ""
        if forwarders:
            fwd_block = "    forwarders {{ {fs}; }};\n".format(
                fs="; ".join(_format_forwarder(str(f), opts) for f in forwarders)
            )
            # ``forward only`` means "never fall back to recursing yourself".
            # It was settable, persisted and shipped in the bundle, but no
            # ``forward`` statement was ever rendered — so BIND used its own
            # default (``first``) and an operator who chose ``only`` silently
            # got the opposite. That matters beyond tidiness: ``only`` is how
            # you force every query through a filtering upstream, and
            # ``first`` lets queries leak straight past it on any upstream
            # hiccup.
            #
            # Emitted only for ``only``, because ``first`` IS BIND's default
            # — rendering it explicitly would change named.conf on every
            # install that has forwarders and reload BIND for no behaviour
            # change. Found by the #899 audit for stored-but-never-rendered
            # fields, same class as allow-transfer (#734) and named ACLs.
            if str(opts.get("forward_policy", "first")).lower() == "only":
                fwd_block += "    forward only;\n"

        tsig_keys = bundle.get("tsig_keys") or []
        tsig_key_name = tsig_keys[0]["name"] if tsig_keys else None
        # Derived from ``state_dir``, not hardcoded (#920). AGENT_STATE_DIR is
        # an honoured override and every other path the config points at —
        # zone files, rndc.key, the DoT/DoH cert — is already built from it.
        # This one was the exception, so a non-default state dir wrote the key
        # file to one place and told named to read another. If some file
        # happened to exist at the default path, ``named-checkconf`` passed
        # and the apply reported ok while named held a stale key set — a TSIG
        # transfer then fails BADKEY with nothing anywhere reporting a problem.
        tsig_include = (
            f'include "{self.state_dir / "tsig" / "ddns.key"}";\n' if tsig_keys else ""
        )

        # Split-horizon (issue #24): when the group defines views, every
        # zone — and every RPZ/response-policy — lives INSIDE a
        # ``view { match-clients … }`` block. BIND9 forbids mixing
        # top-level zones with views, so the global response-policy below
        # is only emitted in the no-views path; with views it's rendered
        # per-view further down.
        views = bundle.get("views") or []
        has_views = bool(views)
        # The keys that let the control plane's own transfers select a view
        # (#920). Their own file and include, beside ddns.key rather than in
        # it: ddns.key's FIRST key is the loopback identity the record-op path
        # and the ingest worker sign with, and nothing here may ever displace
        # it. Defined at global scope, above every view that names them.
        view_keys = _view_transfer_keys(views) if has_views else {}
        if view_keys:
            tsig_include += (
                f'include "{self.state_dir / "tsig" / "view-transfer.key"}";\n'
            )
        # Server-wide transfer policy (issue #734). Rendered once here so it
        # covers every zone type — primary, secondary, stub, RPZ — and so the
        # control plane can read any zone this server serves. A zone with its
        # own ``allow_transfer`` override emits its own clause below, which
        # BIND lets shadow this one entirely. The view keys are granted with
        # the rest: selecting a view is only half a transfer.
        key_grants = _transfer_key_grants([*tsig_keys, *view_keys.values()])
        allow_transfer_opt = _render_allow_transfer(
            opts.get("allow_transfer"), key_grants
        )

        # Response-policy block needs to list every RPZ zone we're about to
        # declare, otherwise BIND9 won't consult them on lookups.
        blocklists = bundle.get("blocklists") or []
        response_policy_block = ""
        if blocklists and not has_views:
            zones_list = "; ".join(
                f'zone "{bl["rpz_zone_name"].rstrip(".")}"' for bl in blocklists
            )
            # break-dnssec lets RPZ rewrite responses from DNSSEC-signed zones
            # (otherwise BIND9 returns SERVFAIL on a DNSSEC conflict). For a
            # blocking use-case this is what you want: the user intent is to
            # block, not to preserve validation integrity.
            response_policy_block = (
                f"    response-policy {{ {zones_list}; }} break-dnssec yes;\n"
            )

        logging_block = _render_logging_block(opts)
        conf = NAMED_CONF_SKELETON.format(
            recursion=recursion,
            allow_query=allow_query,
            allow_transfer=allow_transfer_opt.rstrip(),
            dnssec=dnssec,
            forwarders=fwd_block,
            response_policy=response_policy_block,
            rate_limit=_render_rate_limit_block(opts),
            response_log=_render_response_log_option(opts),
            logging_block=logging_block,
            tsig_include=tsig_include,
            acl_statements=_render_acl_statements(bundle.get("acls")),
            tls_statements=_render_tls_statements(opts, self.state_dir, has_cert),
            encrypted_listeners=_render_encrypted_listeners(opts, has_cert),
        )

        # Explicit controls block keyed off the agent-generated rndc.key
        # (written by the entrypoint at first boot). Without this, BIND9
        # auto-generates an in-memory rndc key that doesn't match the
        # on-disk file, so `rndc reconfig` + the rndc-status pusher both
        # fail with "bad auth". The same key lives on disk under
        # state_dir/rndc.key with an `rndc.conf` wrapper the agent uses
        # for every CLI invocation.
        rndc_key_path = self.state_dir / "rndc.key"
        if rndc_key_path.exists():
            conf += (
                f'include "{rndc_key_path}";\n'
                "controls {\n"
                "    inet 127.0.0.1 port 953 allow { 127.0.0.1; } "
                'keys { "spatium-rndc"; };\n'
                "};\n"
            )

        # DNSSEC signing policies (issue #49). Custom policies referenced by
        # a signed zone render as top-level ``dnssec-policy { ... }`` blocks;
        # BIND's built-in "default" needs none. The key-directory above is
        # where BIND auto-generates + rotates the private keys.
        conf += _render_dnssec_policies(bundle.get("dnssec_policies") or [])

        def _zone_stanza(zone: dict[str, Any], file_prefix: str) -> str:
            """Build one ``zone "..." { ... };`` and write its zone file.

            ``file_prefix`` namespaces the on-disk file (e.g.
            ``"internal/"``) so the SAME zone name served from multiple
            views doesn't clobber files (issue #24). Returns "" for a
            zone that shouldn't be emitted (forward zone w/o upstreams).
            """
            zname = zone.get("name") or ""
            if not zname:
                return ""
            zone_type = zone.get("type", "primary")
            # Forward zones: just a forwarders block, no file / allow-update.
            # Per-zone upstreams inherit the group's forward transport
            # (issue #50) — a group forwarding over DoT shouldn't silently
            # fall back to plaintext for its zone-scoped upstreams.
            if zone_type == "forward":
                fwds = [
                    _format_forwarder(str(f), opts)
                    for f in (zone.get("forwarders") or [])
                    if f
                ]
                if not fwds:
                    return ""
                policy = "only" if bool(zone.get("forward_only", True)) else "first"
                return (
                    f'zone "{zname}" {{ type forward; forward {policy}; '
                    f'forwarders {{ {"; ".join(fwds)}; }}; }};\n'
                )
            # Secondary / stub zones (issue #336): the daemon AXFRs the zone
            # from the configured masters, so we emit no zone file (BIND
            # writes it on first transfer) and a ``masters { <ip> [port
            # <n>]; … };`` clause. Without masters, ``named-checkconf``
            # rejects the stanza, so a misconfigured zone (no masters) is
            # simply skipped rather than poisoning the whole config.
            if zone_type in {"secondary", "slave", "stub"}:
                masters = [str(m) for m in (zone.get("masters") or []) if m]
                if not masters:
                    log.warning("bind9_secondary_zone_no_masters_skipped", zone=zname)
                    return ""
                rel_zfile = f"zones/{file_prefix}{zname.rstrip('.')}.db"
                abs_zfile = self.state_dir / self.rendered_dir_name / rel_zfile
                bind_type = "stub" if zone_type == "stub" else "slave"
                masters_clause = "; ".join(_format_master(m) for m in masters)
                return (
                    f'zone "{zname}" {{ type {bind_type}; file "{abs_zfile}"; '
                    f"masters {{ {masters_clause}; }}; }};\n"
                )
            # Relative path inside the rendered tree; absolute path written
            # into named.conf so BIND9 doesn't resolve against its
            # `directory` (/var/cache/bind, not our rendered tree).
            rel_zfile = f"zones/{file_prefix}{zname.rstrip('.')}.db"
            abs_zfile = self.state_dir / self.rendered_dir_name / rel_zfile
            # Coarse allow-update (IP + TSIG) unless the ACL needs the
            # fine-grained update-policy path (name-scope / per-type / deny).
            if _zone_needs_update_policy(zone):
                update_clause = _render_update_policy(zone, tsig_key_name)
            else:
                update_clause = _render_allow_update(zone, tsig_key_name)
            # Transfer policy (issues #641 + #734). The key grant that makes
            # ingest-back and the drift report work now lives in the options
            # block above, so it covers every zone rather than only dynamic
            # ones — a static zone is still a zone the control plane has to be
            # able to read, and static zones are most of them.
            #
            # A per-zone clause is emitted only when the operator set
            # ``DNSZone.allow_transfer``, because BIND lets a zone-level
            # ``allow-transfer`` shadow the options one completely. The key
            # grants are re-added here so that override can widen or narrow
            # who else may transfer without ever locking out the control
            # plane — which would silently break drift, and look exactly like
            # the bug this replaced.
            zone_xfer_acl = zone.get("allow_transfer")
            allow_transfer = (
                _render_allow_transfer(zone_xfer_acl, key_grants)
                if zone_xfer_acl is not None
                else ""
            )
            # DNSSEC inline-signing (issue #49): primary zones with signing on
            # reference a dnssec-policy + enable inline-signing; BIND
            # auto-generates keys in key-directory + signs on load.
            dnssec_clause = ""
            if zone.get("dnssec_enabled"):
                pol = zone.get("dnssec_policy_name") or "default"
                dnssec_clause = f'dnssec-policy "{pol}"; inline-signing yes; '
            self._write_zone_file(new_dir / rel_zfile, zone)
            return (
                f'zone "{zname}" {{ type master; file "{abs_zfile}"; '
                f"{update_clause}{allow_transfer}{dnssec_clause}}};\n"
            )

        def _rpz_stanza(bl: dict[str, Any], file_prefix: str) -> str:
            """Build an RPZ ``zone "..." { ... };`` and write its file.

            Entries render as CNAME records: nxdomain → CNAME .,
            sinkhole → CNAME rpz-drop., redirect → CNAME <target>.,
            exceptions → CNAME rpz-passthru.
            """
            zname = bl["rpz_zone_name"]
            rel = f"zones/{file_prefix}{zname.rstrip('.')}.db"
            abs_zfile = self.state_dir / self.rendered_dir_name / rel
            self._write_rpz_zone_file(new_dir / rel, bl)
            return (
                f'zone "{zname}" {{ type master; file "{abs_zfile}"; '
                f"allow-query {{ localhost; }}; }};\n"
            )

        def _indent(text: str, spaces: int = 4) -> str:
            pad = " " * spaces
            return "".join(
                (pad + ln if ln.strip() else ln)
                for ln in text.splitlines(keepends=True)
            )

        if has_views:
            # Split-horizon (issue #24): every zone + RPZ lives inside its
            # view block. Group-level blocklists (view_name=None) replicate
            # into EVERY view; per-view blocklists land only in their own
            # view. Files are namespaced per view (zones/<view>/...) so
            # identical zone names across views don't collide. Views are
            # already ordered low→high by the control plane for first-match
            # precedence.
            global_bls = [bl for bl in blocklists if bl.get("view_name") is None]
            for view in views:
                vname = view.get("name") or ""
                if not vname:
                    continue
                match_clients = _render_match_clients(view, view_keys)
                recursion_v = "yes" if view.get("recursion", True) else "no"
                view_bls = [
                    bl for bl in blocklists if bl.get("view_name") == vname
                ] + global_bls
                body = ""
                if view_bls:
                    zlist = "; ".join(
                        f'zone "{bl["rpz_zone_name"].rstrip(".")}"' for bl in view_bls
                    )
                    body += f"response-policy {{ {zlist}; }} break-dnssec yes;\n"
                for zone in bundle.get("zones", []):
                    if zone.get("view_name") != vname:
                        continue
                    body += _zone_stanza(zone, f"{vname}/")
                for bl in view_bls:
                    body += _rpz_stanza(bl, f"{vname}/")
                md = [str(m) for m in (view.get("match_destinations") or [])]
                # A view must match on BOTH lists, and BIND checks this one
                # with the request's key too — so a view the operator pinned
                # to one listen address admits its own transfer key here as
                # well, or the control plane (which dials whichever address
                # the server row names) is refused by the destination half.
                if md and vname in view_keys:
                    md = [f'key "{view_keys[vname]["name"]}"', *md]
                md_line = (
                    f"    match-destinations {{ {'; '.join(md)}; }};\n"
                    if md
                    else ""
                )
                # #430 — per-view query ACLs. When the control plane sets
                # allow_query / allow_query_cache on a view, enforce it here;
                # a null/empty value inherits the server-options allow-query.
                aq = view.get("allow_query")
                aq_line = (
                    f"    allow-query {{ {'; '.join(str(c) for c in aq)}; }};\n"
                    if aq
                    else ""
                )
                aqc = view.get("allow_query_cache")
                aqc_line = (
                    f"    allow-query-cache {{ {'; '.join(str(c) for c in aqc)}; }};\n"
                    if aqc
                    else ""
                )
                conf += (
                    f'view "{vname}" {{\n'
                    f"    match-clients {{ {match_clients}; }};\n"
                    f"{md_line}"
                    f"    recursion {recursion_v};\n"
                    f"{aq_line}"
                    f"{aqc_line}"
                    f"{_indent(body)}"
                    f"}};\n"
                )
        else:
            for zone in bundle.get("zones", []):
                conf += _zone_stanza(zone, "")

            # BIND9 catalog zone (RFC 9432) — flat path only. Catalog + views
            # is an unsupported combo in this cut (views render their own
            # per-view zones); the producer/consumer wiring assumes top-level
            # zones, which BIND9 forbids alongside views.
            catalog = bundle.get("catalog") or None
            if catalog and catalog.get("mode") == "producer":
                cname = catalog["zone_name"]
                rel = f"zones/{cname.rstrip('.')}.db"
                abs_zfile = self.state_dir / self.rendered_dir_name / rel
                conf += (
                    f'zone "{cname}" {{ type master; file "{abs_zfile}"; '
                    f"allow-transfer {{ any; }}; notify yes; }};\n"
                )
                self._write_catalog_zone_file(new_dir / rel, catalog)
            elif catalog and catalog.get("mode") == "consumer":
                cname = catalog["zone_name"]
                producer_addr = (catalog.get("producer_addr") or "").strip()
                if producer_addr:
                    # `catalog-zones` lives inside options{}; inject before
                    # the closing brace of the options block. ``in-memory
                    # yes`` keeps member zones in RAM (no per-member files).
                    injection = (
                        f"    catalog-zones {{ "
                        f'zone "{cname}" default-masters {{ {producer_addr}; }} '
                        f"in-memory yes; }};"
                    )
                    target = "    check-integrity no;"
                    if target in conf and injection not in conf:
                        conf = conf.replace(target, target + "\n" + injection, 1)

            for bl in blocklists:
                conf += _rpz_stanza(bl, "")

        (new_dir / "named.conf").write_text(conf)

        # TSIG keys — written to tsig/ddns.key (stable path). ALL keys in
        # the bundle are rendered as ``key {}`` blocks, not just the group
        # loopback key: operator-managed keys (DNSTSIGKey rows) can be
        # referenced from a zone's dynamic-update ACL (issue #641), and BIND
        # rejects an ``allow-update { key "X"; }`` that names an undefined
        # key. tsig_keys[0] is the group loopback key (control plane appends
        # it first); the rest are operator keys.
        # Issue #249 — atomic write so a crash between write_text +
        # chmod doesn't leave a world-readable secret on disk.
        if tsig_keys:
            self._write_key_file("ddns.key", tsig_keys)
        # The per-view transfer keys (#920), same atomic 0600 write. Removed
        # once the bundle stops carrying them (the group lost its views), so
        # no secret outlives the config that needed it.
        view_key_file = self.state_dir / "tsig" / "view-transfer.key"
        if view_keys:
            self._write_key_file("view-transfer.key", list(view_keys.values()))
        elif view_key_file.exists():
            view_key_file.unlink()

        # DoT / DoH listener cert (issue #50) — written to the stable
        # tls/ paths the ``tls`` statement above points at. Same atomic
        # 0600 write as the TSIG key: the private key must never exist
        # world-readable, not even for the window between create + chmod.
        #
        # Only the key is really secret, but both go through the same path
        # so a partially-written pair can't be picked up by a reload racing
        # this write.
        self._write_listener_cert(tls_cert if has_cert else None)

    def _write_key_file(self, filename: str, keys: list[dict[str, Any]]) -> None:
        """Write ``key {}`` blocks to ``<state>/tsig/<filename>``, atomically, 0600.

        Created 0600 through ``os.open`` and renamed into place, so the
        secret is never on disk world-readable, not even between create and
        chmod (#249), and a reload racing the write reads the old file or the
        new one, never half of one.
        """
        tsig_dir = self.state_dir / "tsig"
        tsig_dir.mkdir(parents=True, exist_ok=True)
        path = tsig_dir / filename
        tmp = path.with_name(path.name + ".new")
        payload = "".join(
            f'key "{k["name"]}" {{ algorithm {k.get("algorithm", "hmac-sha256")}; '
            f'secret "{k["secret"]}"; }};\n'
            for k in keys
        )
        fd = os.open(
            str(tmp),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.write(fd, payload.encode())
        finally:
            os.close(fd)
        tmp.replace(path)

    def _write_listener_cert(self, tls_cert: dict[str, Any] | None) -> None:
        """Write (or remove) the DoT/DoH listener cert pair.

        ``None`` means no usable cert in the bundle — the listener was
        disabled, or the certificate row was deleted (the FK is ON DELETE
        SET NULL). Remove the pair rather than leaving it: a private key
        that outlives the feature that put it there is exactly the kind of
        thing that ends up in a backup or a hostPath snapshot long after
        anyone remembers it exists.

        Mirrors ``PowerDNSDriver._write_listener_cert``.
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
            dest = tls_dir / filename
            tmp = dest.with_suffix(dest.suffix + ".new")
            fd = os.open(
                str(tmp),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                os.write(fd, material.encode())
            finally:
                os.close(fd)
            tmp.replace(dest)

    def _write_catalog_zone_file(self, path: Path, catalog: dict[str, Any]) -> None:
        """Render a BIND9 catalog zone file per RFC 9432.

        Each member zone shows up as a synthetic label
        ``<sha1-of-wire-name>.zones.<catalog>``. The PTR record at that
        label points back to the member zone name. The mandatory
        ``version`` TXT at the apex pins the schema to "2" (the only
        version BIND9 accepts).

        SOA serial uses ``int(time.time())`` because the long-poll only
        delivers a fresh bundle when membership actually changes (the
        catalog block is in the structural ETag); the agent only re-
        renders on bundle change, so each render really is a different
        membership state and consumers will always pull.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        cname = (catalog.get("zone_name") or "").strip()
        if not cname:
            return
        members = catalog.get("members") or []
        serial = int(time.time())
        lines = [
            "$TTL 86400",
            f"@ IN SOA invalid. invalid. ( {serial} 86400 3600 86400 86400 )",
            "@ IN NS invalid.",
            'version IN TXT "2"',
        ]
        for m in members:
            zname = (m.get("zone_name") or "").strip()
            if not zname:
                continue
            text = zname.lower().rstrip(".")
            # RFC 9432 §4.1: hash is SHA-1 of the *wire-format* zone
            # name (each label prefixed with its length byte, root null
            # byte at the end).
            wire = (
                b"".join(
                    bytes([len(label)]) + label.encode("ascii")
                    for label in text.split(".")
                    if label
                )
                + b"\x00"
            )
            digest = hashlib.sha1(wire).hexdigest()
            text_with_dot = text + "." if text else "."
            lines.append(f"{digest}.zones IN PTR {text_with_dot}")
        path.write_text("\n".join(lines) + "\n")

    def _write_zone_file(self, path: Path, zone: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        name = zone.get("name") or ""
        ttl = zone.get("ttl", 3600)
        serial = zone.get("serial") or 1
        # Auto-emit a self-referential glue A record so BIND9 accepts the
        # zone even when the user didn't explicitly add `ns1 IN A …`.
        # 127.0.0.1 is fine for dev; production should set primary_ns + glue
        # explicitly via the zone create form.
        lines = [
            f"$TTL {ttl}",
            f"@ IN SOA ns1.{name} admin.{name} ( {serial} 3600 600 86400 300 )",
            f"@ IN NS ns1.{name}",
            "ns1 IN A 127.0.0.1",
        ]
        for rec in zone.get("records", []) or []:
            rec_ttl = rec.get("ttl") or ttl
            name_field = rec.get("name") or "@"
            rtype = rec["type"].upper()
            value = rec["value"]
            # MX / SRV zone-file format requires inline priority (and
            # weight+port for SRV) before the target. The control plane
            # stores those in separate columns; compose the wire shape
            # here so ``named-checkzone`` parses the zone cleanly.
            if rtype == "MX" and rec.get("priority") is not None:
                if not value.lstrip().split(" ", 1)[0].isdigit():
                    value = f"{rec['priority']} {value}"
            elif (
                rtype == "SRV"
                and rec.get("priority") is not None
                and rec.get("weight") is not None
                and rec.get("port") is not None
                and len(value.split()) < 4
            ):
                value = f"{rec['priority']} {rec['weight']} {rec['port']} {value}"
            lines.append(f"{name_field} {rec_ttl} IN {rtype} {value}")
        path.write_text("\n".join(lines) + "\n")

    def _write_rpz_zone_file(self, path: Path, bl: dict[str, Any]) -> None:
        """Render an RPZ zone file.

        RPZ uses CNAME trigger records to tell BIND9 how to rewrite responses:
          - CNAME .            → synthesize NXDOMAIN
          - CNAME *.           → synthesize NODATA
          - CNAME rpz-drop.    → drop the query (no response)
          - CNAME rpz-passthru → explicit bypass (used for exceptions)
          - CNAME <target>.    → rewrite response to CNAME target
          - A / AAAA <ip>      → answer with a literal address

        Wildcard entries are emitted as `*.<domain>` *in addition to* the
        bare name, because an RPZ wildcard matches subdomains only — a
        `*.example.com`-only rule leaves the apex resolving normally.

        Every owner name is emitted at most once. Two CNAMEs at one owner
        is a "multiple RRs of singleton type" error, and BIND then refuses
        the ENTIRE zone — so one bad pair silently disables every other
        entry. Two ways that happens, both ordinary rather than exotic:

          - a domain that is both an entry and an exception (which is
            what an exception is *for*);
          - the same domain in two assigned lists whose ``block_mode``
            differs, e.g. overlapping NSFW feeds where one is set to
            sinkhole. The effective blocklist concatenates lists without
            deduping, so this reaches the renderer intact.

        Nothing upstream catches it: ``validate()`` runs named-checkconf,
        which does not read zone files.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        zname = bl["rpz_zone_name"]
        lines = [
            "$TTL 60",
            "@ IN SOA localhost. root.localhost. ( 1 3600 600 86400 60 )",
            "@ IN NS localhost.",
        ]
        # Exceptions are emitted as passthru below, so an entry for the
        # same name must not also be emitted. Matches the control-plane
        # renderer, which already skips excluded domains.
        excluded = {
            str(x).rstrip(".").lower() for x in (bl.get("exceptions") or []) if x
        }
        # First writer of an owner name wins. The choice between two
        # disagreeing lists is arbitrary — what is NOT arbitrary is that
        # the zone must load, since the alternative is enforcing nothing
        # at all. Collisions are logged so the operator can reconcile the
        # lists rather than wonder which one is in effect.
        seen: dict[str, str] = {}
        collisions: list[str] = []
        bad_targets: list[str] = []
        for e in bl.get("entries") or []:
            domain = e["domain"].rstrip(".")
            key = domain.lower()
            if key in excluded:
                continue
            action = e.get("action") or "block"
            block_mode = e.get("block_mode") or "nxdomain"
            is_wildcard = bool(e.get("is_wildcard"))
            target = e.get("target")
            if action == "redirect" and target:
                # An unusable target means the rewrite cannot be expressed.
                # Dropping the entry is the honest outcome — a redirect is
                # a rewrite, so not rewriting is the same as no rule, while
                # substituting a block would invent policy the operator
                # never asked for.
                rewrite = _redirect_rdata(str(target))
                if rewrite is None:
                    bad_targets.append(domain)
                    continue
                rdata = rewrite
            elif block_mode == "sinkhole":
                rdata = "CNAME rpz-drop."
            else:  # default: nxdomain
                rdata = "CNAME ."
            if key in seen:
                # An identical repeat is harmless duplication (BIND loads
                # it); only a differing one would have killed the zone.
                if seen[key] != rdata:
                    collisions.append(domain)
                continue
            seen[key] = rdata
            lines.append(f"{domain} {rdata}")
            if is_wildcard:
                lines.append(f"*.{domain} {rdata}")
        # Exceptions → passthrough (never blocked even if a broader rule
        # matches). Deduped on the same lowercased key so two spellings of
        # one name cannot land twice either.
        emitted_exceptions: set[str] = set()
        for exc in bl.get("exceptions") or []:
            d = str(exc).rstrip(".")
            if not d or d.lower() in emitted_exceptions:
                continue
            emitted_exceptions.add(d.lower())
            lines.append(f"{d} CNAME rpz-passthru.")
            lines.append(f"*.{d} CNAME rpz-passthru.")
        path.write_text("\n".join(lines) + "\n")
        if bad_targets:
            log.warning(
                "bind9_rpz_redirect_target_unusable",
                zone=zname,
                count=len(bad_targets),
                sample=sorted(set(bad_targets))[:5],
                detail=(
                    "A redirect entry's target cannot be a domain name "
                    "(whitespace or an empty label). Those entries were "
                    "dropped; rendering them would make BIND reject the "
                    "whole zone."
                ),
            )
        if collisions:
            log.warning(
                "bind9_rpz_entry_collision",
                zone=zname,
                count=len(collisions),
                sample=sorted(set(collisions))[:5],
                detail=(
                    "The same domain appears in two assigned blocklists with "
                    "different block modes. The first was rendered and the "
                    "rest ignored — emitting both would put two CNAMEs on one "
                    "owner name, which makes BIND reject the whole zone."
                ),
            )
        log.info(
            "bind9_rpz_written",
            zone=zname,
            entries=len(bl.get("entries") or []),
            owners=len(seen),
        )

    def validate(self) -> None:
        new_dir = self.state_dir / "rendered.new"
        conf = new_dir / "named.conf"
        if not shutil.which("named-checkconf"):
            log.warning("named_checkconf_missing_skipping")
            return
        res = subprocess.run(
            ["named-checkconf", str(conf)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if res.returncode != 0:
            # #882 — read stdout FIRST. ``named-checkconf`` writes its
            # diagnostics ("named.conf:20: undefined ACL 'trusted'", with the
            # line number) to stdout and leaves stderr empty, so reading only
            # stderr produced the message "named-checkconf failed: " with
            # nothing after the colon. That was survivable while the text went
            # nowhere; now it is the operator-facing explanation of why their
            # config did not go live, and an empty one makes the whole revert
            # report useless. Mirrors the PowerDNS driver's
            # ``res.stderr or res.stdout``, inverted because these two tools
            # disagree about which stream diagnostics belong on.
            detail = (res.stdout or "").strip() or (res.stderr or "").strip()
            raise RuntimeError(f"named-checkconf failed: {detail or 'no output'}")

    def swap_and_reload(self) -> None:
        new_dir = self.state_dir / "rendered.new"
        current = self.state_dir / self.rendered_dir_name
        backup = self.state_dir / "rendered.prev"
        if current.exists():
            if backup.exists():
                shutil.rmtree(backup)
            current.rename(backup)
        new_dir.rename(current)
        # If start_daemon deferred at boot (no rendered config existed
        # yet), this is the moment we have one — start named now. Without
        # this, a fresh agent that joins a brand-new control plane (no
        # zones yet) never launches the daemon, port 53 stays unbound,
        # and the K8s readiness probe (tcpSocket: 53) never passes.
        if not self.daemon_running():
            self.start_daemon()
            return
        # Signal daemon. Try rndc first; if it isn't configured (no rndc.key),
        # fall back to SIGHUP which named handles as a config + zone reload.
        rndc_ok = False
        if shutil.which("rndc"):
            base = self._rndc_base()
            # ``reconfig`` picks up config changes and zones that were ADDED or
            # REMOVED — but by BIND's documented definition it "does not reload
            # existing zone files even if they have changed". That was fine
            # while a record edit rode the RFC 2136 path. Under split-horizon
            # (issue #24) it is not: the control plane deliberately stops
            # dispatching record ops for a group with views — an nsupdate to
            # loopback cannot target a view — and propagates record changes by
            # RE-RENDERING the zone file instead
            # (backend/app/services/dns/agent_config.py, has_views branch).
            # ``reconfig`` never reads that file back, so on any group with a
            # view every record created after the zone's first load was written
            # to disk and never served: the API returned 201 and the wire
            # answered NXDOMAIN forever. Proven live on a 3-node QA rig
            # 2026-08-06 — the record was present in
            # rendered/zones/<view>/<zone>.db while dig returned NXDOMAIN, and
            # the zone's own ``rndc zonestatus`` still showed the serial and
            # node count from the previous load.
            res = subprocess.run(
                [*base, "reconfig"], capture_output=True, text=True, check=False
            )
            rndc_ok = res.returncode == 0
            if not rndc_ok:
                log.warning(
                    "rndc_failed_falling_back_to_sighup", stderr=res.stderr.strip()
                )
            else:
                self._reload_rendered_zones(base, self._changed_zones(backup))
                self._sync_response_log_runtime(base)
        if not rndc_ok and self.daemon_pid:
            # Degraded path: SIGHUP is a config + zone reload, and like a
            # plain reload it does NOT re-read a dynamic zone's file — and
            # without rndc there is no freeze/thaw to force it. So on this
            # path the split-horizon record-propagation fix above does not
            # apply and re-rendered record changes may not be served until
            # named restarts. Log it as such rather than as a clean apply.
            try:
                os.kill(self.daemon_pid, signal.SIGHUP)
                log.warning(
                    "named_sighup_sent_record_propagation_degraded",
                    pid=self.daemon_pid,
                    note="SIGHUP does not re-read dynamic zone files; "
                    "rendered record changes may not be served",
                )
            except OSError as e:
                log.error("named_sighup_failed", error=str(e))

    def _sync_response_log_runtime(self, base: list[str]) -> None:
        """Assert named's runtime response-logging state after a reconfig.

        ``rndc reconfig`` does NOT apply ``responselog`` (issue #914,
        verified against BIND 9.20.26): the freshly-swapped named.conf
        said ``responselog yes;``, the reconfig succeeded, and
        ``rndc status`` still reported ``response logging is OFF``. It is
        a live switch, like ``querylog``, and reconfig deliberately
        preserves whatever the running server was last told rather than
        stamping the file's value over an operator's ``rndc`` override.

        Query logging escapes this only by accident of BIND's own
        defaulting — with no ``querylog`` statement, it follows the
        presence of the ``queries`` logging category, which the reload
        does pick up. Response logging does not follow its category the
        same way, so without this the operator gets a toggle that
        rewrites named.conf, passes ``named-checkconf``, reloads cleanly
        and produces not one line until the daemon is next restarted.

        The desired state is read back off the config we just swapped in
        rather than threaded down from the bundle, so it cannot disagree
        with what named is actually running — the same reason #899 and
        #734 assert on the rendered config rather than the stored row.

        Best effort: a failure leaves the config-file value to take
        effect at the next restart, which is strictly better than the
        pre-#914 behaviour, so it is logged rather than raised.
        """
        conf = self.state_dir / self.rendered_dir_name / "named.conf"
        try:
            desired = "responselog yes;" in conf.read_text()
        except OSError as exc:
            log.warning("rndc_responselog_conf_unreadable", error=str(exc))
            return
        res = subprocess.run(
            [*base, "responselog", "on" if desired else "off"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            # An older named has no ``responselog`` command at all, which
            # is a legitimate reason to land here — hence warning, not
            # error, and no exception.
            log.warning(
                "rndc_responselog_failed",
                desired=desired,
                stderr=res.stderr.strip(),
            )

    def rendered_zone_views(self) -> list[tuple[str, str | None]]:
        """``(zone_name, view_name)`` for every zone file we just rendered.

        Read back off the rendered tree rather than threaded down from
        ``render()`` so it cannot drift from what is actually on disk — the
        layout is ``rendered/zones/<view>/<zone>.db`` under split-horizon and
        ``rendered/zones/<zone>.db`` without views, which is exactly the
        ``file_prefix`` contract ``_zone_stanza`` writes.
        """
        root = self.state_dir / self.rendered_dir_name / "zones"
        out: list[tuple[str, str | None]] = []
        try:
            entries = sorted(root.iterdir())
        except OSError:
            return out
        for entry in entries:
            if entry.is_dir():
                for zf in sorted(entry.glob("*.db")):
                    out.append((zf.name[: -len(".db")], entry.name))
            elif entry.name.endswith(".db"):
                out.append((entry.name[: -len(".db")], None))
        return out

    def _changed_zones(self, prev_dir: Path) -> set[tuple[str, str | None]] | None:
        """Which rendered zones differ from the previous render.

        ``None`` means "cannot tell — reload everything": no previous tree (first
        render after a cold start), or a read error. Returning the empty set is
        therefore meaningfully different from ``None`` and must stay that way.

        This is what keeps the reload proportional to the edit. A group with
        views re-renders on EVERY record change (records are folded into the
        structural etag there), so reloading the whole tree each time turns one
        record edit into an rndc freeze/reload/thaw storm across every zone —
        with the deep test tiers mutating records continuously, that is a real
        load amplification on an 8-12 GiB appliance, not a theoretical one.
        Comparing the rendered bytes costs one read per zone and collapses it to
        the zones that actually moved.
        """
        if not prev_dir.exists():
            return None
        changed: set[tuple[str, str | None]] = set()
        try:
            for zname, view in self.rendered_zone_views():
                rel = f"zones/{view}/{zname}.db" if view else f"zones/{zname}.db"
                new_p = self.state_dir / self.rendered_dir_name / rel
                old_p = prev_dir / rel
                if not old_p.exists() or new_p.read_bytes() != old_p.read_bytes():
                    changed.add((zname, view))
        except OSError:
            return None
        return changed

    def _reload_rendered_zones(
        self,
        base: list[str],
        only: set[tuple[str, str | None]] | None = None,
    ) -> None:
        """Make named re-read the zone files ``reconfig`` just ignored.

        Every primary zone we render carries an ``allow-update`` clause — the
        group's loopback TSIG grant is ALWAYS included so control-plane record
        ops can flow (see ``_render_allow_update``), which makes the zone
        DYNAMIC as far as named is concerned. named will not re-read a dynamic
        zone's file on a plain reload, because doing so would silently discard
        journal contents; it has to be frozen first. So: freeze → reload →
        thaw, per zone, per view. ``freeze``/``thaw`` fail harmlessly on a zone
        that is not dynamic, and the plain ``reload`` covers that case, so one
        sequence is correct for both.

        Best-effort by design: a zone that will not reload must not stop the
        rest from reloading, and it is already reported through the daemon's
        own status channel.

        Two known subtleties, recorded so nobody chases them as bugs:

        * **Journal-dirty flat zones.** ``freeze`` syncs the journal into the
          master file — i.e. it overwrites the fresh render with named's
          in-memory zone before ``reload`` reads it back. Views groups (the
          case this fix exists for) never journal, so it is moot there. For a
          flat zone with RFC 2136 activity it means the render does not truly
          land (no regression — ``reconfig`` never read it either, and DB and
          journal converge through the record-op path), and the clobbered
          on-disk file no longer byte-matches render output, so that zone
          diffs as "changed" on every later structural render and reloads
          each time. Harmless: flat structural renders are infrequent.
        * **DNSSEC inline-signed zones.** ``freeze``/``thaw`` semantics for
          inline-signed dynamic zones vary across BIND versions (older ones
          refuse, or do not re-read the raw zone on thaw). A failure here
          only logs ``bind9_zone_reload_failed`` — for a signed zone that is
          the same "rendered but never served" symptom this fix removes for
          unsigned ones. Untested interaction; if it bites, the fix likely
          belongs next to the ``inline-signing`` rendering, not here.
        """
        all_zones = self.rendered_zone_views()
        targets = all_zones if only is None else [z for z in all_zones if z in only]
        for zname, view in targets:
            scope = [zname] + (["in", view] if view else [])
            for verb in ("freeze", "reload", "thaw"):
                res = subprocess.run(
                    [*base, verb, *scope],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode != 0 and verb == "reload":
                    log.warning(
                        "bind9_zone_reload_failed",
                        zone=zname,
                        view=view,
                        stderr=res.stderr.strip()[:200],
                    )
        log.info(
            "bind9_rendered_zones_reloaded",
            zones=len(targets),
            of=len(all_zones),
            selective=only is not None,
        )

    # ── Record ops (RFC 2136 over loopback) ─────────────────────────────────

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        # DNSSEC ops (issue #49). BIND9 signs from the rendered config
        # (inline-signing), so sign/unsign need no per-op action here — the
        # zone's dnssec_enabled flip already reshaped the bundle + triggered a
        # reload. A manual rollover is the one thing that needs an rndc call.
        op_kind = op.get("op")
        if op_kind == "dnssec_rollover":
            return self._dnssec_rollover(op)
        if op_kind in ("dnssec_sign", "dnssec_unsign"):
            return None

        if dns is None:
            raise RuntimeError("dnspython not installed — cannot apply record ops")
        zone = op["zone_name"].rstrip(".") + "."
        rec = op["record"]
        name = rec.get("name") or "@"
        rtype = rec["type"]
        value = rec["value"]
        # rec.get returns None when the field exists with null value (which
        # is the common case from JSON), so fall back explicitly.
        ttl_value = rec.get("ttl")
        ttl = ttl_value if ttl_value is not None else 3600

        tsig_path = self.state_dir / "tsig" / "ddns.key"
        keyring = None
        if tsig_path.exists():
            # Very small parser — supports the one-line key we render above.
            content = tsig_path.read_text()
            import re

            m = re.search(r'key\s+"([^"]+)".*?secret\s+"([^"]+)"', content, re.DOTALL)
            if m:
                keyring = dns.tsigkeyring.from_text({m.group(1): m.group(2)})

        wire_value = _wire_value(rtype, value, rec)

        # #773 — the control plane ships the complete desired RRset for the
        # (name, type) this op touches, so the update is expressed as one
        # atomic whole-RRset write: dnspython's ``replace`` with N rdatas emits
        # a single delete-RRset followed by N adds in ONE message. That is what
        # makes a name with several values — round-robin A, a backup MX, SPF
        # beside a verification TXT — survive. Applying the same RRset twice is
        # a no-op, so ops are idempotent and replay-safe rather than
        # order-dependent.
        #
        # An empty member list means the RRset should not exist at all (the op
        # deleted its last value).
        rrset = rec.get("rrset") if isinstance(rec.get("rrset"), dict) else None
        members = rrset.get("members") if rrset is not None else None

        upd = dns.update.Update(zone, keyring=keyring)
        if rrset is not None and members is not None and op["op"] in RRSET_OP_KINDS:
            # ``or ttl`` would swallow a legitimate TTL of 0 (RFC 2181 allows
            # it and it is how "never cache this" is expressed), so test for
            # absence rather than falsiness.
            rrset_ttl = rrset.get("ttl")
            # Parse each member on its own before handing the list to
            # ``replace``, which parses internally and would fail the WHOLE op
            # on one bad value. That matters because the members are siblings
            # the op did not ask about: one legacy or imported row dnspython
            # cannot read would otherwise block every future write to the name,
            # not just its own. Skip it with a warning instead — an rdata that
            # will not parse cannot be served either way, and the value the
            # operator is actually changing still lands. The op's OWN value is
            # not skipped: a failure there is the operator's edit failing, and
            # must surface as one.
            own_wire = wire_value
            wire_members: list[str] = []
            for m in members:
                candidate = _wire_value(rtype, m.get("value") or "", m)
                if candidate == own_wire or _parses_as_rdata(rtype, candidate):
                    wire_members.append(candidate)
                else:
                    log.warning(
                        "rrset_member_unparseable_skipped",
                        zone=zone,
                        name=name,
                        type=rtype,
                        value=candidate,
                    )
            if wire_members:
                upd.replace(
                    name,
                    int(ttl if rrset_ttl is None else rrset_ttl),
                    rtype,
                    *wire_members,
                )
            else:
                upd.delete(name, rtype)
        else:
            # Fallback for an op enqueued by a control plane that predates the
            # ``rrset`` payload. ``rrset_action`` is the older, per-op override
            # for these semantics — DNS pools set it because N A records share
            # one name there and a bare ``replace`` clobbers siblings.
            rrset_action = (rec.get("rrset_action") or "").lower()
            if op["op"] in ("create", "update"):
                if rrset_action == "add":
                    upd.add(name, ttl, rtype, wire_value)
                else:
                    upd.replace(name, ttl, rtype, wire_value)
            elif op["op"] == "delete":
                if rrset_action == "delete_value":
                    # Remove the specific RR only; sibling RRs at the same
                    # (name, rtype) survive. Used by pool member removal so
                    # taking one member out doesn't drop the rest.
                    upd.delete(name, rtype, wire_value)
                else:
                    # Some BIND configurations reject the RR-specific delete
                    # form (value must exactly match a live RR) when the
                    # running daemon has drifted from the zone file. Delete
                    # by (name, rtype) so any matching RR gets cleared.
                    # Idempotent.
                    upd.delete(name, rtype)
            else:
                raise ValueError(f"unknown op: {op['op']}")
        resp = dns.query.tcp(upd, "127.0.0.1", timeout=10)
        rcode = resp.rcode()
        if rcode != 0:  # NOERROR
            raise RuntimeError(
                f"nsupdate returned rcode={rcode} "
                f"(zone={zone} op={op['op']} name={name} type={rtype})"
            )
        # Explicit None so the record-op path matches the dict|None return
        # type the DNSSEC branches use (no implicit fall-through).
        return None

    # ── DNSSEC (issue #49) ──────────────────────────────────────────────────

    def _rndc_base(self) -> list[str]:
        cmd = ["rndc"]
        agent_conf = self.state_dir / "rndc.conf"
        if agent_conf.exists():
            cmd += ["-c", str(agent_conf)]
        return cmd

    def collect_dnssec_state(self, bundle: dict[str, Any]) -> list[dict[str, Any]]:
        """For every signed primary zone, read its DS rrset + per-key state
        and return report entries for ``POST /dns/agents/dnssec-state``.

        BIND owns the private keys (inline-signing); this is a read-only
        mirror via ``rndc dnssec -status`` + ``dnssec-dsfromkey``. Best
        effort — a zone still mid-key-generation just reports empty DS, and
        the next sync picks it up.
        """
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for z in bundle.get("zones", []):
            if not z.get("dnssec_enabled"):
                continue
            ztype = z.get("type", "primary")
            if ztype not in {"primary", "master"}:
                continue
            zname = (z.get("name") or "").rstrip(".")
            if not zname or zname in seen:
                continue
            seen.add(zname)
            try:
                out.append(self._zone_dnssec_state(zname))
            except Exception as e:  # noqa: BLE001 — never let one zone block the rest
                log.warning("dnssec_state_collect_failed", zone=zname, error=str(e))
        return out

    def _zone_dnssec_state(self, zone: str) -> dict[str, Any]:
        keys: list[dict[str, Any]] = []
        ds_records: list[str] = []
        if shutil.which("rndc"):
            res = subprocess.run(
                [*self._rndc_base(), "dnssec", "-status", zone],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                keys = _parse_dnssec_status(res.stdout)
        # DS rrset(s) from the KSK public-key files BIND wrote into the
        # key-directory. The CDS records BIND publishes are an alternative,
        # but dnssec-dsfromkey is deterministic + version-stable.
        key_dir = "/var/cache/bind/keys"
        if shutil.which("dnssec-dsfromkey") and os.path.isdir(key_dir):
            for fn in sorted(os.listdir(key_dir)):
                if not fn.endswith(".key") or not fn.startswith(f"K{zone}.+"):
                    continue
                path = os.path.join(key_dir, fn)
                try:
                    if not _keyfile_is_ksk(path):
                        continue
                    dres = subprocess.run(
                        ["dnssec-dsfromkey", "-2", path],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    for ln in dres.stdout.splitlines():
                        ln = ln.strip()
                        if ln and " DS " in ln:
                            ds_records.append(ln)
                except Exception as e:  # noqa: BLE001
                    log.warning("dsfromkey_failed", zone=zone, file=fn, error=str(e))
        # Attach DS to the KSK key entries so the per-key UI can show them.
        for k in keys:
            if k.get("key_type") in ("ksk", "csk"):
                k["ds_records"] = ds_records
        return {"zone_name": zone + ".", "ds_records": ds_records, "keys": keys}

    def _dnssec_rollover(self, op: dict[str, Any]) -> dict[str, Any] | None:
        """Force a key rollover for the zone (``rndc dnssec -rollover``).

        The op record carries the ``key_tag`` to roll. After triggering, we
        re-read the zone's state so the control plane reflects the new key
        set on the next heartbeat.
        """
        zone = op["zone_name"].rstrip(".")
        rec = op.get("record") or {}
        key_tag = rec.get("key_tag")
        if not shutil.which("rndc"):
            raise RuntimeError("rndc not available — cannot roll DNSSEC key")
        cmd = [*self._rndc_base(), "dnssec", "-rollover", "-key", str(key_tag), zone]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"rndc dnssec -rollover failed: {res.stderr.strip()}")
        log.info("dnssec_rollover_triggered", zone=zone, key_tag=key_tag)
        try:
            return {"dnssec_state": self._zone_dnssec_state(zone)}
        except Exception:  # noqa: BLE001
            return None

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start_daemon(self) -> None:
        conf_path = self.state_dir / self.rendered_dir_name / "named.conf"
        if not conf_path.exists():
            log.warning("named_conf_missing_startup_deferred")
            return
        # -f (not -g): keep named in the foreground so subprocess.Popen
        # can track the PID, but honour the user-defined ``logging {}``
        # block in named.conf. ``-g`` *also* runs in the foreground but
        # additionally forces every category to stderr regardless of
        # named.conf — that silently breaks the query-log file channel
        # we render when ``query_log_enabled=True``. We're already
        # running unprivileged as ``spatium`` (entrypoint dropped privs
        # via su-exec), so don't pass ``-u`` — named would try to
        # setgid() to a different user and fail.
        # Idempotent against the SYSTEM, not just this object's state.
        #
        # ``daemon_pid`` is per-instance state, and only
        # ``daemon_running()`` stands between the two ``start_daemon()``
        # call sites and a duplicate spawn. Observed on a real agent:
        # two ``named_started`` events 118 ms apart at boot (pids 14 and
        # 32, same parent, same config). The precise race is not fully
        # established — see ``_process`` — but consulting the system
        # rather than instance state fixes it either way.
        #
        # Two named processes do not fail loudly — BIND uses
        # SO_REUSEPORT, so both bind :53 and :953 and the kernel
        # load-balances between them. The visible symptom is that
        # ``rndc`` becomes unreliable: ``rndc querylog on`` flips the
        # flag on whichever instance answered, while queries and
        # ``rndc status`` land on either. Enabling query logging then
        # appears to do nothing, which silently breaks the Logs → DNS
        # Queries surface and anything built on it.
        # The system look-up alone does NOT close the race: it matches on
        # ``/proc/<pid>/comm``, and a child that has been forked but has not
        # yet ``execve``'d still carries the PARENT's name, so a concurrent
        # caller sees no daemon and spawns a second one. Hold an exclusive
        # lock across the check, the spawn, and the wait for the new process
        # to become visible under its own name — then the window has no
        # interior. (Observed live 2026-08-06: pids 14 and 24, same parent,
        # same config, both bound to :53 and :953.)
        with spawn_guard(self.state_dir, "named"):
            existing = find_running_daemon("named")
            if existing is not None:
                self.daemon_pid = existing
                log.info(
                    "named_already_running_adopted",
                    pid=existing,
                    note="did not spawn a second daemon",
                )
                return
            self.daemon_pid = subprocess.Popen(
                ["named", "-f", "-c", str(conf_path)]
            ).pid
            wait_for_daemon("named", self.daemon_pid)
        log.info("named_started", pid=self.daemon_pid)

    def daemon_running(self) -> bool:
        # Falls back to a system-wide look-up when this object has no
        # pid of its own: another driver instance may legitimately own
        # the running daemon, and answering "not running" would spawn a
        # duplicate (see start_daemon).
        if self.daemon_pid is None:
            found = find_running_daemon("named")
            if found is None:
                return False
            self.daemon_pid = found
            return True
        try:
            os.kill(self.daemon_pid, 0)
        except OSError:
            return False
        # A zombie still answers signal 0, so the state check is what
        # actually distinguishes "running" from "dead but unreaped".
        return not is_zombie(str(self.daemon_pid))

    def daemon_version(self) -> str | None:
        """Running ``named`` version, e.g. ``"9.20.26"``.

        ``named -v`` prints ``BIND 9.20.26 (Stable Release) <id:5a605f8>``.
        Reported so the control plane knows what every DNS node is actually
        running, the same way ``kea_version`` is reported for DHCP (#637).
        BIND has no equivalent of PowerDNS's one-way LMDB migration (#638) —
        zone data is text on disk — so this is inventory, not a hazard signal.
        """
        exe = shutil.which("named")
        if exe is None:
            return None
        try:
            proc = subprocess.run(  # noqa: S603
                [exe, "-v"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as e:
            log.debug("named_version_probe_failed", error=str(e))
            return None
        m = re.search(r"BIND\s+([0-9]+(?:\.[0-9]+)*)", f"{proc.stdout}\n{proc.stderr}")
        return m.group(1) if m else None
