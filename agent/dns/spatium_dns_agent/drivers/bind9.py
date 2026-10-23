"""BIND9 agent driver.

Renders ``named.conf`` and zone files under ``/var/lib/spatium-dns-agent/rendered``,
validates with ``named-checkconf``, atomically swaps, and reloads via ``rndc``.
Record ops are applied via ``nsupdate`` over loopback, authenticated with the
TSIG key carried in the config bundle.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Collection, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, NamedTuple

import structlog

try:
    import dns.name
    import dns.query
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.tsigkeyring
    import dns.update
except ImportError:  # pragma: no cover - runtime-optional
    dns = None  # type: ignore[assignment]

from ..oom_watch import cgroup_memory_limit_bytes as _cgroup_memory_limit_bytes
from ._forwarders import bind_zone_forwarders as _bind_zone_forwarders
from ._forwarders import bind_zone_tls_statement as _bind_zone_tls_statement
from ._process import (
    find_running_daemon,
    is_zombie,
    spawn_guard,
    wait_for_daemon,
)
from ._txt import quote_txt as _quote_txt
from .base import RRSET_OP_KINDS, DriverBase, HeldZone

log = structlog.get_logger(__name__)

NAMED_CONF_SKELETON = """\
{acl_statements}{tls_statements}options {{
    directory "/var/cache/bind";
    listen-on {{ any; }};
    listen-on-v6 {{ any; }};
{encrypted_listeners}    recursion {recursion};
{allow_recursion}    allow-query {{ {allow_query}; }};
{allow_query_cache}    {allow_transfer}
    dnssec-validation {dnssec};
    key-directory "/var/cache/bind/keys";
    check-integrity no;
{max_cache_size}{query_log}{response_log}{forwarders}{notify_block}{response_policy}{rate_limit}
}};
statistics-channels {{
    inet 127.0.0.1 port 8053 allow {{ 127.0.0.1; }};
}};
{logging_block}{tsig_include}"""

# Query-log channel + category block. The channel is ALWAYS a file at the
# QueryLogShipper default (``/var/log/named/queries.log``) so the shipper
# can tail what the daemon writes — the entrypoint script chowns this
# directory to the unprivileged ``spatium`` user at boot. ``channel`` and
# ``file`` are not operator-settable (the control plane refuses them, #2265):
# syslog / stderr / another path would silently starve the DNS Queries tab.
# ``severity`` and ``print-*`` ARE honoured, within what the shipper can
# still read (see ``_query_log_channel_settings``).
_QUERY_LOG_FILE = "/var/log/named/queries.log"
_QUERY_LOG_DEBUG_RE = re.compile(r"^debug(?:\s+\d{1,3})?$")


def _query_log_channel_settings(opts: dict[str, Any]) -> tuple[str, str, str, str]:
    """``(severity, print-category, print-severity, print-time)`` tokens.

    named logs queries at ``info``, so a channel severity of ``notice`` or
    above would drop every line; a stored value like that (set before the
    control plane refused it) falls back to ``info`` here rather than
    emptying the DNS Queries tab. ``print-time`` is always ``yes`` — the
    shipper reads each line's timestamp. Absent keys (an older control
    plane) render the historical defaults.
    """
    severity = str(opts.get("query_log_severity") or "info").strip().lower()
    if severity != "dynamic" and not _QUERY_LOG_DEBUG_RE.match(severity):
        severity = "info"

    def yn(key: str) -> str:
        return "no" if opts.get(key) is False else "yes"

    return severity, yn("query_log_print_category"), yn("query_log_print_severity"), "yes"


def _query_log_head(opts: dict[str, Any]) -> str:
    severity, category, print_sev, print_time = _query_log_channel_settings(opts)
    return f"""\
logging {{
    channel queries_channel {{
        file "{_QUERY_LOG_FILE}" versions 5 size 50m;
        severity {severity};
        print-category {category};
        print-severity {print_sev};
        print-time {print_time};
    }};
    category queries {{ queries_channel; }};
    category query-errors {{ queries_channel; }};
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
    block = _query_log_head(opts) + _RPZ_LOG_CATEGORIES
    if bool(opts.get("response_log_enabled")):
        block += _RESPONSE_LOG_CATEGORY
    return block + "};\n"


def _render_query_log_option(opts: dict[str, Any]) -> str:
    """``querylog yes;`` inside ``options``, or nothing (issue #2249).

    Without the statement BIND decides query logging from the presence
    of a ``queries`` logging category, but only when named STARTS: the
    flag is a runtime switch that ``rndc reconfig`` never touches,
    statement or no statement (verified against BIND 9.20.29). Rendering
    it makes a fresh start agree with what the operator asked for
    without leaning on that defaulting, and gives
    ``Bind9Driver._sync_logging_runtime`` an explicit marker in the
    swapped-in config to read the desired state back from. Omitted when
    query logging is off, so a group with it off renders a byte-identical
    named.conf.
    """
    if bool(opts.get("query_log_enabled")):
        return "    querylog yes;\n"
    return ""


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


def _dedupe_key_names(keys: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the first key per BIND-normalised name (case-folded, no trailing dot).

    Two ``key`` statements for one name are a redefinition: ``named-checkconf``
    rejects the file and the whole bundle is declined (#2295). The control plane
    refuses the clash and dedupes the bundle; this covers an older control plane.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for k in keys:
        norm = str(k.get("name", "")).strip().lower().rstrip(".")
        if norm in seen:
            log.warning("tsig_key_duplicate_skipped", key=k.get("name"))
            continue
        seen.add(norm)
        out.append(k)
    return out


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


#: The ``notify`` statement's grammar (control-plane validator, #1316).
_NOTIFY_CHOICES = frozenset({"yes", "no", "explicit", "master-only", "primary-only"})

#: Characters that would break out of a ``{ ... };`` statement in
#: named.conf. The control plane validates these lists on write (#1316),
#: but rows stored before the validators existed still reach the bundle,
#: and one bad entry must not poison the whole group's config.
_UNSAFE_CONF_CHARS = re.compile(r"[;{}\n\r]")


def _safe_conf_entries(entries: Any) -> list[str]:
    """Bundle list entries safe to render inside a named.conf list."""
    out: list[str] = []
    for entry in entries or []:
        token = str(entry).strip()
        if token and not _UNSAFE_CONF_CHARS.search(token):
            out.append(token)
    return out


def _render_notify_block(opts: dict[str, Any]) -> str:
    """Server-level NOTIFY statements for the options block (#1523).

    ``notify_enabled`` / ``also_notify`` / ``allow_notify`` were settable,
    validated and stored but never shipped in the bundle, so BIND ran its
    defaults: a stealth primary (``notify no``) still sent NOTIFY, and
    also-notify targets were never notified. Entries are already in BIND
    grammar (``<ip> [port <n>] [key <name>]`` / address-match lists) from
    the #1316 validators; unsafe legacy entries are dropped, not rendered.
    """
    lines: list[str] = []
    notify = str(opts.get("notify_enabled") or "").strip().lower()
    if notify in _NOTIFY_CHOICES:
        lines.append(f"    notify {notify};\n")
    also = _safe_conf_entries(opts.get("also_notify"))
    if also:
        lines.append(f"    also-notify {{ {'; '.join(also)}; }};\n")
    allow_notify = _safe_conf_entries(opts.get("allow_notify"))
    if allow_notify:
        lines.append(f"    allow-notify {{ {'; '.join(allow_notify)}; }};\n")
    return "".join(lines)


def _zone_notify_clauses(zone: dict[str, Any]) -> str:
    """Zone-level ``allow-query`` / ``notify`` / ``also-notify`` clauses (#1523).

    Each field is emitted only when the zone carries its own value —
    ``None`` means "inherit the server options", and in BIND a zone-level
    clause shadows the options one, so rendering an inherited value would
    freeze it against later server-level edits.
    """
    clauses = ""
    if zone.get("allow_query") is not None:
        aq = _safe_conf_entries(zone.get("allow_query"))
        if aq:
            clauses += f"allow-query {{ {'; '.join(aq)}; }}; "
    notify = str(zone.get("notify_enabled") or "").strip().lower()
    if notify in _NOTIFY_CHOICES:
        clauses += f"notify {notify}; "
    if zone.get("also_notify") is not None:
        also = _safe_conf_entries(zone.get("also_notify"))
        if also:
            clauses += f"also-notify {{ {'; '.join(also)}; }}; "
    return clauses


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


#: Answer a ``sinkhole`` list gives when it names no address of a family
#: (#2124). The unspecified address is what every DNS sinkhole answers with
#: (Pi-hole, AdGuard Home): a client connecting to it fails at once, rather
#: than waiting out a resolver timeout as ``rpz-drop`` makes it.
DEFAULT_SINKHOLE_V4 = "0.0.0.0"
DEFAULT_SINKHOLE_V6 = "::"


def sinkhole_rdatas(sinkhole_ip: Any) -> tuple[tuple[str, ...], bool]:
    """RPZ local data for a ``sinkhole`` entry: an A *and* an AAAA (#2124).

    Both families are answered, so an AAAA lookup fails fast too instead of
    falling through to NODATA and a retry over v4. The list's
    ``sinkhole_ip`` replaces the default of its own family; the other
    family keeps the unspecified address.

    Returns ``(rdatas, usable)``. ``usable`` is False when ``sinkhole_ip``
    was set but is not an IP address, in which case the defaults are used:
    the API validates the field now, but a legacy row is not, and an
    unparseable address in the rdata would make BIND refuse the WHOLE zone
    (#878) — answering with the unspecified address is the closer reading
    of "sinkhole this" than enforcing nothing.

    Mirrored by ``_sinkhole_rdatas`` in the control plane's BIND9 driver;
    the two implement one contract and must not diverge.
    """
    v4, v6 = DEFAULT_SINKHOLE_V4, DEFAULT_SINKHOLE_V6
    usable = True
    text = str(sinkhole_ip).strip() if sinkhole_ip is not None else ""
    if text:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            usable = False
        else:
            if ip.version == 6:
                v6 = str(ip)
            else:
                v4 = str(ip)
    return (f"A {v4}", f"AAAA {v6}"), usable


# ── Resolver cache ceiling (issue #1725) ────────────────────────────────────
# BIND's ``max-cache-size`` defaults to 90 % of PHYSICAL memory for every view
# with recursion, and named reads the host's RAM rather than the container's
# cgroup limit. The option sizes ONE cache, and each view has its own (the ARM:
# "the total amount of memory required for cache data is the sum of the cache
# database sizes for all views"), so a server-wide figure in ``options {}``
# is per view. A pod holding a large RPZ (~1.4 kB per entry per zone,
# measured) has nothing left for caches allowed to grow to nine tenths of the
# node each. So the caches get an explicit ceiling: a quarter of the cgroup
# memory limit in total, split across the recursive views.
# ``NAMED_MAX_CACHE_SIZE`` overrides it (a BIND size, e.g. ``512m``; per view,
# as BIND applies it).
_CACHE_SHARE_OF_LIMIT = 0.25
_CACHE_MIN_MIB = 32


def _render_max_cache_size(
    environ: Any = None, limit_bytes: int | None = None, caches: int = 1
) -> str:
    """``max-cache-size`` line for ``options {}``; "" when there is neither an
    override nor a container memory limit (named then keeps its own default,
    which is the right answer on a host that set no limit on purpose).

    ``caches`` is the number of views that keep a resolver cache (recursion
    on); the quarter of the limit is split between them, since the option in
    ``options {}`` is inherited by every view as its OWN cache's ceiling."""
    env = os.environ if environ is None else environ
    override = (env.get("NAMED_MAX_CACHE_SIZE") or "").strip()
    if override:
        if re.fullmatch(r"(?:\d+[kKmMgG]?|unlimited|default)", override):
            return f"    max-cache-size {override};\n"
        log.warning("bind9_max_cache_size_ignored", value=override)
    if limit_bytes is None:
        limit_bytes = _cgroup_memory_limit_bytes()
    if limit_bytes is None:
        return ""
    budget_mib = limit_bytes / (1024 * 1024) * _CACHE_SHARE_OF_LIMIT
    mib = max(int(budget_mib / max(caches, 1)), _CACHE_MIN_MIB)
    return f"    max-cache-size {mib}m;\n"


def _resolver_cache_count(bundle: dict[str, Any]) -> int:
    """How many resolver caches named will keep for ``bundle``: one per
    rendered view with recursion on, or one when there are no views.

    A view with recursion off has its own cache too, but BIND keeps it to
    2 MB by default and nothing fills it, so it is not given a share. The
    options-level value does reach it as its ceiling; a ceiling it never
    approaches costs nothing."""
    views = [v for v in (bundle.get("views") or []) if v.get("name")]
    if not views:
        return 1
    return max(sum(1 for v in views if v.get("recursion", True)), 1)


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


def _render_zone_tls_statements(zones: list[dict[str, Any]] | None) -> str:
    """One ``tls`` statement per distinct upstream hostname that a TLS forward
    zone forwards to (#2121), sorted so the file is stable.

    Rendered with the other top-level tls statements, above ``options`` and
    so above every zone that names one: BIND resolves a tls name where it is
    written. A zone on plain DNS contributes nothing, so a group with no TLS
    forward zone renders exactly what it did before.
    """
    hostnames: set[str] = set()
    for zone in zones or []:
        if zone.get("type") != "forward":
            continue
        _tokens, hostname, _refusal = _bind_zone_forwarders(zone)
        if hostname:
            hostnames.add(hostname)
    return "".join(_bind_zone_tls_statement(h) for h in sorted(hostnames))


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
    """Render one of the GROUP's ``forwarders`` tokens, honouring its transport.

    The group's forwarders only: a forward zone's upstreams carry their own
    transport and render through ``_forwarders.bind_zone_forwarders`` (#2121).

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


def _parses_as_rdata(rtype: str, wire: str, origin: str | None = None) -> bool:
    """Whether dnspython can read ``wire`` as rdata of ``rtype``.

    Used to keep one unreadable sibling from failing a whole-RRset write. Any
    exception counts as "no" — ``from_text`` raises a different type per rdata
    class (SyntaxError, ValueError, dns.exception.*), and the only thing worth
    knowing here is whether the value is usable. ``origin`` is the zone a
    zone-file line is read in: relative names in the rdata are legal there.
    """
    try:
        dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.from_text(rtype),
            wire,
            origin=dns.name.from_text(origin) if origin else None,
        )
    except Exception:  # noqa: BLE001 — see docstring: any failure means unusable
        return False
    return True


# Whitespace of any kind, or a C0 / DEL control character. An owner name
# carrying one cannot be written as the first token of a master-file line.
_OWNER_UNSAFE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
# Any C0 / DEL control character, newline included. Spaces and quotes are
# legal in rdata (CAA, LOC, NAPTR, TXT), control characters never are.
_RDATA_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _zone_line_refusal(name: Any, value: Any) -> str | None:
    """Why ``name`` / ``value`` cannot be written as one zone-file line.

    Returns None when both are safe to interpolate. A blank or
    whitespace-bearing owner would render a line that starts with
    whitespace, which BIND reads as "same owner as the previous record";
    a control character in either field (a newline above all) would end
    the line early and let the rest be read as a record of its own.
    """
    if not isinstance(name, str) or not isinstance(value, str):
        return "its owner or value is not text"
    if _OWNER_UNSAFE_RE.search(name):
        return "its owner name is blank or contains whitespace or a control character"
    if _RDATA_CONTROL_RE.search(value):
        return "its value contains a newline or control character"
    return None


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
    if rtype_u == "TXT":
        # TXT must reach the wire quoted (issue #1514): an unquoted
        # value is parsed by BIND as zone-file syntax, so a ``;``
        # truncates SPF/DMARC at a comment and spaces split the value
        # into separate character-strings resolvers concatenate wrong.
        return _quote_txt(value)
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


# ── Zone apex (issue #1153) ──────────────────────────────────────────────────
#
# The one name server the agent ever invents for a zone, and the one address it
# ever invents for it. BIND loads a zone only if its apex has an NS, and only if
# every NS inside the zone has an A/AAAA in it — so when a zone names no name
# server of its own, the agent still has to write one. It is the last resort,
# never written beside a name server the zone does name, and logged whenever it
# is served. The control plane's drift / sync filter for this exact glue (#920,
# ``_AGENT_NS_GLUE``) mirrors these values: keep the two in step.
_PLACEHOLDER_NS_LABEL = "ns1"
_PLACEHOLDER_NS_ADDRESS = "127.0.0.1"
_PLACEHOLDER_RNAME_LABEL = "admin"

# Characters a master-file name cannot carry unescaped. The same set as the
# control plane's ``contains_zonefile_unsafe`` (backend app/core/dns_names.py),
# which guards primary_ns / admin_email on write; checked again here because
# rows written before that guard existed still reach the bundle.
_ZONEFILE_UNSAFE_RE = re.compile(r'[\s;$()"@\\]|[\x00-\x1f\x7f]')


def _absolute_name(value: Any) -> str | None:
    """``value`` as an absolute domain name, or None if it cannot be one.

    ``primary_ns`` and ``admin_email`` are stored in SOA form with or without
    the trailing dot — the zone form's placeholders carry it, the importers
    strip it — and the rest of the product reads both spellings as absolute
    (the zone export appends the dot). The zone file has to as well: written
    bare, BIND reads ``ns1.example.com`` relative to the zone and serves
    ``ns1.example.com.<zone>``.
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
        or _ZONEFILE_UNSAFE_RE.search(name)
    ):
        return None
    return name if name.endswith(".") else name + "."


_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _is_host_name(absolute: str) -> bool:
    """Whether absolute ``absolute`` is a usable Primary NS: the control
    plane's ``primary_ns_error`` rule (backend ``app/core/dns_names.py``, kept
    in step by shared test vectors). RFC 1123 labels, at most 63 octets each
    and 253 in all, as BIND's default ``check-names`` requires: a row stored
    before #2075 with ``ns_1.…`` made named refuse the zone and the agent
    revert the whole bundle. And at least two labels: a single label such as
    ``ns1`` is read as absolute and would be served as a name at the root,
    not the ``ns1.<zone>`` the operator meant."""
    body = absolute[:-1] if absolute.endswith(".") else absolute
    if not body or len(body) > 253 or "." not in body:
        return False
    return all(_HOST_LABEL_RE.match(label) for label in body.split("."))


def _zone_file_name(value: str, origin: str) -> str:
    """How BIND reads ``value`` written into the file of zone ``origin``:
    absolute when it ends in a dot, the apex for ``@`` or nothing, otherwise
    relative to the apex. Record owners and NS targets are written verbatim,
    so this is what they mean on the wire."""
    v = (value or "").strip()
    if v in ("", "@"):
        return origin
    return v if v.endswith(".") else f"{v}.{origin}"


def _inside(name: str, origin: str) -> bool:
    """Whether absolute ``name`` is the apex ``origin`` or below it."""
    n, o = name.lower(), origin.lower()
    return n == o or n.endswith("." + o)


class ZoneApex(NamedTuple):
    """What a zone file opens with — see ``_zone_apex``."""

    soa_mname: str
    soa_rname: str
    # NS targets written at the apex by the renderer. Empty when the zone has
    # NS records of its own: those are written with the rest of its records.
    ns: tuple[str, ...]
    # Write the placeholder glue ``ns1 IN A 127.0.0.1``.
    placeholder_glue: bool
    # ``(kind, detail)`` pairs, logged once per render by ``_log_apex_notes``.
    notes: tuple[tuple[str, str], ...]


def _zone_apex(zone: dict[str, Any]) -> ZoneApex:
    """The SOA and NS a zone's file opens with (issue #1153).

    The NS set, most specific first:

    1. The zone's own NS records at the apex. They are what the operator
       declared, and what the delegation wizard copies into the parent, so they
       are the whole NS set: nothing is written beside them.
    2. Otherwise ``primary_ns``, if it can resolve: a name outside the zone
       resolves wherever it lives; a name inside it needs an A/AAAA record in
       the zone, and none is invented.
    3. Otherwise the placeholder ``ns1.<zone>``, glued to 127.0.0.1 unless the
       zone holds an address for ``ns1`` itself. That glue sends every
       resolver that follows the zone's own NS set to loopback, so it is noted
       for a warning.

    The SOA MNAME is ``primary_ns``, else the first declared NS, else the
    placeholder; the RNAME is ``admin_email``, else ``admin.<zone>``. Before
    this, every zone got the placeholder SOA, NS and glue whatever it held:
    ``primary_ns`` and ``admin_email`` never reached the agent, and a zone's own
    NS records were served beside ``ns1.<zone>``.
    """
    raw = str(zone.get("name") or "")
    origin = raw if raw.endswith(".") else raw + "."
    notes: list[tuple[str, str]] = []

    addressed: set[str] = set()
    declared_ns: list[str] = []
    for rec in zone.get("records") or []:
        rtype = str(rec.get("type") or "").upper()
        owner = _zone_file_name(str(rec.get("name") or ""), origin)
        if rtype in ("A", "AAAA"):
            addressed.add(owner.lower())
        elif rtype == "NS" and owner.lower() == origin.lower():
            declared_ns.append(_zone_file_name(str(rec.get("value") or ""), origin))

    primary_ns = _absolute_name(zone.get("primary_ns"))
    if primary_ns is not None and not _is_host_name(primary_ns):
        primary_ns = None  # reported below as an unusable field, then healed
    admin = _absolute_name(zone.get("admin_email"))
    for field, parsed in (("primary_ns", primary_ns), ("admin_email", admin)):
        if parsed is None and str(zone.get(field) or "").strip():
            notes.append(("unusable_field", f"{field}={zone.get(field)!r}"))

    placeholder = f"{_PLACEHOLDER_NS_LABEL}.{origin}"
    apex_ns: tuple[str, ...]
    if declared_ns:
        apex_ns = ()
        ns_set = declared_ns
    elif primary_ns is not None and (
        not _inside(primary_ns, origin) or primary_ns.lower() in addressed
    ):
        apex_ns = (primary_ns,)
        ns_set = [primary_ns]
    else:
        if primary_ns is not None:
            notes.append(("unaddressed_primary_ns", primary_ns))
        apex_ns = (placeholder,)
        ns_set = [placeholder]

    ns_lower = {n.lower() for n in ns_set}
    placeholder_glue = (
        placeholder.lower() in ns_lower and placeholder.lower() not in addressed
    )
    if placeholder_glue:
        notes.append(("placeholder", placeholder))
    for n in declared_ns:
        low = n.lower()
        if _inside(n, origin) and low not in addressed and low != placeholder.lower():
            notes.append(("unaddressed_ns", n))

    mname = primary_ns or (declared_ns[0] if declared_ns else placeholder)
    rname = admin or f"{_PLACEHOLDER_RNAME_LABEL}.{origin}"
    return ZoneApex(mname, rname, apex_ns, placeholder_glue, tuple(notes))


# The SOA timers in wire order, each with the value every zone was served with
# before the control plane shipped them (#1171). A bundle from a control plane
# that sends none renders exactly the bytes it did before.
_SOA_TIMERS = (("refresh", 3600), ("retry", 600), ("expire", 86400), ("minimum", 300))
# RFC 2181 section 8's TTL ceiling, and the zone API's (int4) column's.
_SOA_TIMER_MAX = 2**31 - 1


def _soa_timers(zone: dict[str, Any]) -> tuple[str, tuple[tuple[str, str], ...]]:
    """``REFRESH RETRY EXPIRE MINIMUM`` for a zone's SOA, and a note for each
    value that could not be used (issue #1171).

    The zone's own timers are written. One the bundle does not carry (an older
    control plane) is served as every zone was before they shipped; one it
    carries that BIND would refuse — anything but a whole number of seconds
    from 0 to 2^31-1 — is served the same way and noted, rather than making
    named refuse the zone, and with it the group's whole config."""
    values: list[str] = []
    notes: list[tuple[str, str]] = []
    for key, before in _SOA_TIMERS:
        value = zone.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _SOA_TIMER_MAX:
            values.append(str(value))
            continue
        if value is not None:
            notes.append(("unusable_timer", f"{key}={value!r}"))
        values.append(str(before))
    return " ".join(values), tuple(notes)


_APEX_NOTE_LOG: dict[str, tuple[str, str]] = {
    "placeholder": (
        "bind9_zone_apex_ns_is_loopback",
        (
            "These zones name no name server of their own (no Primary NS, no "
            "NS record at the apex), so they are served with the placeholder "
            "NS ns1.<zone> and its glue ns1 A 127.0.0.1. A resolver that "
            "follows a zone's own NS set is sent to loopback. Set the zone's "
            "Primary NS (with an A/AAAA record for it if it is inside the "
            "zone), or add NS records at the apex."
        ),
    ),
    "unaddressed_primary_ns": (
        "bind9_zone_primary_ns_has_no_address",
        (
            "The zone's Primary NS is inside the zone, but the zone holds no "
            "A/AAAA record for it, and BIND will not load a zone whose NS has "
            "no address. The placeholder NS was served instead. Add the "
            "address record."
        ),
    ),
    "unaddressed_ns": (
        "bind9_zone_ns_record_has_no_address",
        (
            "An NS record at the zone apex names a host inside the zone that "
            "has no A/AAAA record in it. BIND will not load such a zone. Add "
            "the address record."
        ),
    ),
    "unusable_field": (
        "bind9_zone_soa_field_unusable",
        (
            "The zone's Primary NS or Admin Email is not a usable domain name "
            "and was ignored."
        ),
    ),
    "unusable_timer": (
        "bind9_zone_soa_timer_unusable",
        (
            "A zone's SOA refresh, retry, expire or minimum is not a whole "
            "number of seconds from 0 to 2147483647, and BIND would refuse the "
            "zone over it. It was served with the value every zone carried "
            "before the timers were rendered (3600/600/86400/300) instead. Fix "
            "the zone's timers."
        ),
    ),
}


def _log_apex_notes(notes: list[tuple[str, str, str]]) -> None:
    """One warning per kind per render, from ``(zone, kind, detail)`` triples.

    Aggregated rather than per zone: the placeholder is still every zone's
    apex on an install where nobody has set a Primary NS, and under views a
    group re-renders on every record change.
    """
    by_kind: dict[str, set[str]] = {}
    for zname, kind, detail in notes:
        entry = zname if kind == "placeholder" else f"{zname} ({detail})"
        by_kind.setdefault(kind, set()).add(entry)
    for kind, entries in by_kind.items():
        event, text = _APEX_NOTE_LOG[kind]
        log.warning(event, count=len(entries), sample=sorted(entries)[:5], detail=text)


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


# Where BIND's dnssec-policy keeps its key files (rendered as key-directory).
DNSSEC_KEY_DIR = "/var/cache/bind/keys"


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


# BIND's own rule for which keys belong in the parent's DS set: the CDS it
# publishes covers exactly the keys whose kasp ``DSState`` is rumoured or
# omnipresent (``syncpublish`` in lib/dns/dnssec.c). A key still hidden has a
# DNSKEY that has not propagated yet; one unretentive or hidden after being
# in the chain is being withdrawn at the end of a rollover.
_DS_SUBMITTABLE_STATES = frozenset({"rumoured", "omnipresent"})


def _key_ds_state(key_path: str) -> str | None:
    """The ``DSState`` from the ``.state`` file beside a ``.key`` file.

    None when there is no state file or it carries no ``DSState`` line,
    i.e. a key BIND does not manage through dnssec-policy.
    """
    state_path = key_path[: -len(".key")] + ".state"
    try:
        with open(state_path) as f:
            for line in f:
                name, sep, value = line.partition(":")
                if sep and name.strip() == "DSState":
                    return value.strip().lower() or None
    except OSError:
        return None
    return None


def _ds_from_key_dir(zone: str, key_dir: str) -> list[str]:
    """SHA-256 DS records (``<zone>. IN DS tag alg 2 HEX``) for a zone's KSKs.

    Same output as ``dnssec-dsfromkey -2`` but computed with dnspython, so it
    needs no BIND tools in the image (#1854). Only keys BIND itself would
    put in its CDS are included: those whose ``DSState`` is rumoured or
    omnipresent. A KSK whose DNSKEY has not propagated yet (hidden) or that
    is being withdrawn after a rollover (unretentive / hidden) is left out,
    so the card never asks the operator to publish a DS the parent must not
    trust yet, or to keep one BIND has finished with. A key with no
    ``.state`` file (not managed by dnssec-policy) is included, as before.

    A signed zone that yields no DS is logged, never reported empty in
    silence: ``dnssec_ds_pending`` when BIND has not made a KSK's DS
    submittable yet, ``dnssec_ds_unavailable`` when there is no key at all.
    """
    import dns.dnssec
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype

    out: list[str] = []
    if not os.path.isdir(key_dir):
        log.warning("dnssec_ds_unavailable", zone=zone, reason="key_dir_missing", key_dir=key_dir)
        return out
    origin = dns.name.from_text(zone)
    held: list[str] = []
    for fn in sorted(os.listdir(key_dir)):
        if not fn.endswith(".key") or not fn.startswith(f"K{zone}.+"):
            continue
        path = os.path.join(key_dir, fn)
        try:
            if not _keyfile_is_ksk(path):
                continue
            ds_state = _key_ds_state(path)
            if ds_state is not None and ds_state not in _DS_SUBMITTABLE_STATES:
                held.append(f"{fn}:{ds_state}")
                continue
            with open(path) as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith(";") or " DNSKEY " not in s:
                        continue
                    rdata_text = s.split(" DNSKEY ", 1)[1]
                    key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, rdata_text)
                    ds = dns.dnssec.make_ds(origin, key, "SHA256")
                    out.append(f"{origin.to_text()} IN DS {ds.to_text().upper()}")
                    break
        except Exception as e:  # noqa: BLE001 — one bad key file must not hide the others
            log.warning("dsfromkey_failed", zone=zone, file=fn, error=str(e))
    if not out:
        if held:
            log.info("dnssec_ds_pending", zone=zone, reason="ds_not_yet_submittable", keys=held)
        else:
            log.warning("dnssec_ds_unavailable", zone=zone, reason="no_ksk_key_file", key_dir=key_dir)
    return out


def _ds_key_tag(ds_record: str) -> int | None:
    """The key tag of a ``<owner> IN DS <tag> <alg> <type> <digest>`` line."""
    parts = ds_record.split()
    try:
        return int(parts[parts.index("DS") + 1])
    except (ValueError, IndexError):
        return None


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


# How long ``swap_and_reload`` waits for named to report that it loaded the
# zones it was just told to load (#1224, #1239). ``rndc reload <zone>`` only
# QUEUES the load and exits 0 even for a file named cannot parse, so the
# verdict has to be read back afterwards. Generous, because a large zone
# (an RPZ feed runs to a million records) takes real time to load and a
# timeout here reverts a config that was fine.
_ZONE_LOAD_TIMEOUT_S = 60.0
_ZONE_LOAD_POLL_S = 0.5
# How long a freshly started named has to answer ``rndc status``. A daemon
# that exits in this window refused its config; one still alive but silent
# at the end is logged and trusted, since the failure worth catching is the
# exit and a slow first zone load is not one.
_NAMED_START_TIMEOUT_S = 30.0
# After SIGHUP (the no-rndc fallback) there is no channel to ask named
# whether it took the config; this is how long it gets to fall over.
_SIGHUP_SETTLE_S = 1.0
# Per-call bound on the rndc queries those loops make (see ``_rndc_run``).
_RNDC_QUERY_TIMEOUT_S = 10.0
# How long ``swap_and_reload`` waits, before the new render goes in, for named to
# write a zone it has just frozen back to the zone's file (#1407). ``rndc freeze``
# answers once the write is queued, not done. A small zone takes milliseconds; the
# bound is a load's, since a large zone writes as slowly as it loads.
_ZONE_DUMP_TIMEOUT_S = 60.0
_ZONE_DUMP_POLL_S = 0.1

# Bulk applies (#2180). Every per-zone step of an apply is a process: one
# ``named-checkzone`` (~63 ms, nearly all of it BIND's library start-up, not the
# zone) and five ``rndc`` calls (~10 ms each, nearly all of it process start).
# Run one zone at a time, a change touching 20,000 zones took ~50 minutes to be
# served. Rendering is ~0.2 ms a zone and was never the cost.
#
# The rndc calls for different zones are independent, so they run on a bounded
# pool; each zone's own calls stay in order. Never wider than the CPUs this
# process may actually use (the cgroup quota, not the host's count, the #980
# lesson), so a small node does what it did before: one at a time.
_APPLY_WORKERS_MAX = 8
# ``named-checkconf -z`` loads every zone in a config in ONE process, so it
# screens a batch of zones for the price of one start-up (500 zones: 0.2 s, where
# named-checkzone took 31 s). It only ever CLEARS zones: a batch that fails, or
# cannot be read as a clean pass, sends each of its zones back through
# ``named-checkzone``, which stays the authority on what is refused and why.
# Below the minimum the per-zone check is as quick; a file over the size bound
# (an RPZ feed runs to a million records) is checked on its own and serially, as
# before, so a batch or the pool never holds several of those in memory at once.
_CHECK_BATCH_MIN_ZONES = 8
_CHECK_BATCH_ZONES = 500
_CHECK_BATCH_MAX_FILE_BYTES = 4 * 1024 * 1024
# And a batch is cut at this many bytes of zone file, so one run stays far inside
# ``_CHECK_TIMEOUT_S`` (named-checkconf loads ~6-7 MiB/s of zone file on one
# core; 500 files near the size bound would be ~300 s, and a timed-out batch is
# all wasted time before the per-zone fallback). Memory does not grow with the
# batch: -z loads and frees one zone at a time.
_CHECK_BATCH_MAX_BYTES = 256 * 1024 * 1024
_CHECK_TIMEOUT_S = 300
_LOADED_LINE = re.compile(r"^zone \S+: loaded serial \d+", re.MULTILINE)

def _cgroup_cpu_quota(root: Path = Path("/sys/fs/cgroup")) -> float | None:
    """CPUs this container may use per its cgroup quota, or None if unbounded.

    cgroup v2 (``cpu.max``: ``<quota|max> <period>``) first, then v1
    (``cpu.cfs_quota_us``, -1 when unbounded). Anything unreadable or
    malformed reads as unbounded; ``_apply_workers`` still caps the pool at
    ``_APPLY_WORKERS_MAX``, so a wrong read can never size it past that.
    """
    try:
        quota, period = (root / "cpu.max").read_text().split()[:2]
        if quota != "max" and int(period) > 0:
            return int(quota) / int(period)
        return None
    except (OSError, ValueError):
        # No cgroup v2 cpu.max (or an unreadable one): try the v1 files.
        pass
    try:
        quota_us = int((root / "cpu" / "cpu.cfs_quota_us").read_text())
        period_us = int((root / "cpu" / "cpu.cfs_period_us").read_text())
        if quota_us > 0 and period_us > 0:
            return quota_us / period_us
    except (OSError, ValueError):
        # No readable v1 quota either: report no limit (the CPU count rules).
        pass
    return None


def _apply_workers() -> int:
    """How many per-zone steps of an apply may run at once (#2180)."""
    try:
        cpus = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cpus = os.cpu_count() or 1
    quota = _cgroup_cpu_quota()
    if quota is not None:
        cpus = min(cpus, max(1, math.ceil(quota)))
    return max(1, min(cpus, _APPLY_WORKERS_MAX))


def _parallel_map[T, R](fn: Callable[[T], R], items: Iterable[T]) -> list[R]:
    """``[fn(i) for i in items]``, on the bounded apply pool, in input order.

    An exception from any call is raised here, as the serial loop would, but
    only once EVERY call has run. ``Executor.map`` cancels the calls still
    queued when one raises; for a thaw pass that strands the zones whose
    thaw never ran frozen, refusing every RFC 2136 update until named
    restarts, so nothing here is cancelled.
    """
    seq = list(items)
    workers = min(_apply_workers(), len(seq))
    if workers <= 1:
        return [fn(i) for i in seq]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bind9-apply") as ex:
        futures = [ex.submit(fn, i) for i in seq]
    # The ``with`` waited for every call (shutdown without cancel_futures).
    return [f.result() for f in futures]


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _conf_safe(text: str) -> bool:
    """Whether ``text`` can sit inside a quoted named.conf string as-is."""
    return not any(c in text for c in '"\\;{}\n\r')


def _zone_views_under(root: Path) -> list[tuple[str, str | None]]:
    """``(zone_name, view_name)`` for every ``*.db`` under ``root/zones``.

    The layout ``render()`` writes: ``zones/<view>/<zone>.db`` under
    split-horizon, ``zones/<zone>.db`` without views. Every primary, RPZ and
    catalog zone file lands there. A secondary or stub zone's file lands
    there too, but only in the LIVE tree and only once named has transferred
    it: the render never writes one, so a staged tree holds none, while an
    enumeration of the live tree can include them. That is harmless to the
    callers (their serial is whatever named just wrote), but do not assume
    every entry here is a zone we rendered.
    """
    zones = root / "zones"
    out: list[tuple[str, str | None]] = []
    try:
        entries = sorted(zones.iterdir())
    except OSError:
        return out
    for entry in entries:
        if entry.is_dir():
            for zf in sorted(entry.glob("*.db")):
                out.append((zf.name[: -len(".db")], entry.name))
        elif entry.name.endswith(".db"):
            out.append((entry.name[: -len(".db")], None))
    return out


def _zone_rel(zname: str, view: str | None) -> str:
    return f"zones/{view}/{zname}.db" if view else f"zones/{zname}.db"


def _zone_label(zname: str, view: str | None) -> str:
    return f"{zname} (view {view})" if view else zname


# ── Unchanged RPZ zones are not rewritten (#2157) ───────────────────────────
#
# Every structural apply used to re-serialise every RPZ zone from scratch: a
# catalog feed is ~186k entries and an ~11 MB file, written again on every
# agent for an edit that touched no blocklist (removing a forward zone,
# changing a group option), and deleted again one apply later as
# ``rendered.prev``. The control plane now ships a content hash per RPZ zone
# (``rpz_sha256``), and the render records it beside the file it wrote, in a
# ``<zone>.db.sha256`` sidecar. When the next bundle's hash matches a tree's
# sidecar, the file is hard-linked into ``rendered.new`` instead of rendered:
# no serialisation, no bytes written, and — because the live and backup trees
# then share the inode — no extra blocks for ``rendered.prev`` either.
#
# That sharing is only safe while nothing ever writes INTO a rendered file.
# Every write to a rendered tree therefore lands as a new inode (a temp file
# renamed over the name, ``_write_new_inode``): a write through the name of a
# hard-linked file would silently change the backup the #882 revert restores
# from, and the live tree named serves, at the same time.

#: Bumped whenever ``_rpz_zone_lines`` would write different bytes for the
#: same zone dict. The control plane's hash covers the INPUT; this covers the
#: renderer, so an agent upgrade that changes the output re-renders every RPZ
#: file once instead of hard-linking the old renderer's bytes forever.
#:
#: 2 (#2124): a ``sinkhole`` entry renders as A + AAAA local data instead of
#: ``CNAME rpz-drop.``. An entry whose list names no address ships the same
#: bytes as before, so its ``rpz_sha256`` does not move and only this bump
#: stops a #2157 agent's dropping file from being linked forward.
_RPZ_RENDER_REVISION = 2
_RPZ_HASH_SUFFIX = ".sha256"


def _rpz_sidecar(path: Path) -> Path:
    """The hash sidecar of an RPZ zone file. Not ``*.db``, so neither the
    zone enumeration nor the byte comparison ever mistakes it for a zone."""
    return path.with_name(path.name + _RPZ_HASH_SUFFIX)


def _rpz_render_key(bl: dict[str, Any]) -> str | None:
    """What a reusable file's sidecar must say, or None when this bundle
    carries no hash (a control plane from before #2157): then the zone is
    rendered every time, exactly as before, and no sidecar is written."""
    digest = bl.get("rpz_sha256")
    if not isinstance(digest, str) or not digest or any(c.isspace() for c in digest):
        return None
    return f"r{_RPZ_RENDER_REVISION}:{digest}"


def _rpz_serial(bl: dict[str, Any]) -> int:
    """The SOA serial of an RPZ zone's file: derived from its content.

    Never the render time: the same zone must render the same bytes, or the
    byte comparison reloads it on every apply. It was a constant 1, which is
    deterministic too, but left ``_verify_zones_loaded`` nothing to check —
    every version of the zone carried the same serial, so "named is still on
    the old copy" and "named loaded the new one" read the same. A serial that
    moves with the content makes the load verifiable like any other zone's.
    RFC 1982 order means nothing here (nothing transfers an RPZ zone from
    us), so a hash is fine; 0 is skipped because the render reads it as "no
    serial". A bundle without a hash keeps the old constant, and its bytes.
    """
    key = _rpz_render_key(bl)
    if key is None:
        return 1
    return int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % (2**32 - 1) + 1


def _rpz_reusable(src: Path, key: str) -> bool:
    """``src`` is a regular file whose sidecar records ``key`` and whose size
    is the size it had when it was written.

    The size is the cheap half of the check: these files are never rewritten
    once they are reused, so a file truncated by a crash (written, renamed,
    not yet flushed) would otherwise be linked forward from tree to tree
    rather than replaced by the next render.
    """
    try:
        recorded = _rpz_sidecar(src).read_text(encoding="utf-8").split()
        size = src.stat().st_size if src.is_file() and not src.is_symlink() else None
    except (OSError, UnicodeDecodeError):
        return False
    return (
        size is not None and len(recorded) == 2 and recorded[0] == key and recorded[1] == str(size)
    )


def _fsync_path(path: Path) -> None:
    """Flush ``path``'s data to disk before anything vouches for it.

    An RPZ file's sidecar is that vouching (#2157): once it exists, the file
    is linked forward instead of re-rendered, and is never again run through
    ``named-checkzone``. So the file's bytes must be durable before its
    sidecar is written. The sidecar itself needs no fsync: losing it only
    costs one re-render. The size recorded in the sidecar still catches the
    commonest crash shape (a delayed-allocation file that comes back empty);
    this closes the rest, at one fsync per RPZ file actually written."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new_inode(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` as a NEW inode: a temp file renamed over it.

    Never opens ``path`` itself for writing, so a file hard-linked into
    another tree (#2157) keeps its bytes there."""
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _copy_new_inode(src: Path, dst: Path) -> None:
    """A private copy of ``src`` at ``dst``, as a new inode."""
    tmp = dst.with_name(dst.name + ".tmp")
    shutil.copyfile(src, tmp)
    _fsync_path(tmp)
    os.replace(tmp, dst)


def _link_or_copy(src: Path, dst: Path) -> str:
    """Put ``src``'s bytes at ``dst`` without writing them, when the
    filesystem allows: a hard link. A copy when it does not (another device,
    a filesystem without links). Returns which one it was."""
    tmp = dst.with_name(dst.name + ".tmp")
    tmp.unlink(missing_ok=True)
    try:
        os.link(src, tmp)
        how = "link"
    except OSError:
        shutil.copyfile(src, tmp)
        _fsync_path(tmp)
        how = "copy"
    os.replace(tmp, dst)
    return how


def _zones_differing(new_root: Path, old_root: Path) -> set[tuple[str, str | None]] | None:
    """Zones under ``new_root`` whose file is new or differs from ``old_root``.

    ``None`` means "cannot tell, treat every zone as changed": no old tree,
    or a read error. The empty set is a real answer and must stay distinct.

    A file hard-linked from the old tree (#2157) is the same inode, so it is
    unchanged without reading it: that is an ~11 MB RPZ zone file compared
    twice per apply for nothing.
    """
    if not old_root.exists():
        return None
    changed: set[tuple[str, str | None]] = set()
    try:
        for zname, view in _zone_views_under(new_root):
            rel = _zone_rel(zname, view)
            old_p = old_root / rel
            new_p = new_root / rel
            if not old_p.exists():
                changed.add((zname, view))
            elif os.path.samefile(new_p, old_p):
                continue
            elif new_p.read_bytes() != old_p.read_bytes():
                changed.add((zname, view))
    except OSError:
        return None
    return changed


def _soa_serial(path: Path) -> int | None:
    """The SOA serial in a zone file, or None if there is none to read.

    Tolerates both shapes the file can take: ours
    (``@ IN SOA mname rname ( 42 3600 ... )``) and the one named writes
    back on ``freeze`` (owner and TTL spelled out, the serial on its own
    line with a ``; serial`` comment).
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    m = re.search(r"\bSOA\b(.*)", text, re.DOTALL)
    if not m:
        return None
    body = re.sub(r";[^\n]*", " ", m.group(1)[:600]).replace("(", " ").replace(")", " ")
    tokens = body.split()
    if len(tokens) < 3 or not tokens[2].isdigit():
        return None
    return int(tokens[2])


def _serial_at_least(got: int, want: int) -> bool:
    """RFC 1982 serial comparison: ``got`` is ``want`` or later."""
    return got == want or 0 < (got - want) % 2**32 < 2**31


def _serial_later(new: int, old: int) -> bool:
    """RFC 1982 serial comparison: ``new`` is strictly later than ``old``."""
    return 0 < (new - old) % 2**32 < 2**31


_RENDERED_SOA_SERIAL = re.compile(r"^(@ IN SOA \S+ \S+ \( )(\d+)( )", re.MULTILINE)


def _set_rendered_serial(path: Path, serial: int) -> bool:
    """Rewrite the SOA serial of a zone file ``_write_zone_file`` wrote.

    Only the render's own one-line SOA is touched (the shape named writes back
    on a freeze is never staged). False when the file does not carry it.
    """
    try:
        text = path.read_text()
    except OSError:
        return False
    new, count = _RENDERED_SOA_SERIAL.subn(rf"\g<1>{serial}\g<3>", text, count=1)
    if count != 1:
        return False
    _write_new_inode(path, new.encode("utf-8"))
    return True


def _zonestatus_serial(out: str) -> int | None:
    """The zone's serial from ``rndc zonestatus`` output.

    An inline-signed zone prints ``serial:`` (the raw zone, which is what we
    render) and then ``signed serial:``; take the first.
    """
    for line in out.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "serial" and value.strip().isdigit():
            return int(value.strip())
    return None


def _first_line(*texts: str | None, skip_warnings: bool = False) -> str:
    """The first non-blank line across ``texts``.

    ``skip_warnings`` passes over ``warning`` lines first: ``named-checkzone``
    prints warnings (a non-terminal wildcard, say) ahead of the error that
    actually refused the zone, and reporting the warning as the reason sends
    the operator after the wrong record. Falls back to the first line when
    every line is a warning.
    """
    lines = [
        line.strip()
        for text in texts
        for line in (text or "").splitlines()
        if line.strip()
    ]
    if skip_warnings:
        for line in lines:
            if "warning" not in line.lower():
                return line
    return lines[0] if lines else "no output"


def _rndc_run(base: list[str], *args: str) -> tuple[int, str, str]:
    """Run one ``rndc`` query with a bound on how long it may take.

    rndc's own default timeout is 60 s, and the verification loops check
    their deadlines only between calls, so an unbounded call against a
    wedged or still-loading named could hold an apply for a minute per zone.
    A call that times out reads as a non-answer (rc 1), which the loops
    already treat as "not yet".
    """
    try:
        res = subprocess.run(
            [*base, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=_RNDC_QUERY_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return 1, "", f"rndc {args[0]} timed out after {_RNDC_QUERY_TIMEOUT_S:g}s"
    except OSError as e:
        # Could not even start it (EAGAIN from fork under load, a binary gone):
        # also a non-answer. Raised instead, from a worker of the apply pool
        # (#2180), it would abort a freeze pass that has already frozen other
        # zones, and nothing would thaw them.
        return 1, "", f"rndc {args[0]} could not run: {e}"
    return res.returncode, res.stdout or "", res.stderr or ""


# One address-match-list element: ``[!]`` then an address / prefix / built-in /
# ACL name, or ``key <name>``. The API gate (#876/#1244) is authoritative; this
# only stops a value stored before that gate existed (or an ACL deleted since)
# from reaching named.conf, where one bad element makes named-checkconf refuse
# the whole bundle.
_AML_ELEMENT_RE = re.compile(r"^!?\s*(?:key\s+)?[A-Za-z0-9_.:/-]+$")
#: The stored default for ``allow_recursion`` (#1817): local + private
#: networks. ``localnets`` is the subnets of the interfaces named sees, which
#: is the LAN only on host networking (the plain appliance); on a pod / bridge
#: network (appliance DNS VIP, umbrella chart, k8s manifests, Compose) it is
#: that network, so the private ranges are what keep a LAN recursing. Mirrors
#: the control plane's ``app.models.dns.DEFAULT_ALLOW_RECURSION``.
DEFAULT_ALLOW_RECURSION = (
    "localhost",
    "localnets",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
)
_AML_BUILTINS = frozenset({"any", "none", "localhost", "localnets"})


def _aml_element_ok(entry: str, acl_names: Collection[str]) -> bool:
    """Whether ``entry`` is an element named-checkconf will accept here."""
    if not _AML_ELEMENT_RE.match(entry):
        return False
    body = entry.lstrip("!").strip()
    if body.lower().startswith("key ") or body.lower() in _AML_BUILTINS:
        return True
    try:
        ipaddress.ip_network(body, strict=False)
        return True
    except ValueError:
        pass
    # A bare name is an ACL reference: it must be defined in this bundle, or
    # named-checkconf fails on the undefined symbol.
    return body in acl_names


def _render_allow_recursion(
    opts: dict[str, Any], acls: list[dict[str, Any]] | None = None
) -> str:
    """The ``allow-recursion`` line for ``options {}`` (#1786, #1817), or ``""``.

    Rendered literally. Recursion off renders no line (``recursion no;``).
    The stored default is local + private networks
    (``DEFAULT_ALLOW_RECURSION``), so a group nobody configured is not an open
    resolver; an explicit ``any`` renders ``any`` and really opens recursion.
    A key absent from the bundle (an older control plane) takes the default
    too. An empty list renders ``none``: the API saves a blank field as the
    default, so an empty list only reaches here from a row written around it,
    and omitting the line would fall back to ``allow-query`` (``any`` by
    default, ``bin/named/server.c``), i.e. open. Fail closed.

    Elements named-checkconf would refuse (a malformed value, an ACL not
    defined in this bundle) are dropped; if none survive the line is ``none``,
    never omitted.
    """
    if not opts.get("recursion_enabled", True):
        return ""
    stored = opts.get("allow_recursion")
    if stored is None:
        stored = list(DEFAULT_ALLOW_RECURSION)
    raw = [str(e).strip() for e in stored if str(e).strip()]
    acl_names = {str(a.get("name") or "").strip() for a in acls or []}
    kept: list[str] = []
    for entry in raw:
        if _aml_element_ok(entry, acl_names):
            kept.append(entry)
        else:
            log.warning("bind9_allow_recursion_entry_dropped", entry=entry)
    if not kept:
        # Fail closed, as the Technitium agent does (#1761).
        kept = ["none"]
    return f"    allow-recursion {{ {'; '.join(kept)}; }};\n"


def _render_allow_query_cache(
    opts: dict[str, Any], acls: list[dict[str, Any]] | None = None
) -> str:
    """The group-level ``allow-query-cache`` line (#2264), or ``""``.

    The control plane ships the key only when the operator set something other
    than the stored default; absent renders nothing, so BIND keeps its own
    default and an untouched group's named.conf is byte-identical. Elements
    named-checkconf would refuse are dropped; if none survive the line is
    ``none`` (fail closed: this setting exists to narrow cache access).
    """
    stored = opts.get("allow_query_cache")
    if stored is None:
        return ""
    acl_names = {str(a.get("name") or "").strip() for a in acls or []}
    kept: list[str] = []
    for entry in (str(e).strip() for e in stored if str(e).strip()):
        if _aml_element_ok(entry, acl_names):
            kept.append(entry)
        else:
            log.warning("bind9_allow_query_cache_entry_dropped", entry=entry)
    if not kept:
        kept = ["none"]
    return f"    allow-query-cache {{ {'; '.join(kept)}; }};\n"


_TRUST_ANCHOR_LABEL = r"[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_TRUST_ANCHOR_NAME_RE = re.compile(rf"^(\.|{_TRUST_ANCHOR_LABEL}(\.{_TRUST_ANCHOR_LABEL})*\.?)$")
_TRUST_ANCHOR_KEY_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def _render_trust_anchors(anchors: Any) -> str:
    """Top-level ``trust-anchors { ... };`` statement (#2266), or ``""``.

    DNSKEY anchors only, which is all the control plane stores: ``static-key``
    for a fixed key, ``initial-key`` for one BIND then maintains by RFC 5011.
    Flags are always 257 (a KSK; the only kind an anchor is) and protocol 3.
    ``key_tag`` is not part of BIND's syntax. Without this the options API's
    anchors were stored and never reached named, so ``dnssec-validation yes``
    validated nothing.

    An entry that would not parse is skipped with a warning rather than
    rendered: one bad line makes ``named-checkconf`` reject the whole file and
    the group stops converging. Empty input renders nothing, so a group with
    no anchors keeps a byte-identical named.conf.
    """
    lines: list[str] = []
    for ta in anchors or []:
        if not isinstance(ta, dict):
            continue
        name = str(ta.get("zone_name") or "").strip()
        key = "".join(str(ta.get("public_key") or "").split())
        try:
            alg = int(ta.get("algorithm"))
        except (TypeError, ValueError):
            alg = 0
        if not (
            _TRUST_ANCHOR_NAME_RE.match(name)
            and _TRUST_ANCHOR_KEY_RE.match(key)
            and 1 <= alg <= 255
        ):
            log.warning("bind9_trust_anchor_skipped_invalid", zone=name)
            continue
        kind = "initial-key" if ta.get("is_initial_key", True) else "static-key"
        lines.append(f'    "{name}" {kind} 257 3 {alg} "{key}";\n')
    if not lines:
        return ""
    return "trust-anchors {\n" + "".join(lines) + "};\n"


class Bind9Driver(DriverBase):
    rendered_dir_name = "rendered"
    #: Records the current render left out because their rdata does not parse
    #: (#2510), one ``"<zone>: …"`` line each; surfaced via ``refused_zones``.
    _skipped_records: set[str] | None = None

    # ── Render / validate / swap ────────────────────────────────────────────

    def render(self, bundle: dict[str, Any]) -> None:
        self._skipped_records = set()
        try:
            self._render(bundle)
        finally:
            # Reported as a partial apply by the sync loop (#2510); sorted so
            # the report is the same whatever order views rendered in.
            self._refused_zones = tuple(sorted(self._skipped_records or ()))

    def _render(self, bundle: dict[str, Any]) -> None:
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

        tsig_keys = _dedupe_key_names(bundle.get("tsig_keys") or [])
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
            # qname-wait-recurse no (#2427): BIND's default (yes) resolves the
            # qname first and does not rewrite a failed lookup, so a blocked
            # name whose upstream is dead answered SERVFAIL after ~10 s instead
            # of the policy answer. A blocklist wants the opposite.
            response_policy_block = (
                f"    response-policy {{ {zones_list}; }} "
                "break-dnssec yes qname-wait-recurse no;\n"
            )

        logging_block = _render_logging_block(opts)
        conf = NAMED_CONF_SKELETON.format(
            recursion=recursion,
            allow_recursion=_render_allow_recursion(opts, bundle.get("acls")),
            allow_query=allow_query,
            allow_query_cache=_render_allow_query_cache(opts, bundle.get("acls")),
            allow_transfer=allow_transfer_opt.rstrip(),
            dnssec=dnssec,
            forwarders=fwd_block,
            notify_block=_render_notify_block(opts),
            response_policy=response_policy_block,
            rate_limit=_render_rate_limit_block(opts),
            max_cache_size=_render_max_cache_size(caches=_resolver_cache_count(bundle)),
            query_log=_render_query_log_option(opts),
            response_log=_render_response_log_option(opts),
            logging_block=logging_block,
            tsig_include=tsig_include,
            acl_statements=_render_acl_statements(bundle.get("acls")),
            tls_statements=(
                _render_tls_statements(opts, self.state_dir, has_cert)
                + _render_zone_tls_statements(bundle.get("zones"))
            ),
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
        conf += _render_trust_anchors(opts.get("trust_anchors"))

        # ``(zone, kind, detail)`` from every zone file written below — logged
        # once, aggregated, after the loop (issue #1153).
        apex_notes: list[tuple[str, str, str]] = []

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
            # The transport is the ZONE's own (#2121), not the group's: the
            # group's ``forward_transport`` applies to its resolver
            # forwarders only. Inheriting it sent DoT to plain-DNS upstreams
            # like Tailscale's 100.100.100.100, validated against the group
            # provider's certificate name, and the zone SERVFAILed.
            if zone_type == "forward":
                fwds, _tls_host, refusal = _bind_zone_forwarders(zone)
                if refusal:
                    # Skipped rather than downgraded to plain DNS or to
                    # unverified TLS, neither of which the operator chose.
                    log.warning(
                        "bind9_forward_zone_skipped", zone=zname, reason=refusal
                    )
                    return ""
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
                    f"masters {{ {masters_clause}; }}; "
                    f"{_zone_notify_clauses(zone)}}};\n"
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
            for kind, detail in self._write_zone_file(new_dir / rel_zfile, zone):
                apex_notes.append((zname.rstrip("."), kind, detail))
            return (
                f'zone "{zname}" {{ type master; file "{abs_zfile}"; '
                f"{update_clause}{allow_transfer}{dnssec_clause}"
                f"{_zone_notify_clauses(zone)}}};\n"
            )

        def _rpz_stanza(bl: dict[str, Any], file_prefix: str) -> str:
            """Build an RPZ ``zone "..." { ... };`` and write its file.

            Entries render as RPZ policy records: nxdomain → CNAME .,
            sinkhole → A + AAAA local data (#2124), redirect → CNAME
            <target>. or A/AAAA, exceptions → CNAME rpz-passthru.
            """
            zname = bl["rpz_zone_name"]
            rel = f"zones/{file_prefix}{zname.rstrip('.')}.db"
            abs_zfile = self.state_dir / self.rendered_dir_name / rel
            self._place_rpz_zone_file(new_dir / rel, bl, rel)
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
            # view block. Per-view blocklists land only in their own view;
            # a group-level one (view_name=None) only in a view that has no
            # zone of its own (#1706). Files are namespaced per view (zones/<view>/...) so
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
                own_bls = [bl for bl in blocklists if bl.get("view_name") == vname]
                # #1706 — a view's own zone already folds in the group's
                # lists, so the group zone behind it would load the same
                # entries a second time. Only a view with no zone of its own
                # falls back to the group zone.
                view_bls = own_bls if own_bls else list(global_bls)
                body = ""
                if view_bls:
                    zlist = "; ".join(
                        f'zone "{bl["rpz_zone_name"].rstrip(".")}"' for bl in view_bls
                    )
                    body += (
                        f"response-policy {{ {zlist}; }} "
                        "break-dnssec yes qname-wait-recurse no;\n"
                    )
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

        _log_apex_notes(apex_notes)
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

    def _write_zone_file(
        self, path: Path, zone: dict[str, Any]
    ) -> tuple[tuple[str, str], ...]:
        """Write one primary zone's file; returns its apex notes for the
        caller to log once per render (``_log_apex_notes``)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        ttl = zone.get("ttl", 3600)
        serial = zone.get("serial") or 1
        # The apex comes from the zone's own primary_ns / admin_email / NS
        # records (issue #1153). The placeholder ``ns1.<zone>`` + ``ns1 A
        # 127.0.0.1`` is left only for a zone that names no name server —
        # BIND will not load a zone without one — and is logged when served.
        apex = _zone_apex(zone)
        timers, timer_notes = _soa_timers(zone)
        lines = [
            f"$TTL {ttl}",
            f"@ IN SOA {apex.soa_mname} {apex.soa_rname} ( {serial} {timers} )",
            *(f"@ IN NS {ns}" for ns in apex.ns),
        ]
        if apex.placeholder_glue:
            lines.append(f"{_PLACEHOLDER_NS_LABEL} IN A {_PLACEHOLDER_NS_ADDRESS}")
        for rec in zone.get("records", []) or []:
            # A record's own TTL wins, 0 included (#1382): 0 is how an operator
            # says "do not cache this" through a cut-over, and ``or`` served it
            # with the zone's TTL. Only a record with no TTL of its own takes
            # the zone's, as on the RFC 2136 path (apply_record_op).
            rec_ttl = ttl if rec.get("ttl") is None else rec["ttl"]
            name_field = rec.get("name") or "@"
            rtype = rec["type"].upper()
            value = rec["value"]
            # A master-file line is ``<owner> <ttl> IN <type> <rdata>``. An
            # owner that is blank or carries whitespace starts the line with
            # whitespace (or splits it), and BIND then reads the record as
            # belonging to the PREVIOUS owner; a newline or other control
            # character in either field starts a second record of the value's
            # choosing. No legal owner or rdata carries one, so the row is
            # left out and reported, as an unparseable one is below.
            line_refusal = _zone_line_refusal(name_field, value)
            if line_refusal is not None:
                zname = (zone.get("name") or "").rstrip(".")
                log.warning(
                    "zone_record_unsafe_skipped",
                    zone=zname,
                    name=name_field,
                    type=rtype,
                    value=value,
                    reason=line_refusal,
                )
                if self._skipped_records is None:
                    self._skipped_records = set()
                self._skipped_records.add(
                    f"{zname}: record {name_field!r} {rtype} {value!r} skipped, "
                    f"{line_refusal}"
                )
                continue
            # MX / SRV zone-file format requires inline priority (and
            # weight+port for SRV) before the target. The control plane
            # stores those in separate columns; compose the wire shape
            # here so ``named-checkzone`` parses the zone cleanly.
            if rtype == "TXT":
                # Quote TXT (issue #1514) — see _wire_value.
                value = _quote_txt(value)
            elif rtype == "MX" and rec.get("priority") is not None:
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
            # One row dnspython cannot read makes named-checkzone refuse the
            # whole zone, and #882 then quarantines the whole bundle (#2510).
            # Leave that row out, name it in ``_skipped_records`` for the sync
            # loop to report, and render the rest. Deterministic: the verdict
            # depends only on the row, so the file (and ETag) cannot flap.
            if not _parses_as_rdata(rtype, value, zone.get("name") or None):
                owner = name_field
                zname = (zone.get("name") or "").rstrip(".")
                log.warning(
                    "zone_record_unparseable_skipped",
                    zone=zname,
                    name=owner,
                    type=rtype,
                    value=value,
                )
                if self._skipped_records is None:
                    self._skipped_records = set()
                self._skipped_records.add(
                    f"{zname}: record {owner} {rtype} {value!r} skipped, "
                    "its rdata does not parse"
                )
                continue
            lines.append(f"{name_field} {rec_ttl} IN {rtype} {value}")
        path.write_text("\n".join(lines) + "\n")
        return apex.notes + timer_notes

    def _place_rpz_zone_file(self, path: Path, bl: dict[str, Any], rel: str) -> None:
        """Put the RPZ zone ``bl`` at ``path``, rendering it only if it changed.

        Reused (#2157) when the bundle's content hash matches the sidecar of
        the live tree's file, or of the backup's — the backup matters on a
        #882 revert, which re-renders the previous bundle while the live tree
        holds the failed one. A reused file is hard-linked, so it costs no
        write and no blocks; its bytes are by construction the bytes this
        render would have produced, so the zone stays out of the changed set,
        out of ``named-checkzone`` and out of every ``rndc reload``.
        """
        key = _rpz_render_key(bl)
        if key is not None:
            for tree in (self.rendered_dir_name, "rendered.prev"):
                src = self.state_dir / tree / rel
                if not _rpz_reusable(src, key):
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                how = _link_or_copy(src, path)
                if tree != self.rendered_dir_name:
                    # From the backup: a revert, putting back the zone named
                    # served before the failed one. named skips ``rndc
                    # reload`` of a primary zone whose file is OLDER than its
                    # last load ("master file older than last load"), and this
                    # file is older than the failed one it loaded — so it
                    # would keep serving the failed copy. A fresh mtime fixes
                    # that; it changes no byte, and the backup sharing the
                    # inode loses nothing.
                    os.utime(path)
                _write_new_inode(_rpz_sidecar(path), f"{key} {path.stat().st_size}\n".encode())
                log.info(
                    "bind9_rpz_reused",
                    zone=bl["rpz_zone_name"],
                    source=tree,
                    via=how,
                    entries=len(bl.get("entries") or []),
                )
                return
        self._write_rpz_zone_file(path, bl)
        if key is not None:
            _write_new_inode(_rpz_sidecar(path), f"{key} {path.stat().st_size}\n".encode())

    def _write_rpz_zone_file(self, path: Path, bl: dict[str, Any]) -> None:
        """Render an RPZ zone file, streaming it to disk.

        RPZ uses CNAME trigger records to tell BIND9 how to rewrite responses:
          - CNAME .            → synthesize NXDOMAIN
          - CNAME *.           → synthesize NODATA
          - CNAME rpz-drop.    → drop the query (no response)
          - CNAME rpz-passthru → explicit bypass (used for exceptions)
          - CNAME <target>.    → rewrite response to CNAME target
          - A / AAAA <ip>      → answer with a literal address

        ``block_mode`` maps onto those as: ``nxdomain`` → ``CNAME .``;
        ``sinkhole`` → an ``A`` and an ``AAAA`` (the list's
        ``sinkhole_ip``, else the unspecified address; #2124). Nothing
        renders ``rpz-drop``: a dropped query leaves the client waiting out
        its resolver timeout, the worst answer an ad blocker can give. A
        legacy ``refused`` (BIND's RPZ has no REFUSED action, and #2124
        retired the mode) renders as NXDOMAIN, as it always did here.

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
        # Streamed (#1109 Part 3): building a list of every line, joining
        # it and encoding the result kept three full copies of a ~1.2M
        # record zone alive beside a running named. Lines now go straight
        # through a buffered writer; the output is byte-identical to the
        # old ``"\n".join(lines) + "\n"``. The caller renders into a
        # staging directory that is swapped in whole, so writing in place
        # here gives up no atomicity.
        path.parent.mkdir(parents=True, exist_ok=True)
        zname = bl["rpz_zone_name"]
        # ``seen`` is the owner-name collision ledger (#878) and must stay.
        seen: dict[str, tuple[str, ...]] = {}
        collisions: list[str] = []
        bad_targets: list[str] = []
        bad_sinkholes: set[str] = set()
        # A temp file renamed into place, so the file is always a NEW inode
        # (#2157): ``path`` may be a name another tree hard-links.
        tmp = path.with_name(path.name + ".tmp")
        with tmp.open("w", encoding="utf-8", buffering=1 << 20) as fh:
            for line in self._rpz_zone_lines(
                bl, seen, collisions, bad_targets, bad_sinkholes
            ):
                fh.write(line)
                fh.write("\n")
            # Durable before the caller's sidecar vouches for it (#2157).
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        if bad_sinkholes:
            log.warning(
                "bind9_rpz_sinkhole_ip_unusable",
                zone=zname,
                sinkhole_ips=sorted(bad_sinkholes)[:5],
                detail=(
                    "A sinkhole list's sinkhole_ip is not an IP address, so "
                    "its entries answer with 0.0.0.0 / :: instead. Rendering "
                    "it would make BIND reject the whole zone. Correct the "
                    "list's sinkhole address."
                ),
            )
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
                    "different block modes or sinkhole addresses. The first "
                    "was rendered and the rest ignored — emitting both would "
                    "put two CNAMEs, or a CNAME beside an address, on one "
                    "owner name, which makes BIND reject the whole zone."
                ),
            )
        log.info(
            "bind9_rpz_written",
            zone=zname,
            entries=len(bl.get("entries") or []),
            owners=len(seen),
        )

    def _rpz_zone_lines(
        self,
        bl: dict[str, Any],
        seen: dict[str, tuple[str, ...]],
        collisions: list[str],
        bad_targets: list[str],
        bad_sinkholes: set[str] | None = None,
    ) -> Iterator[str]:
        """Yield the RPZ zone file's lines; see ``_write_rpz_zone_file``."""
        yield "$TTL 60"
        yield f"@ IN SOA localhost. root.localhost. ( {_rpz_serial(bl)} 3600 600 86400 60 )"
        yield "@ IN NS localhost."
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
                rdatas: tuple[str, ...] = (rewrite,)
            elif block_mode == "sinkhole":
                # Local data, not ``rpz-drop`` (#2124): drop made named
                # send no response at all, so every blocked lookup hung
                # for the client's resolver timeout, and the list's
                # ``sinkhole_ip`` was never read.
                rdatas, usable = sinkhole_rdatas(e.get("sinkhole_ip"))
                if not usable and bad_sinkholes is not None:
                    bad_sinkholes.add(str(e.get("sinkhole_ip")))
            else:  # nxdomain, and a legacy ``refused`` (#2124)
                rdatas = ("CNAME .",)
            if key in seen:
                # An identical repeat is harmless duplication (BIND loads
                # it); only a differing one would have killed the zone —
                # and an A beside a CNAME at one owner is as fatal as two
                # CNAMEs, so the whole rdata set is compared.
                if seen[key] != rdatas:
                    collisions.append(domain)
                continue
            seen[key] = rdatas
            for rdata in rdatas:
                yield f"{domain} {rdata}"
            if is_wildcard:
                for rdata in rdatas:
                    yield f"*.{domain} {rdata}"
        # Exceptions → passthrough (never blocked even if a broader rule
        # matches). Deduped on the same lowercased key so two spellings of
        # one name cannot land twice either.
        emitted_exceptions: set[str] = set()
        for exc in bl.get("exceptions") or []:
            d = str(exc).rstrip(".")
            if not d or d.lower() in emitted_exceptions:
                continue
            emitted_exceptions.add(d.lower())
            yield f"{d} CNAME rpz-passthru."
            yield f"*.{d} CNAME rpz-passthru."

    def validate(self) -> None:
        # What this apply holds back (#1403); refilled by _check_zone_files.
        self.held_back = ()
        new_dir = self.state_dir / "rendered.new"
        conf = new_dir / "named.conf"
        # Fail closed (#1224). Skipping validation because the checker is
        # missing used to report the apply as validated, and commit it as
        # last-known-good, on the strength of no check at all.
        if not shutil.which("named-checkconf"):
            raise RuntimeError(
                "named-checkconf is not installed, so the config cannot be "
                "validated; refusing to apply it unchecked"
            )
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
        self._check_zone_files(new_dir)

    def _check_zone_files(self, new_dir: Path) -> None:
        """``named-checkzone`` every zone file this render added or changed (#1224),
        and hold back each one it refuses instead of failing the apply (#1403).

        ``named-checkconf`` never reads zone files, so a zone named cannot
        load used to pass validation. named then kept serving the OLD copy of
        an existing zone and answered SERVFAIL for a new one, while the
        apply reported OK and was committed as last-known-good.

        A refused file then failed the WHOLE apply, and the sync loop
        quarantined the server's whole config bundle with it: one zone with
        data named will not load stopped every record change in every zone
        the server holds, until the bad data was removed (#1403). Each
        refused zone is held back instead, which is what named itself does
        with a zone file it cannot load, and the rest of the bundle applies:

        * a zone named already serves keeps that copy. The live file is
          copied over the staged one, so after the swap the zone is
          byte-identical, and is neither reloaded nor verified;
        * a zone with no live copy (a new zone) has its staged file removed.
          Its stanza stays in named.conf, so named does not load the zone and
          answers SERVFAIL for it; leaving the stanza out instead would hand
          its names to recursion.

        Every hold is recorded in ``held_back`` for the sync loop to report,
        and the next bundle is re-rendered, so the zone goes live as soon as
        its data loads. A checker that cannot run at all (missing, or timed
        out) still fails the apply: that is not a verdict on the zone.

        Not ``named-checkconf -z`` over the rendered conf: it names zone files
        by absolute path under the LIVE tree, so it would test the files
        already being served rather than these. (A scratch config naming the
        STAGED files is used as a batch screen in front of this check, #2180;
        see ``_screen_zone_batches``.) And not every zone: a views group
        re-renders on every record change, and loading a million-record RPZ
        each time is the load amplification ``_changed_zones`` exists to
        avoid. A zone whose bytes did not change is the one named already
        loaded.

        The flags keep the checker from being stricter than named, which
        would refuse zones named loads. ``-k fail`` is named's default
        ``check-names`` for a primary zone. ``-i none`` matches the rendered
        ``check-integrity no``, and it matters for a second reason: the
        default ``full`` mode RESOLVES out-of-zone MX, SRV and NS targets
        over the network, an outbound query from a validation step (and a
        hang on an air-gapped box). What both still refuse, verified against
        BIND 9.20: an unparseable record, and an in-zone NS name with no
        address, which named will not load even with ``check-integrity no``.
        """
        live = self.state_dir / self.rendered_dir_name
        changed = _zones_differing(new_dir, live)
        targets = [
            zv for zv in _zone_views_under(new_dir) if changed is None or zv in changed
        ]
        if not targets:
            return
        if not shutil.which("named-checkzone"):
            raise RuntimeError(
                "named-checkzone is not installed, so the zone files cannot be "
                "validated; refusing to apply them unchecked"
            )
        # A batch screen first (#2180): it clears zones, it never refuses one.
        cleared = self._screen_zone_batches(new_dir, targets)
        rest = [zv for zv in targets if zv not in cleared]
        # Large files one at a time, as before, so the pool never holds several
        # million-record RPZ loads in memory at once; the rest on the pool.
        large = [
            zv
            for zv in rest
            if _file_size(new_dir / _zone_rel(*zv)) > _CHECK_BATCH_MAX_FILE_BYTES
        ]
        small = [zv for zv in rest if zv not in set(large)]
        refused: dict[tuple[str, str | None], str] = {}
        verdicts = _parallel_map(lambda zv: self._checkzone(new_dir, zv), small)
        for zv, reason in zip(small, verdicts):
            if reason is not None:
                refused[zv] = reason
        for zv in large:
            reason = self._checkzone(new_dir, zv)
            if reason is not None:
                refused[zv] = reason
        held: list[HeldZone] = []
        for zname, view in targets:
            detail = refused.get((zname, view))
            if detail is None:
                continue
            rel = _zone_rel(zname, view)
            last_good = live / rel
            served = last_good.is_file()
            staged_sidecar = _rpz_sidecar(new_dir / rel)
            if served:
                # A copy as a new inode, never a write through the staged
                # name: that name can be a hard link into ``rendered.prev``
                # (#2157), whose bytes the #882 revert restores from.
                _copy_new_inode(last_good, new_dir / rel)
                # The staged sidecar described the refused render; the file
                # is now the live one, so it gets the live one's (or none).
                if _rpz_sidecar(last_good).is_file():
                    _copy_new_inode(_rpz_sidecar(last_good), staged_sidecar)
                else:
                    staged_sidecar.unlink(missing_ok=True)
            else:
                (new_dir / rel).unlink()
                staged_sidecar.unlink(missing_ok=True)
            held.append(HeldZone(zname, view, detail, served))
        if held:
            log.warning(
                "bind9_zones_held_back",
                count=len(held),
                sample=[f"{_zone_label(h.zone, h.view)}: {h.reason}" for h in held[:5]],
                detail=(
                    "named-checkzone refused these zones' new files. A zone named "
                    "already served keeps its last good copy; a new one is not "
                    "served. Every other change in the config applied."
                ),
            )
        self.held_back = tuple(held)

    def _checkzone(self, new_dir: Path, zv: tuple[str, str | None]) -> str | None:
        """``named-checkzone`` one staged zone file: None if it loads, else the
        reason, first line, with the staging path stripped. A checker that
        cannot run (missing, timed out) raises: that is no verdict on the zone."""
        zname, view = zv
        rel = _zone_rel(zname, view)
        res = subprocess.run(
            [
                "named-checkzone",
                "-i",
                "none",
                "-k",
                "fail",
                zname,
                str(new_dir / rel),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=_CHECK_TIMEOUT_S,
        )
        if res.returncode == 0:
            return None
        return _first_line(res.stdout, res.stderr, skip_warnings=True).replace(
            f"{new_dir}/", ""
        )

    def _screen_zone_batches(
        self, new_dir: Path, targets: list[tuple[str, str | None]]
    ) -> set[tuple[str, str | None]]:
        """The zones a batched ``named-checkconf -z`` load passes (#2180).

        A fast path in front of the per-zone ``named-checkzone``, never a
        replacement for it. ``-z`` test-loads every primary zone in a config
        in one process, with the options the scratch config sets: the same
        ``check-integrity no`` and ``check-names master fail`` the per-zone
        flags (``-i none -k fail``) and the rendered config ask for. Verified
        against BIND 9.20 to refuse exactly what ``named-checkzone`` refuses
        (bad rdata, check-names, CNAME and other data, an in-zone NS with no
        address, an over-long TXT) and pass what it passes.

        A batch counts as passed only when the checker exits 0 AND reports a
        load for every zone in it. A batch the checker refused is split in two
        and each half screened again, so one bad zone in 500 costs a handful
        of cheap batch runs and a few per-zone checks rather than 500. Anything
        else clears nothing: a batch too small to split, or one the checker
        could not give a verdict on (a timeout, a missing binary, a name the
        scratch config cannot quote) is not retried, and its zones go through
        ``named-checkzone`` one by one, so which zone was refused and why is
        still decided there.
        """
        eligible = [
            zv
            for zv in targets
            if _file_size(new_dir / _zone_rel(*zv)) <= _CHECK_BATCH_MAX_FILE_BYTES
        ]
        if len(eligible) < _CHECK_BATCH_MIN_ZONES or not shutil.which("named-checkconf"):
            return set()
        chunks: list[list[tuple[str, str | None]]] = [[]]
        chunk_bytes = 0
        for zv in eligible:
            size = _file_size(new_dir / _zone_rel(*zv))
            if chunks[-1] and (
                len(chunks[-1]) >= _CHECK_BATCH_ZONES
                or chunk_bytes + size > _CHECK_BATCH_MAX_BYTES
            ):
                chunks.append([])
                chunk_bytes = 0
            chunks[-1].append(zv)
            chunk_bytes += size
        passed: set[tuple[str, str | None]] = set()
        pending = chunks
        runs = 0
        while pending:
            verdicts = _parallel_map(lambda c: self._screen_chunk(new_dir, c), pending)
            runs += len(pending)
            split: list[list[tuple[str, str | None]]] = []
            for chunk, verdict in zip(pending, verdicts):
                if verdict is True:
                    passed.update(chunk)
                elif verdict is False and len(chunk) > _CHECK_BATCH_MIN_ZONES:
                    mid = len(chunk) // 2
                    split += [chunk[:mid], chunk[mid:]]
            pending = split
        log.info(
            "bind9_zone_check_batched",
            zones=len(targets),
            batched=len(eligible),
            cleared=len(passed),
            batches=runs,
        )
        return passed

    def _screen_chunk(
        self, new_dir: Path, chunk: list[tuple[str, str | None]]
    ) -> bool | None:
        """One ``named-checkconf -z`` over ``chunk``.

        True: a clean pass, every zone loaded. False: the checker ran and
        refused something (a zone, or the scratch config). None: no verdict
        at all (the checker could not run, or timed out, or a name cannot be
        quoted), which is not worth splitting and retrying.

        Each real view becomes a scratch view of its own (a zone name can
        repeat across views, never within one), so every zone sits in a view
        and the config is valid whatever mix the group renders.
        """
        groups: dict[str | None, list[str]] = {}
        for zname, view in chunk:
            groups.setdefault(view, []).append(zname)
        lines = [
            (
                f'options {{ directory "{self.state_dir}"; check-integrity no; '
                "check-names master fail; };"
            )
        ]
        for n, (view, names) in enumerate(groups.items()):
            lines.append(f'view "c{n}" {{ match-clients {{ none; }};')
            for zname in names:
                path = str(new_dir / _zone_rel(zname, view))
                if not (_conf_safe(zname) and _conf_safe(path)):
                    return None
                lines.append(f'zone "{zname}" {{ type master; file "{path}"; }};')
            lines.append("};")
        if not _conf_safe(str(self.state_dir)):
            return None
        try:
            fd, conf = tempfile.mkstemp(
                prefix=".zone-check-", suffix=".conf", dir=self.state_dir
            )
        except OSError:
            return None  # no scratch config, no verdict: the per-zone check decides
        try:
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write("\n".join(lines) + "\n")
            except OSError:
                return None
            try:
                res = subprocess.run(
                    ["named-checkconf", "-z", conf],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=_CHECK_TIMEOUT_S,
                )
            except (OSError, subprocess.SubprocessError):
                return None
            return res.returncode == 0 and len(_LOADED_LINE.findall(res.stdout or "")) == len(
                chunk
            )
        finally:
            try:
                os.unlink(conf)
            except OSError:
                pass  # already gone; nothing is left to clean up

    def swap_and_reload(self) -> None:
        """Put the staged tree live and confirm named is serving it.

        Every way this can fail raises, so the #882 revert puts the previous
        config back and the failure is reported, instead of the apply being
        recorded as OK and committed as last-known-good (#1224, #1239).

        The render has to land over whatever named holds that its zone file
        does not (#1407). named keeps an RFC 2136 update in memory and in the
        zone's journal, and writes it into the zone's file up to 15 minutes
        later. Swapped in first and frozen after, a zone in that state had
        named dump its own copy, asynchronously, over the new render, and the
        thaw loaded the dump: a zone-level change (its TTL, SOA timers, apex)
        was dropped while the apply reported it served, and the served serial
        could go backwards. So each changed zone named serves is frozen BEFORE
        the swap, and the swap waits until named has written it out to the
        file it is replacing (``_freeze_before_swap``). A frozen zone takes no
        update, so nothing can be dumped over the render afterwards.
        """
        new_dir = self.state_dir / "rendered.new"
        current = self.state_dir / self.rendered_dir_name
        backup = self.state_dir / "rendered.prev"
        rndc = shutil.which("rndc")
        base = self._rndc_base() if rndc else []
        # What moved, against the tree being replaced: the live one, or (no live
        # tree) whatever the last swap left as the backup.
        changed = self._changed_zones(new_dir, current if current.exists() else backup)
        frozen: dict[tuple[str, str | None], int | None] = {}
        if rndc and current.exists() and self.daemon_running():
            frozen = self._freeze_before_swap(base, new_dir, current, changed)
        # The serial each changed zone has to be served under: the render's,
        # read before the swap, so nothing written to the live file afterwards
        # can stand in for it.
        rendered = {
            zv: _soa_serial(new_dir / _zone_rel(*zv))
            for zv in _zone_views_under(new_dir)
            if changed is None or zv in changed
        }
        # Until thawed, a zone frozen here refuses every update: whatever
        # fails below, nothing may leave it frozen.
        still_frozen = set(frozen)
        try:
            self._swap_in(new_dir, current, backup)
            # If start_daemon deferred at boot (no rendered config existed
            # yet), this is the moment we have one — start named now. Without
            # this, a fresh agent that joins a brand-new control plane (no
            # zones yet) never launches the daemon, port 53 stays unbound,
            # and the K8s readiness probe (tcpSocket: 53) never passes.
            if not self.daemon_running():
                still_frozen.clear()  # a new named holds no freeze
                self.start_daemon()
                if self._await_named_started():
                    self._verify_zones_loaded(self._rndc_base(), None)
                return
            self._signal_reload(base if rndc else None, changed, frozen, still_frozen, rendered)
        finally:
            if still_frozen:
                self._thaw(base, still_frozen)

    def _swap_in(self, new_dir: Path, current: Path, backup: Path) -> None:
        if current.exists():
            if backup.exists():
                shutil.rmtree(backup)
            current.rename(backup)
        new_dir.rename(current)

    def _thaw(self, base: list[str], zones: Collection[tuple[str, str | None]]) -> None:
        """Best-effort thaw of the zones ``_freeze_before_swap`` froze, on the way
        out of an apply that failed before its own thaw: a zone left frozen
        refuses every update until named restarts."""

        def thaw(zv: tuple[str, str | None]) -> None:
            zname, view = zv
            rc, _out, err = _rndc_run(base, "thaw", zname, *(["in", view] if view else []))
            if rc != 0:
                log.warning("bind9_zone_thaw_failed", zone=zname, view=view, stderr=err[:200])

        _parallel_map(thaw, list(zones))

    def _signal_reload(
        self,
        base: list[str] | None,
        changed: set[tuple[str, str | None]] | None,
        frozen: dict[tuple[str, str | None], int | None],
        still_frozen: set[tuple[str, str | None]],
        rendered: dict[tuple[str, str | None], int | None],
    ) -> None:
        """Have the running named take the swapped-in tree, and confirm it did.

        ``frozen`` maps each zone frozen before the swap to the serial named
        served it under; ``still_frozen`` is emptied once they are thawed."""
        # Signal daemon. Try rndc first; if the control channel cannot be
        # reached, fall back to SIGHUP, which named handles as a config +
        # zone reload.
        if base is not None:
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
            if res.returncode == 0:
                # A frozen zone's serial was read once it was frozen; nothing
                # has moved it since.
                if changed is None:
                    rest = {
                        zv
                        for zv in _zone_views_under(self.state_dir / self.rendered_dir_name)
                        if zv not in frozen
                    }
                else:
                    rest = changed - frozen.keys()
                before = {**self._serving_serials(base, rest), **frozen}
                self._reload_rendered_zones(base, changed, already_frozen=frozen.keys())
                still_frozen.clear()
                self._sync_logging_runtime(base)
                self._verify_zones_loaded(base, changed, before, rendered)
                return
            error = _first_line(res.stderr, res.stdout)
            # "rndc: 'reconfig' failed: TLS error" is named ANSWERING, and
            # refusing: a config ``named-checkconf`` passed but named cannot
            # run (an unreadable cert or key, a port already in use). named
            # keeps the old config. SIGHUP would be refused for the same
            # reason while this reported success (#1239), so it is the apply
            # failing. Only a channel that cannot be reached at all ("connect
            # failed", bad key) falls through to SIGHUP.
            if "'reconfig' failed:" in error:
                raise RuntimeError(f"named rejected the new config: {error}")
            log.warning("rndc_failed_falling_back_to_sighup", stderr=error)
            # Whatever was frozen before the swap must not stay frozen through
            # the fallback; the channel may well refuse this too.
            self._thaw(base, still_frozen)
            still_frozen.clear()
        self._sighup_reload()

    def _sighup_reload(self) -> None:
        """The no-rndc fallback. Degraded, and cannot be verified.

        SIGHUP is a config + zone reload, and like a plain reload it does NOT
        re-read a dynamic zone's file — and without rndc there is no
        freeze/thaw to force it. So on this path the split-horizon
        record-propagation fix does not apply and re-rendered record changes
        may not be served until named restarts. Nor is there a channel to
        ask named whether it took the config. What can be checked is that
        the signal was delivered and named survived it.
        """
        if not self.daemon_pid:
            raise RuntimeError("named is not running, so there is nothing to reload")
        try:
            os.kill(self.daemon_pid, signal.SIGHUP)
        except OSError as e:
            raise RuntimeError(f"could not signal named (pid {self.daemon_pid}): {e}") from e
        log.warning(
            "named_sighup_sent_record_propagation_degraded",
            pid=self.daemon_pid,
            note="SIGHUP does not re-read dynamic zone files; "
            "rendered record changes may not be served",
        )
        time.sleep(_SIGHUP_SETTLE_S)
        if not self.daemon_running():
            raise RuntimeError("named exited after being told to reload")

    def _await_named_started(self) -> bool:
        """Wait for a just-started named to answer, or to die (#1239).

        Raises if it exits: that is named refusing its config (or a port it
        cannot bind), and it used to be logged as ``named_started``. Returns
        True once ``rndc status`` answers, so the caller can go on to check
        the zones; False when it cannot tell (no rndc, or still silent at the
        timeout), which is logged and trusted.
        """
        rndc = shutil.which("rndc")
        base = self._rndc_base()
        started = time.monotonic()
        while True:
            if not self.daemon_running():
                raise RuntimeError(
                    "named exited during startup, so it refused this config; "
                    "its log has the reason"
                )
            if rndc:
                rc, _out, _err = _rndc_run(base, "status")
                if rc == 0:
                    return True
            elif time.monotonic() - started >= _SIGHUP_SETTLE_S:
                log.warning("named_start_unverified_no_rndc", pid=self.daemon_pid)
                return False
            if time.monotonic() - started >= _NAMED_START_TIMEOUT_S:
                log.warning(
                    "named_start_unconfirmed",
                    pid=self.daemon_pid,
                    timeout_s=_NAMED_START_TIMEOUT_S,
                )
                return False
            time.sleep(0.25)

    def _freeze_before_swap(
        self,
        base: list[str],
        new_dir: Path,
        live: Path,
        changed: set[tuple[str, str | None]] | None,
    ) -> dict[tuple[str, str | None], int | None]:
        """Freeze each changed zone named serves, and wait until named has
        written it to its live file, before the new render goes in (#1407).

        ``rndc freeze`` makes named write its in-memory copy of a zone, the
        RFC 2136 updates it holds included, into the zone's file, and it
        answers once that write is queued, not done. Frozen after the swap, a
        zone holding updates had that write land on the new render (the file
        at the same path), where the thaw loaded it. Frozen before, the write
        lands on the file being replaced, and this waits for it: the file's
        serial equals the one named serves, frozen, from then on. A zone with
        nothing unwritten matches at once. A frozen zone takes no update, so
        none can start another write before ``_reload_rendered_zones`` reloads
        and thaws it.

        A zone the freeze refuses (named does not serve it yet, it is not
        dynamic, an operator froze it) keeps the freeze/reload/thaw after the
        swap. Its file, if any, is not touched here.

        The render must also be served under a serial later than named's
        (RFC 1982), or a secondary that holds named's serial never transfers
        the change, and a lower one is a serial going backwards. named runs
        ahead of the database's serial when something other than the control
        plane wrote the zone (a third party, #641) or the database went back
        (a revert, a restore). Such a render is staged under named's serial
        plus one.

        Returns each zone it froze, with the serial named serves it under.
        A write that has not landed by ``_ZONE_DUMP_TIMEOUT_S`` is logged and
        the swap goes on, as it did before: named can serve a serial its file
        does not carry with nothing left to write (the file edited outside the
        agent, or a zone the old order left with named's copy on disk after
        the render loaded), and an apply that waited on it forever would never
        land again. ``_verify_zones_loaded`` still fails the apply if named
        then serves anything but the render.
        """
        # A zone frozen here and then lost track of refuses every RFC 2136
        # update until named restarts. ``swap_and_reload`` thaws what this
        # returns; if it raises instead, after some zones froze (a worker of
        # the pool, #2180, or the wait below), it thaws them itself.
        froze: list[tuple[str, str | None]] = []
        try:
            return self._freeze_and_wait(base, new_dir, live, changed, froze)
        except BaseException:
            if froze:
                self._thaw(base, list(froze))
            raise

    def _freeze_and_wait(
        self,
        base: list[str],
        new_dir: Path,
        live: Path,
        changed: set[tuple[str, str | None]] | None,
        froze: list[tuple[str, str | None]],
    ) -> dict[tuple[str, str | None], int | None]:
        """``_freeze_before_swap``'s body; appends each zone to ``froze`` the
        moment named confirms the freeze."""
        candidates = [
            (zname, view)
            for zname, view in _zone_views_under(new_dir)
            if (changed is None or (zname, view) in changed)
            # new to named, or moved between views: no file of it to replace
            and (live / _zone_rel(zname, view)).exists()
        ]

        def freeze(zv: tuple[str, str | None]) -> tuple[bool, int | None]:
            zname, view = zv
            scope = [zname, *(["in", view] if view else [])]
            rc, _out, _err = _rndc_run(base, "freeze", *scope)
            if rc != 0:
                return False, None
            froze.append(zv)  # list.append is atomic under the GIL
            rc, out, err = _rndc_run(base, "zonestatus", *scope)
            serving = _zonestatus_serial(out) if rc == 0 else None
            if serving is None:
                log.warning(
                    "bind9_frozen_zone_serial_unknown",
                    zone=zname,
                    view=view,
                    stderr=_first_line(err, out)[:200],
                )
            return True, serving

        # Each zone's freeze and zonestatus stay in order; zones run on the
        # bounded pool (#2180).
        frozen: dict[tuple[str, str | None], int | None] = {
            zv: serving
            for zv, (ok, serving) in zip(candidates, _parallel_map(freeze, candidates))
            if ok
        }
        pending = {zv: s for zv, s in frozen.items() if s is not None}
        deadline = time.monotonic() + _ZONE_DUMP_TIMEOUT_S
        while pending:
            for zv, dumped in list(pending.items()):
                if _soa_serial(live / _zone_rel(*zv)) == dumped:
                    del pending[zv]
            if not pending or time.monotonic() >= deadline:
                break
            time.sleep(_ZONE_DUMP_POLL_S)
        for (zname, view), dumped in pending.items():
            log.warning(
                "bind9_frozen_zone_not_written_out",
                zone=zname,
                view=view,
                serving=dumped,
                file_serial=_soa_serial(live / _zone_rel(zname, view)),
                waited_s=_ZONE_DUMP_TIMEOUT_S,
            )
        for (zname, view), serving in frozen.items():
            staged = new_dir / _zone_rel(zname, view)
            serial = _soa_serial(staged)
            if serving is None or serial is None or _serial_later(serial, serving):
                continue
            # Past 2**32 - 1 the next serial is 0, which the render reads as
            # "no serial" (``_write_zone_file``); 1 is later too.
            later = (serving + 1) % 2**32 or 1
            if _set_rendered_serial(staged, later):
                log.info(
                    "bind9_zone_serial_moved_past_served",
                    zone=zname,
                    view=view,
                    rendered=serial,
                    serving=serving,
                    serial=later,
                )
        return frozen

    def _serving_serials(
        self, base: list[str], only: set[tuple[str, str | None]] | None
    ) -> dict[tuple[str, str | None], int | None]:
        """Each zone's serial as named serves it, BEFORE the reload.

        What ``_verify_zones_loaded`` needs to tell "named loaded a file
        whose serial was later still" from "named is still on the old zone,
        which happened to be ahead". A zone named does not serve yet (a new
        one) reads ``None``.
        """
        if not shutil.which("rndc"):
            return {}
        live = self.state_dir / self.rendered_dir_name
        zones = [zv for zv in _zone_views_under(live) if only is None or zv in only]

        def serial(zv: tuple[str, str | None]) -> int | None:
            zname, view = zv
            rc, stdout, _err = _rndc_run(
                base, "zonestatus", zname, *(["in", view] if view else [])
            )
            return _zonestatus_serial(stdout) if rc == 0 else None

        return dict(zip(zones, _parallel_map(serial, zones)))

    def _verify_zones_loaded(
        self,
        base: list[str],
        only: set[tuple[str, str | None]] | None,
        before: dict[tuple[str, str | None], int | None] | None = None,
        rendered: dict[tuple[str, str | None], int | None] | None = None,
    ) -> None:
        """Confirm named is serving what was just rendered (#1224, #1239).

        ``rndc reload <zone>`` queues the load and exits 0 whatever happens
        next; verified against BIND 9.20, a zone file named cannot parse
        still answers "zone reload queued". A failed load leaves the zone on
        its OLD serial, and a new zone that failed says "zone not loaded".
        So ask each zone for its serial until it matches the file, or give
        up at ``_ZONE_LOAD_TIMEOUT_S`` and raise.

        The expected serial is the render's, as staged before the swap
        (``rendered``), not the live file's read back after the reload. A
        freeze issued after the swap used to write named's own copy of a zone
        over the render, serial included, and reading the file back then
        passed named's copy as the render (#1407); the zones are now frozen
        before the swap (``_freeze_before_swap``), and this holds the apply
        to the render either way. A zone missing from ``rendered`` (or a call
        without it, as at first start) is checked against its live file. A
        serial later than the expected one is accepted too, since an RFC 2136
        update can land after the thaw, but only if it MOVED from what named
        served before the reload (``before``): a zone whose in-memory serial
        was already ahead of the render, and still reads that same serial,
        may never have loaded the render at all.

        An RPZ zone's serial is derived from its content (#2157), so a
        changed RPZ zone is verified here like any other; one rendered from a
        bundle with no content hash keeps the old constant serial 1, and its
        load is covered only by the pre-swap ``named-checkzone``.
        """
        if not shutil.which("rndc"):
            return
        live = self.state_dir / self.rendered_dir_name
        pending = {
            zv: (
                rendered[zv]
                if rendered is not None and zv in rendered
                else _soa_serial(live / _zone_rel(*zv))
            )
            for zv in _zone_views_under(live)
            if only is None or zv in only
        }
        total = len(pending)
        why: dict[tuple[str, str | None], str] = {}
        deadline = time.monotonic() + _ZONE_LOAD_TIMEOUT_S

        def check(item: tuple[tuple[str, str | None], int | None]) -> str | None:
            """None once the zone serves the render, else why not yet."""
            (zname, view), want = item
            rc, out, err = _rndc_run(
                base, "zonestatus", zname, *(["in", view] if view else [])
            )
            if rc != 0:
                return _first_line(err, out)
            got = _zonestatus_serial(out)
            prior = (before or {}).get((zname, view))
            loaded = (
                want is None
                or got == want
                or (
                    got is not None
                    and _serial_at_least(got, want)
                    and (prior is None or got != prior)
                )
            )
            return None if loaded else f"serving serial {got}, file has {want}"

        while pending:
            # Each pass asks every pending zone once, on the bounded pool (#2180).
            items = list(pending.items())
            for (zv, _want), reason in zip(items, _parallel_map(check, items)):
                if reason is None:
                    del pending[zv]
                else:
                    why[zv] = reason
            if not pending or time.monotonic() >= deadline:
                break
            time.sleep(_ZONE_LOAD_POLL_S)
        if pending:
            listed = [f"{_zone_label(*zv)}: {why.get(zv, 'no answer')}" for zv in pending]
            more = f" (and {len(listed) - 5} more)" if len(listed) > 5 else ""
            raise RuntimeError(
                "named did not load the new zone files: " + "; ".join(listed[:5]) + more
            )
        log.info("bind9_zones_verified", zones=total, selective=only is not None)

    def _sync_logging_runtime(self, base: list[str]) -> None:
        """Assert named's runtime query + response logging after a reconfig.

        ``rndc reconfig`` applies neither ``querylog`` nor ``responselog``.
        Both are live switches that reconfig deliberately leaves as the
        running server was last told, rather than stamping the file's value
        over an operator's ``rndc`` override. Verified against BIND 9.20:

        * ``responselog`` (issue #914, 9.20.26): the swapped-in config said
          ``responselog yes;``, the reconfig succeeded, and ``rndc status``
          still reported ``response logging is OFF``.
        * ``querylog`` (issue #2249, 9.20.29): the same, in both
          directions. A named started with query logging off stays off
          after a reconfig that adds the ``queries`` category, with or
          without ``querylog yes;``; one started with it on stays on after
          a reconfig that removes both. The #914 version of this method
          claimed query logging followed its category on reload. It does
          so only at startup, so enabling query logging on a running server
          logged nothing until named restarted, and with response logging
          on the control plane dropped every response line as an orphan.

        The desired state is read back off the config we just swapped in
        rather than threaded down from the bundle, so it cannot disagree
        with what named is actually running — the same reason #899 and
        #734 assert on the rendered config rather than the stored row.

        Best effort: a failure leaves the config-file value to take effect
        at the next restart, so it is logged rather than raised.
        """
        conf = self.state_dir / self.rendered_dir_name / "named.conf"
        try:
            text = conf.read_text()
        except OSError as exc:
            log.warning("rndc_logging_conf_unreadable", error=str(exc))
            return
        for switch in ("querylog", "responselog"):
            marker = re.search(rf"^\s*{switch}\s+yes\s*;", text, re.MULTILINE)
            desired = marker is not None
            res = subprocess.run(
                [*base, switch, "on" if desired else "off"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                # An older named has no ``responselog`` command at all, which
                # is a legitimate reason to land here — hence warning, not
                # error, and no exception.
                log.warning(
                    f"rndc_{switch}_failed",
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
        return _zone_views_under(self.state_dir / self.rendered_dir_name)

    def _changed_zones(
        self, new_dir: Path, prev_dir: Path
    ) -> set[tuple[str, str | None]] | None:
        """Which zones of the render in ``new_dir`` differ from the previous one.

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
        return _zones_differing(new_dir, prev_dir)

    def _reload_rendered_zones(
        self,
        base: list[str],
        only: set[tuple[str, str | None]] | None = None,
        already_frozen: Collection[tuple[str, str | None]] = (),
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
        rest from reloading. Whether each one actually loaded is decided
        afterwards by ``_verify_zones_loaded`` (#1224): ``rndc reload``
        exits 0 even for a file named cannot parse, so the return code here
        says nothing about the load.

        Two known subtleties, recorded so nobody chases them as bugs:

        * **Zones holding RFC 2136 updates.** ``freeze`` makes named write its
          in-memory zone into the zone's file, asynchronously. Issued here,
          after the swap, that write landed on the new render and the thaw
          loaded it, so the render never landed (#1407: a zone-level edit
          dropped, the served serial going backwards). ``swap_and_reload``
          therefore freezes every changed zone named serves before the swap
          and waits for that write (``_freeze_before_swap``); those zones
          arrive here in ``already_frozen`` and are only reloaded and thawed.
          The freeze here remains for the zones it could not freeze then: new
          to named, or not dynamic, where it fails harmlessly.
        * **DNSSEC inline-signed zones.** ``freeze``/``thaw`` semantics for
          inline-signed dynamic zones vary across BIND versions (older ones
          refuse, or do not re-read the raw zone on thaw). On BIND 9.20 it
          works: verified 2026-09-29, an edited inline-signed zone reloaded
          through freeze/reload/thaw and served the new record, with
          ``zonestatus`` reporting the raw serial first and the signed one
          after (which ``_zonestatus_serial`` relies on).
        """
        all_zones = self.rendered_zone_views()
        targets = all_zones if only is None else [z for z in all_zones if z in only]

        def reload(zv: tuple[str, str | None]) -> None:
            zname, view = zv
            scope = [zname] + (["in", view] if view else [])
            verbs = (
                ("reload", "thaw")
                if (zname, view) in already_frozen
                else ("freeze", "reload", "thaw")
            )
            froze_here = False
            try:
                for verb in verbs:
                    res = subprocess.run(
                        [*base, verb, *scope],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if verb == "freeze":
                        froze_here = res.returncode == 0
                    elif verb == "thaw":
                        froze_here = False
                    if res.returncode != 0 and verb == "reload":
                        log.warning(
                            "bind9_zone_reload_failed",
                            zone=zname,
                            view=view,
                            stderr=res.stderr.strip()[:200],
                        )
            except BaseException:
                # A zone this call froze must not stay frozen because a later
                # verb could not run; zones frozen before the swap are thawed
                # by ``swap_and_reload``'s own ``finally``.
                if froze_here:
                    _rndc_run(base, "thaw", *scope)
                raise

        # One zone's verbs stay in order; zones run on the bounded pool (#2180).
        _parallel_map(reload, targets)
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

    def _zone_rndc_scopes(self, zone: str) -> list[list[str]]:
        """The rndc zone arguments that address ``zone``: ``[zone, "IN", view]``
        for each view the last render placed it in, or ``[zone]`` without views
        (#1946). Read off the rendered tree, like ``rendered_zone_views``."""
        want = zone.rstrip(".").lower()
        views: list[str] = []
        if getattr(self, "state_dir", None) is not None:
            views = [
                v
                for z, v in self.rendered_zone_views()
                if v and z.rstrip(".").lower() == want
            ]
        return [[zone, "IN", v] for v in views] or [[zone]]

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
        mirror via ``rndc dnssec -status`` + a DS computed in-process from
        the KSK key files (#1854). Best effort — a zone still
        mid-key-generation, or whose DS BIND has not made submittable yet,
        reports empty DS, and the periodic refresh in the sync loop picks
        it up.
        """
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        # #1934 — set when some zone's keys could not be read yet (named not
        # answering, zone not keyed); the sync loop re-reads on a short timer
        # instead of the quiet-zone interval.
        self.dnssec_incomplete = False
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
                state = self._zone_dnssec_state(zname)
            except Exception as e:  # noqa: BLE001 — never let one zone block the rest
                log.warning("dnssec_state_collect_failed", zone=zname, error=str(e))
                self.dnssec_incomplete = True
                continue
            if not state["keys"]:
                self.dnssec_incomplete = True
            out.append(state)
        return out

    def _zone_dnssec_state(self, zone: str) -> dict[str, Any]:
        keys: list[dict[str, Any]] = []
        ds_records: list[str] = []
        if shutil.which("rndc"):
            res = subprocess.run(
                # #1946 — one view's copy under split-horizon (the key files
                # are shared); a bare zone name is ambiguous there.
                [*self._rndc_base(), "dnssec", "-status", *self._zone_rndc_scopes(zone)[0]],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                # Not "the zone has no keys": named is not answering for it
                # (still loading, zone not loaded). Reporting [] would wipe
                # the control plane's key rows on a guess (#1934).
                raise RuntimeError(f"rndc dnssec -status failed: {res.stderr.strip()[:200]}")
            keys = _parse_dnssec_status(res.stdout)
        # DS rrset(s) from the KSK public-key files BIND wrote into the
        # key-directory, computed in-process with dnspython (#1854). This
        # used to shell out to ``dnssec-dsfromkey`` behind a ``shutil.which``
        # guard, and the appliance image has no such binary (Alpine ships it
        # in a separate package), so every signed zone silently reported an
        # empty DS. No binary means nothing to be missing from an image.
        ds_records = _ds_from_key_dir(zone, DNSSEC_KEY_DIR)
        # Attach each DS to the key it was derived from, so the per-key UI
        # shows a key's own DS (and none for a key that is not submittable).
        by_tag: dict[int, list[str]] = {}
        for ds in ds_records:
            tag = _ds_key_tag(ds)
            if tag is not None:
                by_tag.setdefault(tag, []).append(ds)
        for k in keys:
            if k.get("key_type") in ("ksk", "csk"):
                k["ds_records"] = by_tag.get(k.get("key_tag"), [])
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
        # #1946 — under split-horizon the zone is loaded once per view that
        # holds it, and a bare ``rndc dnssec … <zone>`` then fails with "zone
        # was found in multiple views". Roll it in every view that holds it
        # (BIND 9.20: each view's copy rolls; the key files are shared).
        failures: list[str] = []
        for scope in self._zone_rndc_scopes(zone):
            cmd = [*self._rndc_base(), "dnssec", "-rollover", "-key", str(key_tag), *scope]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0:
                failures.append(f"{' '.join(scope)}: {res.stderr.strip()}")
        if failures:
            raise RuntimeError(f"rndc dnssec -rollover failed: {'; '.join(failures)}")
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
            alive = wait_for_daemon("named", self.daemon_pid)
        # ``wait_for_daemon`` also answers False on its visibility timeout (a
        # child still pre-``execve``, i.e. alive), so a False alone is not an
        # exit; ask whether the process is actually gone before saying so.
        if not alive and not self.daemon_running():
            # A zombie reads back as "named" too, so this used to log
            # ``named_started`` for a daemon that had already exited (#1239).
            # Logged, not raised: at boot the supervisor's liveness poll owns
            # the exit, and from ``swap_and_reload`` the caller checks.
            log.error("named_exited_during_startup", pid=self.daemon_pid)
            return
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
            proc = subprocess.run(
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
