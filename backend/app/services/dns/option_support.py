"""Which group options each DNS driver applies (#4562).

The Options tab and ``PUT /dns/groups/{id}/options`` are driver-agnostic, but
every driver honours only a subset: a value outside it was stored, shipped in
the bundle and ignored, so the console said one thing and the daemon did
another. This module is the one table of that subset. The API refuses a
*change* to an option a driver in the group does not apply, the options
response carries the group's slice of the table so the page disables what it
cannot offer, and ``test_dns_option_support_4562.py`` fails when an options
column or a registered driver has no decision here.

Three states:

* ``applied``: the driver renders or writes the option.
* ``partial``: applied, with a limit the note states (PowerDNS uses
  forwarders for ALIAS expansion only). Accepted; value-specific refusals
  live with the driver (``technitium_options.refusals``, the transport gates).
* ``not_applied``: no consumer. A change is refused unless it puts the option
  back to a value at which it does nothing (see :func:`inert_values`).

The agent-managed Technitium column is built from
``technitium_options.UNSUPPORTED_OPTIONS`` and the agentless drivers apply no
group option at all (``technitium_api_scope``, ``render_server_config``
returning ``""`` on Windows DNS and the cloud drivers), so those two existing
tables stay the source for their drivers.

A mixed-driver group gets what all of its drivers apply, like the blackhole
and transport gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models.dns import DNSServerOptions
from app.services.dns.technitium_options import UNSUPPORTED_OPTIONS as TECHNITIUM_UNSUPPORTED

APPLIED = "applied"
PARTIAL = "partial"
NOT_APPLIED = "not_applied"


@dataclass(frozen=True)
class Support:
    state: str
    #: Why it is not applied, or what part is. Empty for ``applied``.
    note: str = ""
    #: ``not_applied`` only: the values a change may still set. ``None`` means
    #: the column default; ``()`` means no value is true on this driver, so
    #: every real change is refused.
    inert: tuple[Any, ...] | None = None


#: Operator-facing name of every registered driver.
DRIVER_LABELS: dict[str, str] = {
    "bind9": "BIND9",
    "powerdns": "PowerDNS",
    "technitium": "Technitium",
    "technitium_api": "Technitium (agentless)",
    "windows_dns": "Windows DNS",
    "cloudflare": "Cloudflare",
    "route53": "Route 53",
    "azure_dns": "Azure DNS",
    "google_dns": "Google Cloud DNS",
    "digitalocean": "DigitalOcean",
    "hetzner": "Hetzner",
    "linode": "Linode",
    "vultr": "Vultr",
}

#: Bookkeeping columns, not settings.
IGNORED_COLUMNS = frozenset({"id", "group_id", "created_at", "modified_at"})

#: Every option column the table has to decide.
OPTION_FIELDS: tuple[str, ...] = tuple(
    c.key for c in DNSServerOptions.__table__.columns if c.key not in IGNORED_COLUMNS
)

#: ``DNSServerGroup`` fields that are settings a driver applies or does not.
#: ``is_recursive`` folds into the bundle's ``recursion_enabled``.
GROUP_FIELDS: tuple[str, ...] = ("is_recursive",)

_RECURSION_FIELDS = ("recursion_enabled", "is_recursive")

# ``channel`` / ``file`` / ``print-time`` are fixed on every driver: the query
# log shipper tails one file and reads each line's timestamp (#2265).
_FIXED = "fixed by SpatiumDDI (the query-log shipper reads one file with timestamps)"
_FIXED_FIELDS = ("query_log_channel", "query_log_file", "query_log_print_time")

_DNSDIST = "the dnsdist front is part of the PowerDNS image only"
_DNSDIST_FIELDS = (
    "dnsdist_enabled",
    "dnsdist_max_qps_per_client",
    "dnsdist_action",
    "dnsdist_dynblock_qps",
    "dnsdist_dynblock_seconds",
)

_BIND9_NOT_APPLIED: dict[str, str] = {
    **dict.fromkeys(_FIXED_FIELDS, _FIXED),
    **dict.fromkeys(_DNSDIST_FIELDS, _DNSDIST),
    "doq_enabled": "BIND9 has no DNS-over-QUIC listener",
    "doq_port": "BIND9 has no DNS-over-QUIC listener",
}
_BIND9_PARTIAL: dict[str, str] = {
    "forward_transport": "BIND9 forwards over do53 or tls only (no https or quic)",
}

_PDNS_AUTH = "PowerDNS authoritative does not recurse (there is no recursor)"
_PDNS_NO_FORWARD = (
    "PowerDNS authoritative does not forward client queries (forwarders feed "
    "ALIAS expansion only)"
)
_PDNS_RRL = "PowerDNS has no response rate limiting (use the dnsdist rate limit)"
_PDNS_LOG = "PowerDNS logs queries through its own log, with no channel settings"
_POWERDNS_NOT_APPLIED: dict[str, str] = {
    **dict.fromkeys(_FIXED_FIELDS, _FIXED),
    "forward_policy": _PDNS_NO_FORWARD,
    "forward_tls_hostname": _PDNS_NO_FORWARD,
    "forward_tls_verify": _PDNS_NO_FORWARD,
    "recursion_enabled": _PDNS_AUTH,
    "is_recursive": _PDNS_AUTH,
    "allow_recursion": _PDNS_AUTH,
    "dnssec_validation": "PowerDNS authoritative does not validate (it does not resolve)",
    "allow_notify": "PowerDNS has no allow-notify list rendered from the group",
    "allow_query": "PowerDNS authoritative has no client query ACL",
    "allow_query_cache": "PowerDNS has no cache-access ACL",
    "blackhole": "PowerDNS authoritative has no setting to drop queries from a client address",
    "response_log_enabled": "PowerDNS has no response logging",
    "query_log_severity": _PDNS_LOG,
    "query_log_print_category": _PDNS_LOG,
    "query_log_print_severity": _PDNS_LOG,
    "rrl_enabled": _PDNS_RRL,
    "rrl_responses_per_second": _PDNS_RRL,
    "rrl_window": _PDNS_RRL,
    "rrl_slip": _PDNS_RRL,
    "rrl_qps_scale": _PDNS_RRL,
    "rrl_exempt_clients": _PDNS_RRL,
    "rrl_log_only": _PDNS_RRL,
    "minimal_responses": "PowerDNS has no minimal-responses setting",
    "tcp_clients": "PowerDNS has no TCP client limit rendered from the group",
    "clients_per_query": "PowerDNS has no clients-per-query setting",
    "max_clients_per_query": "PowerDNS has no clients-per-query setting",
    "doq_enabled": "the PowerDNS dnsdist front has no DNS-over-QUIC listener",
    "doq_port": "the PowerDNS dnsdist front has no DNS-over-QUIC listener",
}
_POWERDNS_PARTIAL: dict[str, str] = {
    "forwarders": "PowerDNS uses forwarders only to expand ALIAS records; it does not "
    "forward client queries",
    "forward_transport": "only plain-DNS (do53) forwarders feed PowerDNS ALIAS expansion",
    "allow_transfer": "PowerDNS applies addresses and keys; a negated element is dropped",
}

_TECHNITIUM_NOT_APPLIED: dict[str, str] = {
    **dict.fromkeys(_FIXED_FIELDS, _FIXED),
    **{field: why for field, (_default, why) in TECHNITIUM_UNSUPPORTED.items()},
}
_TECHNITIUM_PARTIAL: dict[str, str] = {
    "forward_policy": "Technitium resolves only through its forwarders ('only'); it "
    "never falls back to recursion",
    "forward_transport": "an encrypted transport needs forward_tls_hostname on Technitium",
    "also_notify": "Technitium notifies bare IP addresses only",
    "allow_query": "applied per zone, for the address-match grammar Technitium can express",
    "allow_transfer": "applied per zone, for the address-match grammar Technitium can express",
}

#: Drivers that write zones and records only: no group option reaches them.
_UNMANAGED: dict[str, str] = {
    "technitium_api": "the agentless Technitium driver writes zones and records only; "
    "set it in the Technitium console, or use the agent-managed 'technitium' driver",
    "windows_dns": "SpatiumDDI writes zones and records to Windows DNS, not server "
    "settings; set it on the Windows server",
    **{
        name: f"{DRIVER_LABELS[name]} is a hosted authoritative service with no server "
        "settings to write"
        for name in (
            "cloudflare",
            "route53",
            "azure_dns",
            "google_dns",
            "digitalocean",
            "hetzner",
            "linode",
            "vultr",
        )
    },
}

#: Unmanaged servers whose own recursion SpatiumDDI neither sets nor reads, so
#: neither "on" nor "off" is a true statement about them. (PowerDNS and the
#: hosted services never recurse, so "off" is true there.)
_RECURSION_UNKNOWN = frozenset({"technitium_api", "windows_dns"})


# What each agent driver renders or writes in full. Named, not inferred: a new
# options column is in none of a driver's three sets, so it lands in
# ``UNDECIDED`` and the guard test fails until someone reads the renderer and
# picks one. (At runtime an undecided column is treated as applied, so a
# missed decision never refuses a working setting.)
_LISTENER_FIELDS = (
    "dot_enabled",
    "dot_port",
    "doh_enabled",
    "doh_port",
    "doh_path",
    "tls_certificate_id",
)
_BIND9_APPLIED = frozenset(
    {
        *_LISTENER_FIELDS,
        "forwarders",
        "forward_policy",
        "forward_tls_hostname",
        "forward_tls_verify",
        "recursion_enabled",
        "is_recursive",
        "allow_recursion",
        "dnssec_validation",
        "notify_enabled",
        "also_notify",
        "allow_notify",
        "allow_query",
        "allow_query_cache",
        "allow_transfer",
        "blackhole",
        "query_log_enabled",
        "query_log_severity",
        "query_log_print_category",
        "query_log_print_severity",
        "response_log_enabled",
        "rrl_enabled",
        "rrl_responses_per_second",
        "rrl_window",
        "rrl_slip",
        "rrl_qps_scale",
        "rrl_exempt_clients",
        "rrl_log_only",
        "minimal_responses",
        "tcp_clients",
        "clients_per_query",
        "max_clients_per_query",
    }
)
_POWERDNS_APPLIED = frozenset(
    {*_LISTENER_FIELDS, *_DNSDIST_FIELDS, "notify_enabled", "also_notify", "query_log_enabled"}
)
_TECHNITIUM_APPLIED = frozenset(
    {
        *_LISTENER_FIELDS,
        "doq_enabled",
        "doq_port",
        "forwarders",
        "forward_tls_hostname",
        "recursion_enabled",
        "is_recursive",
        "allow_recursion",
        "dnssec_validation",
        "notify_enabled",
        "rrl_enabled",
        "rrl_responses_per_second",
        "rrl_window",
        "rrl_slip",
        "rrl_exempt_clients",
    }
)

#: driver -> fields with no decision. Must stay empty (the guard test).
UNDECIDED: dict[str, list[str]] = {}
#: driver -> fields named in more than one of its three sets.
CONFLICTING: dict[str, list[str]] = {}


def _column(
    driver: str,
    applied: frozenset[str],
    not_applied: dict[str, str],
    partial: dict[str, str],
    *,
    recursion_off: bool = False,
) -> dict[str, Support]:
    """One driver's column, from its three named sets."""
    out: dict[str, Support] = {}
    for field in (*OPTION_FIELDS, *GROUP_FIELDS):
        named = (field in applied) + (field in not_applied) + (field in partial)
        if named == 0:
            UNDECIDED.setdefault(driver, []).append(field)
        elif named > 1:
            CONFLICTING.setdefault(driver, []).append(field)
        if field in not_applied:
            inert = (False,) if recursion_off and field in _RECURSION_FIELDS else None
            out[field] = Support(NOT_APPLIED, not_applied[field], inert)
        elif field in partial:
            out[field] = Support(PARTIAL, partial[field])
        else:
            out[field] = Support(APPLIED)
    return out


def _unmanaged_column(driver: str) -> dict[str, Support]:
    why = _UNMANAGED[driver]
    out = {f: Support(NOT_APPLIED, why) for f in (*OPTION_FIELDS, *GROUP_FIELDS)}
    for field in _RECURSION_FIELDS:
        out[field] = Support(NOT_APPLIED, why, () if driver in _RECURSION_UNKNOWN else (False,))
    return out


#: driver -> field -> decision. The one table.
OPTION_SUPPORT: dict[str, dict[str, Support]] = {
    "bind9": _column("bind9", _BIND9_APPLIED, _BIND9_NOT_APPLIED, _BIND9_PARTIAL),
    # ``recursion_enabled`` defaults to on, which PowerDNS never is: "off" is
    # the value a change may set, and a stored "on" re-saves untouched.
    "powerdns": _column(
        "powerdns",
        _POWERDNS_APPLIED,
        _POWERDNS_NOT_APPLIED,
        _POWERDNS_PARTIAL,
        recursion_off=True,
    ),
    "technitium": _column(
        "technitium", _TECHNITIUM_APPLIED, _TECHNITIUM_NOT_APPLIED, _TECHNITIUM_PARTIAL
    ),
    **{driver: _unmanaged_column(driver) for driver in _UNMANAGED},
}

#: What the hand-written dicts above name, for the guard test: a field named
#: there that is not an options column is a typo that would decide nothing.
DECLARED_FIELDS: frozenset[str] = frozenset(
    {
        *_BIND9_APPLIED,
        *_POWERDNS_APPLIED,
        *_TECHNITIUM_APPLIED,
        *_BIND9_NOT_APPLIED,
        *_BIND9_PARTIAL,
        *_POWERDNS_NOT_APPLIED,
        *_POWERDNS_PARTIAL,
        *_TECHNITIUM_NOT_APPLIED,
        *_TECHNITIUM_PARTIAL,
    }
)


def label(driver: str) -> str:
    return DRIVER_LABELS.get(driver, driver)


def support(driver: str, field: str) -> Support:
    """The decision for one (driver, field). ``KeyError`` when there is none."""
    return OPTION_SUPPORT[driver][field]


def applies_no_option(driver: str) -> bool:
    return driver in _UNMANAGED


def column_default(field: str) -> Any:
    col = DNSServerOptions.__table__.c[field]
    default = col.default
    if default is None:
        return None
    if getattr(default, "is_scalar", False):
        return default.arg
    if getattr(default, "is_callable", False):
        # SQLAlchemy wraps a column default callable to take the exec context.
        return default.arg(None)
    return None


def inert_values(driver: str, field: str) -> tuple[Any, ...]:
    """The values a change may set on an option ``driver`` does not apply."""
    entry = support(driver, field)
    if entry.inert is not None:
        return entry.inert
    if driver == "technitium" and field in TECHNITIUM_UNSUPPORTED:
        return (TECHNITIUM_UNSUPPORTED[field][0],)
    if field in GROUP_FIELDS:
        return ()
    return (column_default(field),)


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == []


def _same(value: Any, other: Any) -> bool:
    return value == other or (_empty(value) and _empty(other))


def _is_inert(driver: str, field: str, value: Any) -> bool:
    return any(_same(value, v) for v in inert_values(driver, field))


def refusals(driver: str, changes: dict[str, Any], stored: Any) -> list[str]:
    """``field: why`` for each change to an option ``driver`` does not apply.

    Transition-only: re-saving the stored value passes (the form posts every
    field on every save), and so does setting an inert value, which is the way
    out of one stored before the gate. An unregistered driver decides nothing.
    """
    column = OPTION_SUPPORT.get(driver)
    if column is None:
        return []
    out: list[str] = []
    for field, value in changes.items():
        entry = column.get(field)
        if entry is None or entry.state != NOT_APPLIED:
            continue
        baseline = getattr(stored, field, None) if stored is not None else column_default(field)
        if _same(value, baseline) or _is_inert(driver, field, value):
            continue
        out.append(f"{field}: {entry.note}")
    return out


def refusal_message(driver: str, refused: list[str]) -> str:
    name = label(driver)
    return (
        f"This group has a {name} server, which cannot apply: "
        + "; ".join(refused)
        + f". Move the {name} server to its own group, or leave these at their defaults."
    )


def stored_warnings(driver: str, stored: Any) -> list[str]:
    """Stored values ``driver`` will not apply: saved before the gate, or
    before the server joined the group. Column defaults are left out (a fresh
    group stores recursion on); the page's per-field note covers those."""
    column = OPTION_SUPPORT.get(driver)
    if column is None or stored is None:
        return []
    out = []
    for field in OPTION_FIELDS:
        entry = column[field]
        if entry.state != NOT_APPLIED:
            continue
        value = getattr(stored, field, None)
        if _same(value, column_default(field)) or _is_inert(driver, field, value):
            continue
        out.append(f"{field}: {entry.note}")
    return out


def group_support(
    drivers: list[str] | set[str], stored: Any, fields: tuple[str, ...] = OPTION_FIELDS
) -> dict[str, dict[str, Any]]:
    """The group's slice of the table, for the options page.

    One entry per field some driver in the group applies partially or not at
    all (an applied field is absent). ``locked`` is true when the page should
    disable the control: a driver does not apply it and the stored value is
    already inert. A stored value that is not stays editable, so it can be
    cleared.
    """
    out: dict[str, dict[str, Any]] = {}
    for field in fields:
        states: list[tuple[str, Support]] = []
        for driver in sorted(drivers):
            entry = OPTION_SUPPORT.get(driver, {}).get(field)
            if entry is not None and entry.state != APPLIED:
                states.append((driver, entry))
        if not states:
            continue
        not_applied = [(d, e) for d, e in states if e.state == NOT_APPLIED]
        shown = not_applied or states
        value = getattr(stored, field, None) if stored is not None else None
        out[field] = {
            "state": NOT_APPLIED if not_applied else PARTIAL,
            "drivers": [label(d) for d, _ in shown],
            "note": "; ".join(dict.fromkeys(e.note for _, e in shown)),
            "locked": any(
                not inert_values(d, field) or _is_inert(d, field, value) for d, _ in not_applied
            ),
        }
    return out


def unmanaged_note(drivers: list[str] | set[str]) -> str | None:
    """One line for a group whose driver applies no option at all."""
    for driver in sorted(drivers):
        if applies_no_option(driver):
            return (
                f"This group has a {label(driver)} server, so the options here are not "
                f"applied: {_UNMANAGED[driver]}."
            )
    return None


def group_field_note(drivers: list[str] | set[str], field: str) -> str | None:
    """Why a ``DNSServerGroup`` field does nothing on this group, or None."""
    for driver in sorted(drivers):
        entry = OPTION_SUPPORT.get(driver, {}).get(field)
        if entry is not None and entry.state == NOT_APPLIED:
            return f"Not applied on {label(driver)}: {entry.note}."
    return None
