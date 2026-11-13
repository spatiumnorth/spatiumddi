"""Pydantic request/response models for the built-in network tools (#58).

Lives in the service layer (not the api layer) so the runner +
socket_tools modules can import the result models + ``validate_host``
without creating a circular import back through the
``app.api.v1.tools`` package ``__init__`` (which imports the router,
which imports these services). The api layer re-exports everything from
``app.api.v1.tools.schemas`` for handler convenience.

Every request model validates its target / port / record-type input
tightly enough that the argv builders in
:mod:`app.services.nettools.runner` can pass values straight through to
``create_subprocess_exec`` without risk of shell injection. The
validators mirror the nmap runner's ``_validate_target`` /
``_validate_port_spec`` model — a literal IPv4/IPv6 address, a CIDR, or
an RFC 1123 hostname, nothing else.

Responses are deliberately thin and uniform: each tool returns the
resolved ``argv`` (so operators see exactly what ran), an ``exit_code``,
timing, and the captured stdout/stderr. The socket-based tools
(port-test, TLS-cert) return structured fields instead.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import uuid
from typing import Final, Literal

from pydantic import BaseModel, Field, field_validator

# ── shared validators ──────────────────────────────────────────────

# RFC 1123 / 952 hostname — same shape the nmap runner accepts. Labels
# of [A-Za-z0-9-] up to 63 chars, joined by dots, optional trailing dot.
_HOSTNAME_RE: Final = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)

# dig record types we expose — same curated list as the DNS propagation
# tool plus a couple query-only extras (ANY, NAPTR, DS, DNSKEY).
_VALID_RECORD_TYPES: Final[frozenset[str]] = frozenset(
    {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "TXT",
        "NS",
        "SOA",
        "PTR",
        "SRV",
        "CAA",
        "TLSA",
        "DS",
        "DNSKEY",
        "NAPTR",
        "ANY",
    }
)


def validate_host(value: str) -> str:
    """Accept a literal IPv4/IPv6 address or an RFC 1123 hostname.

    Rejects CIDR, shell metacharacters, spaces, and anything that isn't
    a valid DNS label / IP literal. Raised as a Pydantic ``ValueError``
    so it surfaces as a 422.
    """
    value = value.strip()
    if not value:
        raise ValueError("host is required")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value):
        return value
    raise ValueError(f"host must be a valid IPv4/IPv6 address or hostname (got {value!r})")


# ── SSRF denylist for socket-connecting tools ───────────────────────
#
# Tools that *open a socket from the server* (port-test, tls-cert) or
# steer a resolver / @server parameter (dig @server, DNS propagation)
# must not be aimable at the host's own loopback or the link-local
# range — the latter includes the cloud instance-metadata IP
# (169.254.169.254) that on AWS / Azure / GCP hands out credentials and
# user-data. We block:
#
#   * loopback   — 127.0.0.0/8, ::1
#   * link-local — 169.254.0.0/16 (covers the metadata IP), fe80::/10
#
# We deliberately do NOT block RFC 1918 (10/8, 172.16/12, 192.168/16) or
# unique-local IPv6 (fc00::/7): diagnosing the *internal* network is the
# entire point of these tools, so a private-range block would gut the
# feature. The block is unconditional (no platform setting) since there
# is never a legitimate diagnostic reason to socket-connect the api
# container's own loopback or the metadata endpoint through these tools.
_BLOCKED_NETWORKS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # 0.0.0.0 (and ::) — the kernel routes a connect() to these to
    # loopback, so they're an SSRF bypass of the 127/8 block.
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
)


def _numeric_ipv4(value: str) -> ipaddress.IPv4Address | None:
    """Parse the short / decimal / hex / octal IPv4 spellings the system
    resolver accepts (``127.1``, ``2130706433``, ``0x7f000001``)."""
    try:
        return ipaddress.IPv4Address(socket.inet_ntoa(socket.inet_aton(value)))
    except (OSError, ValueError, UnicodeError):
        return None


def is_blocked_target(value: str) -> bool:
    """Return True if ``value`` is a blocked address, however it is spelled.

    Covers IP literals, the non-canonical numeric IPv4 forms the system
    resolver accepts (``127.1``, ``2130706433``, ``0x7f000001``) and the
    ``localhost`` names. Any other hostname returns False here — a name that
    DNS maps into a blocked range is caught where the name is resolved
    (:func:`resolve_checked_target`).
    """
    value = value.strip().rstrip(".")
    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(value)
    except ValueError:
        lowered = value.lower()
        if lowered == "localhost" or lowered.endswith(".localhost"):
            return True
        numeric = _numeric_ipv4(value)
        if numeric is None:
            return False
        ip = numeric
    # ``ip.ipv4_mapped`` unwraps ::ffff:127.0.0.1 etc so a mapped
    # loopback / link-local can't sneak past the v4 networks.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip in net for net in _BLOCKED_NETWORKS)


async def resolve_checked_target(host: str) -> tuple[str | None, str | None]:
    """Resolve ``host`` once; return ``(address, None)`` or ``(None, error)``.

    Every answer is checked and ONE blocked answer refuses the name. Callers
    connect to the returned address, not the name, so the address that was
    checked is the address dialled.
    """
    blocked = (
        f"target {host!r} is in a blocked range (loopback / link-local / "
        "cloud-metadata) and cannot be reached by this tool"
    )
    if is_blocked_target(host):
        return None, blocked
    canonical = host.strip()
    numeric = _numeric_ipv4(canonical)
    if numeric is not None:
        canonical = str(numeric)
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            canonical, None, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError) as exc:
        return None, f"DNS resolution failed: {exc}"
    chosen: str | None = None
    for info in infos:
        addr = info[4][0]
        if not isinstance(addr, str):
            continue
        if is_blocked_target(addr.split("%", 1)[0]):
            return None, blocked
        if chosen is None:
            chosen = addr
    if chosen is None:
        return None, f"{host!r} did not resolve to a usable address"
    return chosen, None


def assert_target_allowed(value: str) -> str:
    """Validate ``value`` as a host AND reject blocked-range IP literals.

    Use this (not the bare :func:`validate_host`) for any tool that
    opens a socket from the server or steers a resolver / @server
    parameter: port-test, tls-cert, dig ``@server``, DNS-propagation
    resolvers. A plain ``dig <name>`` against the default resolver does
    NOT route through here — only the network-reaching parameters do.

    Returns the normalised host on success; raises ``ValueError`` (→ 422
    for Pydantic callers) on a blocked literal.

    Hostnames are checked for shape here and, for the socket tools, resolved
    and checked again at connect time (:func:`resolve_checked_target`).
    """
    host = validate_host(value)
    if is_blocked_target(host):
        raise ValueError(
            f"target {host!r} is in a blocked range (loopback / link-local / "
            "cloud-metadata) and cannot be reached by this tool"
        )
    return host


def validate_host_or_cidr(value: str) -> str:
    """Like :func:`validate_host` but also accepts a CIDR (for traceroute /
    ping where the operator may target a network address). Falls back to
    the host validator otherwise."""
    value = value.strip()
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"not a valid CIDR: {value!r} ({exc})") from exc
        return str(net.network_address)
    return validate_host(value)


# ── tool vantage target (agent-perspective dispatch) ────────────────
#
# The optional ``target`` on a reachability request selects WHERE the
# tool runs. ``kind="server"`` (the default when ``target`` is omitted)
# is today's behaviour — the api container runs the tool inline.
# ``kind="appliance"`` dispatches the (server-re-validated) job to a
# supervisor-managed Fleet appliance over the existing outbound poll
# channel and labels the result ``ran_from="appliance:<name>"``.
# ``kind="bgp_lg_collector"`` (#566 Phase 4) resolves ``id`` to a
# ``LookingGlassCollector`` row and dispatches to the appliance it runs on
# (the collector container shares the node's network namespace via
# ``network_mode: host`` / ``hostNetwork: true``), labelling the result
# ``ran_from="looking_glass:<collector-name>"``. Rejected with a 400 when
# the collector isn't appliance-managed (standalone docker/K8s deployment
# — no dispatchable command channel).
#
# The ``Literal`` already lists ``dns_agent`` / ``dhcp_agent`` so the
# wire shape is forward-compatible: the DNS / DHCP service-container
# vantage is a deferred follow-up (the router rejects those kinds until
# their dispatch path lands), but a client serialising one today won't
# fail validation. Only ``server`` + ``appliance`` + ``bgp_lg_collector``
# are wired today.


class NetToolTarget(BaseModel):
    """Where to run a reachability tool from.

    ``id`` identifies the appliance (or, later, the DNS/DHCP agent) row
    when ``kind != "server"``; it's ignored — and may be omitted — for
    ``kind="server"``. ``kind="bgp_lg_collector"`` (#566 Phase 4) resolves
    ``id`` to a ``LookingGlassCollector`` row and dispatches to the
    appliance it runs on — see ``app.api.v1.tools.router
    ._resolve_lg_collector_vantage``.
    """

    kind: Literal["server", "appliance", "dns_agent", "dhcp_agent", "bgp_lg_collector"] = "server"
    id: uuid.UUID | None = None


# ── ping / traceroute / mtr ─────────────────────────────────────────


class HostRequest(BaseModel):
    """Shared single-host request shape for ping / traceroute / mtr."""

    host: str = Field(min_length=1, max_length=253)
    # Optional run-from vantage. None ⇒ run on the api container (server),
    # i.e. exactly today's behaviour. See NetToolTarget above.
    target: NetToolTarget | None = None
    # Proceed against a scope marked do-not-probe (#722). Superadmin
    # only, audited, per-request. Routing-only like ``target`` — it is
    # stripped before the params are shipped to an appliance vantage,
    # because the decision is made here and the supervisor has no
    # business re-deciding it.
    override_do_not_probe: bool = False

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str) -> str:
        return validate_host(v)


class CommandResult(BaseModel):
    """Uniform subprocess result. ``available`` is False when the binary
    is missing — handlers surface this as a clean 200 with the reason in
    ``error`` rather than a 500."""

    tool: str
    argv: list[str]
    available: bool
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: float | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    # Which vantage produced this result. "server" for the api-container
    # run (the default / back-compatible path); "appliance:<name>" when a
    # Fleet appliance ran it. The router stamps this after dispatch so the
    # UI can label the vantage without re-deriving it.
    ran_from: str = "server"


# ── dig ─────────────────────────────────────────────────────────────


class DigRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    record_type: str = Field(default="A")
    # Optional resolver to query (``@server``). When null dig uses the
    # server's /etc/resolv.conf.
    server: str | None = Field(default=None, max_length=253)
    # Optional run-from vantage. None ⇒ server. See NetToolTarget.
    target: NetToolTarget | None = None

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        # A DNS name is hostname-shaped; reuse the host validator but
        # allow a leading underscore label (e.g. _dmarc, _acme-challenge)
        # which is valid in DNS but not in RFC 1123 host syntax.
        candidate = v.lstrip("_")
        if candidate and _HOSTNAME_RE.match(candidate.replace("_", "a")):
            return v
        if _HOSTNAME_RE.match(v):
            return v
        raise ValueError(f"name is not a valid DNS name: {v!r}")

    @field_validator("record_type")
    @classmethod
    def _v_type(cls, v: str) -> str:
        u = v.strip().upper()
        if u not in _VALID_RECORD_TYPES:
            raise ValueError(
                f"Unsupported record type. Allowed: {', '.join(sorted(_VALID_RECORD_TYPES))}"
            )
        return u

    @field_validator("server")
    @classmethod
    def _v_server(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        # @server steers where dig sends the query — apply the SSRF
        # denylist so it can't be aimed at loopback / metadata.
        return assert_target_allowed(v)


# ── whois ───────────────────────────────────────────────────────────


class WhoisRequest(BaseModel):
    query: str = Field(min_length=1, max_length=253)

    @field_validator("query")
    @classmethod
    def _v_query(cls, v: str) -> str:
        # whois accepts an IP, a domain, or an ASN ("AS13335"). Validate
        # against the host shape (covers IP + domain); allow a leading
        # "AS"/"as" + digits for ASN queries.
        v = v.strip()
        if not v:
            raise ValueError("query is required")
        if re.fullmatch(r"(?i:as)?\d{1,10}", v):
            return v
        return validate_host(v)


# ── port test ───────────────────────────────────────────────────────


class PortTestRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp")
    timeout_seconds: float = Field(default=5.0, ge=0.5, le=15.0)
    # Optional run-from vantage. None ⇒ server. See NetToolTarget.
    target: NetToolTarget | None = None
    # See HostRequest.override_do_not_probe (#722).
    override_do_not_probe: bool = False

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str) -> str:
        # port-test opens a socket from the server → SSRF denylist.
        return assert_target_allowed(v)

    @field_validator("protocol")
    @classmethod
    def _v_proto(cls, v: str) -> str:
        u = v.strip().lower()
        if u not in {"tcp", "udp"}:
            raise ValueError("protocol must be 'tcp' or 'udp'")
        return u


class PortTestResult(BaseModel):
    host: str
    port: int
    protocol: str
    # tcp: "open" | "closed" | "filtered" | "error"
    # udp: "open|filtered" | "closed" | "error" (UDP can't be definitive)
    state: str
    rtt_ms: float | None = None
    error: str | None = None
    # See CommandResult.ran_from. "server" default → back-compatible.
    ran_from: str = "server"


# ── TLS certificate inspection ──────────────────────────────────────


class TlsCertRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    # Optional SNI override; defaults to ``host`` when null.
    server_name: str | None = Field(default=None, max_length=253)
    timeout_seconds: float = Field(default=8.0, ge=0.5, le=15.0)
    # Optional run-from vantage. None ⇒ server. See NetToolTarget.
    target: NetToolTarget | None = None
    # See HostRequest.override_do_not_probe (#722).
    override_do_not_probe: bool = False

    @field_validator("host")
    @classmethod
    def _v_host(cls, v: str) -> str:
        # tls-cert opens a TLS socket from the server → SSRF denylist.
        return assert_target_allowed(v)

    @field_validator("server_name")
    @classmethod
    def _v_sni(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        return validate_host(v)


class TlsCertResult(BaseModel):
    host: str
    port: int
    server_name: str | None
    ok: bool
    subject: str | None = None
    issuer: str | None = None
    san: list[str] = []
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    expired: bool = False
    self_signed: bool = False
    hostname_matches: bool | None = None
    serial: str | None = None
    signature_algorithm: str | None = None
    error: str | None = None
    # See CommandResult.ran_from. "server" default → back-compatible.
    ran_from: str = "server"


# ── DNS propagation (reuses the dns_tools helper) ───────────────────


class PropagationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    record_type: str = Field(default="A")
    resolvers: list[str] | None = Field(default=None, max_length=12)
    timeout_seconds: float = Field(default=3.0, ge=0.5, le=10.0)

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        candidate = v.lstrip("_").replace("_", "a")
        if candidate and _HOSTNAME_RE.match(candidate):
            return v.rstrip(".")
        raise ValueError(f"name is not a valid DNS name: {v!r}")

    @field_validator("record_type")
    @classmethod
    def _v_type(cls, v: str) -> str:
        u = v.strip().upper()
        if u not in _VALID_RECORD_TYPES:
            raise ValueError(
                f"Unsupported record type. Allowed: {', '.join(sorted(_VALID_RECORD_TYPES))}"
            )
        return u

    @field_validator("resolvers")
    @classmethod
    def _v_resolvers(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        # Each resolver is a target the server sends DNS queries to →
        # SSRF denylist so a resolver can't be pointed at loopback /
        # metadata.
        return [assert_target_allowed(ip) for ip in v]


# ── MAC vendor lookup (reuses services/oui) ─────────────────────────


class MacVendorRequest(BaseModel):
    macs: list[str] = Field(min_length=1, max_length=256)


class MacVendorEntry(BaseModel):
    mac: str
    vendor: str | None = None
    is_voip_phone: bool = False


class MacVendorResult(BaseModel):
    # ``oui_enabled`` surfaces the platform-settings short-circuit so the
    # UI can explain "OUI lookup is disabled" instead of rendering empty
    # vendor cells.
    oui_enabled: bool
    entries: list[MacVendorEntry]


# ── firewall logs (appliance-diagnostic, #404) ──────────────────────
#
# Not a reachability probe: it serves the supervisor's kmsg-tailed
# nftables drop-log buffer. The api container can't read host kernel
# logs, so this ALWAYS runs from an appliance vantage (the router rejects
# a server target). ``since_seq`` is the incremental cursor.


class FirewallLogsRequest(BaseModel):
    target: NetToolTarget | None = None
    since_seq: int = Field(default=0, ge=0)
    limit: int = Field(default=200, ge=1, le=1000)


class FirewallLogLine(BaseModel):
    seq: int
    ts_us: int
    text: str


class FirewallLogsResult(BaseModel):
    # False when the supervisor couldn't open /dev/kmsg.
    available: bool = False
    lines: list[FirewallLogLine] = []
    # Newest kernel sequence seen — pass back as ``since_seq`` to poll for
    # just-arrived lines.
    cursor: int = 0
    error: str | None = None
    # See CommandResult.ran_from — stamped "appliance:<name>" after dispatch.
    ran_from: str = "server"


__all__ = [
    "CommandResult",
    "DigRequest",
    "FirewallLogLine",
    "FirewallLogsRequest",
    "FirewallLogsResult",
    "HostRequest",
    "MacVendorEntry",
    "MacVendorRequest",
    "MacVendorResult",
    "NetToolTarget",
    "PortTestRequest",
    "PortTestResult",
    "PropagationRequest",
    "TlsCertRequest",
    "TlsCertResult",
    "WhoisRequest",
    "assert_target_allowed",
    "is_blocked_target",
    "resolve_checked_target",
    "validate_host",
    "validate_host_or_cidr",
]
