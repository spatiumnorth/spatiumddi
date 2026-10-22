"""Abstract DNS driver base class and neutral data structures.

The control-plane DNS driver is a *thin* translator: it takes SpatiumDDI DB
models and emits a canonical, backend-neutral `ConfigBundle` (plus per-record
`RecordChange` ops). The actual daemon lifecycle (nsupdate, rndc) runs
inside the agent container — see ``docs/deployment/DNS_AGENT.md`` §3.

CLAUDE.md non-negotiable #10: no daemon specifics leak into the service
layer. The service layer calls ``get_driver(server.driver)`` and receives a
``DNSDriver`` instance whose public methods speak only in neutral types.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Literal

# ── Neutral record / zone data shapes ──────────────────────────────────────


@dataclass(frozen=True)
class RecordData:
    """A single DNS resource record, relative to its zone."""

    name: str  # relative label ("@" = apex)
    record_type: str  # A | AAAA | CNAME | MX | TXT | NS | PTR | SRV | CAA | ...
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


@dataclass(frozen=True)
class ZoneData:
    name: str  # FQDN with trailing dot, e.g. "example.com."
    zone_type: str  # primary | secondary | stub | forward
    kind: str  # forward | reverse
    ttl: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    primary_ns: str
    admin_email: str
    serial: int
    records: tuple[RecordData, ...] = ()
    allow_query: tuple[str, ...] | None = None
    allow_transfer: tuple[str, ...] | None = None
    also_notify: tuple[str, ...] | None = None
    notify_enabled: str | None = None
    view_name: str | None = None
    # Forward-zone fields. Only meaningful when ``zone_type == "forward"``;
    # ignored otherwise. ``forwarders`` is the upstream resolver list and
    # ``forward_only`` toggles "forward only;" (true) vs "forward first;"
    # (false — the resolver may fall back to recursion if all forwarders fail).
    forwarders: tuple[str, ...] = ()
    forward_only: bool = True
    # The forward zone's own upstream transport (#2121) — NOT the group's
    # ``ServerOptions.forward_transport``, which applies to the group's
    # resolver forwarders only. ``forward_tls_hostname`` is the upstream
    # certificate name, required for every encrypted transport.
    forward_transport: str = "do53"
    forward_tls_hostname: str | None = None
    # Secondary / stub primaries (issue #336). The master server IPs this
    # zone transfers FROM, as ``ip`` or ``ip@port`` strings. Required +
    # non-empty for ``zone_type`` in {secondary, stub} — the BIND9 renderer
    # emits ``primaries { <ip> [port <n>]; … };`` from this. Ignored for
    # primary / forward zones. Defaulted empty so existing constructors keep
    # working.
    masters: tuple[str, ...] = ()
    # DNSSEC inline-signing (issue #49). When ``dnssec_enabled`` the BIND9
    # driver renders ``dnssec-policy "<dnssec_policy_name>"; inline-signing
    # yes;`` into the zone stanza and BIND auto-signs. ``dnssec_policy_name``
    # is None ⇒ BIND's built-in ``default`` policy. Only consulted for
    # primary zones; PowerDNS ignores both (online-signing is op-driven).
    dnssec_enabled: bool = False
    dnssec_policy_name: str | None = None
    # Operator-configurable dynamic-update ACL (issue #641). When
    # ``dynamic_update_enabled`` the driver renders backend-specific
    # authorization (BIND9 ``allow-update`` / PowerDNS metadata) from
    # ``update_acl`` *in addition* to the internal agent loopback grant.
    # Empty / disabled ⇒ today's behaviour (loopback grant only). Only
    # meaningful for primary zones on drivers whose ``dynamic_update_caps``
    # advertise support; ignored otherwise.
    dynamic_update_enabled: bool = False
    update_acl: tuple[UpdateAclEntry, ...] = ()


@dataclass(frozen=True)
class UpdateAclEntry:
    """One neutral dynamic-update ACL grant/deny (issue #641).

    Backend-neutral projection of a ``DNSZoneUpdateAcl`` row. Carries a
    TSIG key **name** (never the secret) or a source ``ip_cidr`` — exactly
    one is set. ``action`` / ``name_scope`` / ``name_pattern`` /
    ``record_types`` drive the BIND9 ``update-policy`` fine-grained path
    (P2); the coarse ``allow-update`` path (P1) consumes only
    ``match_kind`` + ``ip_cidr`` / ``tsig_key_name``.
    """

    match_kind: str  # "tsig_key" | "ip"
    action: str = "grant"  # "grant" | "deny"
    ip_cidr: str | None = None
    tsig_key_name: str | None = None
    name_scope: str | None = None
    name_pattern: str | None = None
    record_types: tuple[str, ...] | None = None


@dataclass(frozen=True)
class DynamicUpdateCaps:
    """What a DNS backend can express for dynamic-update ACLs (issue #641).

    The API consults these *before* accepting an ACL: an entry the target
    group's driver can't honour is rejected (422), and a lossy mapping
    (e.g. an IP entry on Windows) is surfaced as a warning. A driver with
    every flag False (cloud) means the feature is unsupported entirely.
    """

    supports_ip_acl: bool = False  # allow-update with address-match-list
    supports_tsig_acl: bool = False  # key-based authorization
    supports_name_scoping: bool = False  # per-name / subdomain grants (BIND update-policy)
    supports_per_type: bool = False  # restrict a grant to A/PTR/…
    coarse_enum_only: bool = False  # Windows: zone-level None/Secure/NonsecureAndSecure


@dataclass(frozen=True)
class DNSSECPolicyData:
    """A BIND9 ``dnssec-policy`` definition shipped in the ConfigBundle
    so the agent can render the matching ``dnssec-policy { ... };`` block
    (issue #49). ``default`` is BIND's built-in and is never shipped."""

    name: str
    algorithm: str = "ecdsap256sha256"
    ksk_lifetime_days: int = 0
    zsk_lifetime_days: int = 90
    nsec3: bool = False
    nsec3_iterations: int = 0
    nsec3_salt_length: int = 0
    nsec3_optout: bool = False


@dataclass(frozen=True)
class ViewData:
    name: str
    match_clients: tuple[str, ...]
    match_destinations: tuple[str, ...]
    recursion: bool
    order: int


@dataclass(frozen=True)
class AclData:
    name: str
    # (value, negate) tuples, in order
    entries: tuple[tuple[str, bool], ...]


@dataclass(frozen=True)
class TrustAnchorData:
    zone_name: str
    algorithm: int
    key_tag: int
    public_key: str
    is_initial_key: bool


@dataclass(frozen=True)
class ServerOptions:
    forwarders: tuple[str, ...] = ()
    forward_policy: str = "first"
    recursion_enabled: bool = True
    # #1817: local + private networks. Mirrors models.dns.DEFAULT_ALLOW_RECURSION.
    allow_recursion: tuple[str, ...] = (
        "localhost",
        "localnets",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
    dnssec_validation: str = "auto"
    notify_enabled: str = "yes"
    also_notify: tuple[str, ...] = ()
    allow_notify: tuple[str, ...] = ()
    allow_query: tuple[str, ...] = ("any",)
    allow_query_cache: tuple[str, ...] = ("localhost", "localnets")
    allow_transfer: tuple[str, ...] = ("none",)
    blackhole: tuple[str, ...] = ()
    trust_anchors: tuple[TrustAnchorData, ...] = ()
    query_log_enabled: bool = False
    # Per-query RCODE logging (#914). BIND9-only, and only meaningful
    # alongside ``query_log_enabled`` — the responses ride the same
    # channel the query-log shipper already tails.
    response_log_enabled: bool = False
    query_log_channel: str = "file"
    query_log_file: str = "/var/log/named/queries.log"
    query_log_severity: str = "info"
    query_log_print_category: bool = True
    query_log_print_severity: bool = True
    query_log_print_time: bool = True
    # Response Rate Limiting + amplification defenses (issue #146). Defaults
    # render nothing, so adding these is a no-op for existing groups.
    rrl_enabled: bool = False
    rrl_responses_per_second: int = 15
    rrl_window: int = 15
    rrl_slip: int = 2
    rrl_qps_scale: int | None = None
    rrl_exempt_clients: tuple[str, ...] = ()
    rrl_log_only: bool = False
    minimal_responses: bool = False
    tcp_clients: int | None = None
    clients_per_query: int | None = None
    max_clients_per_query: int | None = None
    # dnsdist front for PowerDNS (issue #146 Phase 2). Default-off no-op.
    dnsdist_enabled: bool = False
    dnsdist_max_qps_per_client: int | None = None
    dnsdist_action: str = "truncate"
    dnsdist_dynblock_qps: int | None = None
    dnsdist_dynblock_seconds: int = 60
    # Encrypted transports (issue #50). Inbound DoT / DoH listeners are
    # additive — the plain :53 listener is unaffected. Outbound
    # ``forward_transport`` is do53 | tls (BIND has no client-side HTTP
    # transport, so DoH-upstream is not expressible here). Default-off no-op.
    dot_enabled: bool = False
    dot_port: int = 853
    doh_enabled: bool = False
    doh_port: int = 443
    doh_path: str = "/dns-query"
    forward_transport: str = "do53"
    forward_tls_hostname: str | None = None
    forward_tls_verify: bool = True


@dataclass(frozen=True)
class TsigKey:
    name: str
    algorithm: str  # e.g. "hmac-sha256"
    secret: str  # base64


@dataclass(frozen=True)
class BlocklistEntry:
    domain: str
    action: str  # block | redirect | nxdomain
    block_mode: str  # nxdomain | sinkhole (``refused`` retired in #2124)
    sinkhole_ip: str | None
    target: str | None
    is_wildcard: bool


@dataclass(frozen=True)
class EffectiveBlocklistData:
    """Neutral projection of ``app.services.dns_blocklist.EffectiveBlocklist``.

    Drivers consume this to render backend-specific output (BIND9 RPZ
    Lua, etc.). The service-layer builder converts the service dataclass into
    this driver-neutral dataclass so drivers never import service modules.
    """

    rpz_zone_name: str  # e.g. "spatium-blocklist.rpz."
    entries: tuple[BlocklistEntry, ...]
    exceptions: frozenset[str]
    # Issue #24 — which view this RPZ belongs to. ``None`` = group-level
    # (global; rendered into every view, or top-level when no views
    # exist). When views exist, RPZ zones + the response-policy directive
    # must live INSIDE the owning view block — BIND9 forbids top-level
    # ``zone {}`` alongside ``view {}``.
    view_name: str | None = None


@dataclass
class ConfigBundle:
    """Everything an agent needs to render and run a DNS daemon.

    The bundle is hash-keyed (``etag``) so the agent long-poll endpoint can
    return ``304 Not Modified`` when nothing has changed.
    """

    server_id: str
    server_name: str
    driver: str  # bind9
    roles: tuple[str, ...]
    options: ServerOptions
    acls: tuple[AclData, ...]
    views: tuple[ViewData, ...]
    zones: tuple[ZoneData, ...]
    tsig_keys: tuple[TsigKey, ...]
    blocklists: tuple[EffectiveBlocklistData, ...]
    generated_at: datetime
    etag: str = ""
    # DNSSEC signing policies referenced by signed zones (issue #49).
    # Defaulted so existing constructors keep working.
    dnssec_policies: tuple[DNSSECPolicyData, ...] = ()

    def compute_etag(self) -> str:
        """Compute a stable SHA-256 of the bundle contents (excluding the etag/timestamp)."""
        payload = {
            "server_id": self.server_id,
            "server_name": self.server_name,
            "driver": self.driver,
            "roles": sorted(self.roles),
            "options": asdict(self.options),
            "acls": [asdict(a) for a in self.acls],
            "views": [asdict(v) for v in self.views],
            "zones": [asdict(z) for z in self.zones],
            "tsig_keys": [{"name": k.name, "algorithm": k.algorithm} for k in self.tsig_keys],
            "blocklists": [
                {
                    "rpz_zone_name": b.rpz_zone_name,
                    "view_name": b.view_name,
                    "entries": [asdict(e) for e in b.entries],
                    "exceptions": sorted(b.exceptions),
                }
                for b in self.blocklists
            ],
            "dnssec_policies": [asdict(p) for p in self.dnssec_policies],
        }
        blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return "sha256:" + hashlib.sha256(blob).hexdigest()


# ── Per-record incremental ops (agent loopback nsupdate over TSIG) ─────────


@dataclass(frozen=True)
class RRsetMember:
    """One value within a desired RRset.

    Carries the structured fields as well as the value so a driver composes
    each member's wire form exactly as it composes the op's own record.
    """

    value: str
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


@dataclass(frozen=True)
class RRsetData:
    """The COMPLETE desired set of values at one ``(name, type)`` (#783).

    An empty ``members`` means the RRset should not exist at all.

    This is the agentless twin of the ``record["rrset"]`` payload the agent
    drivers consume (#773), and it exists for the same reason: none of the
    backends can express "change this one value and leave its siblings
    alone" from an op that names only the NEW value.

    * **Windows** rendered `Get-DnsServerResourceRecord … | Remove-…`, which
      removes every RR at the ``(name, type)``, then added back the single
      value the op mentioned — so a name with two A records, a backup MX, or
      SPF beside a verification TXT ended up serving one of them.
    * **Route 53 / Azure DNS / Google Cloud DNS** are RRset-oriented APIs.
      Their create/delete paths read-merge and are fine; their ``update``
      paths replaced the whole RRset with the op's single value, and each
      says so in a comment deferring the fix.

    A driver that sees this applies it as ONE whole-RRset write, which also
    makes ops idempotent and self-healing: replaying one converges the
    server to the database instead of moving it to an earlier state.

    ``None`` means the control plane did not resolve a set for this op —
    either the caller opted out via ``rrset_action`` (DNS pools, the
    Windows-cutover TTL pre-flight, both of which need precise per-RR
    semantics) or the op predates the field. Drivers MUST fall back to
    their previous per-value behaviour in that case.
    """

    ttl: int | None
    members: tuple[RRsetMember, ...]

    def as_records(self, base: RecordData) -> list[RecordData]:
        """Each member wearing ``base``'s ``(name, type)`` and TTL.

        Lets a driver reuse whatever it already has for composing one
        ``RecordData`` — rdata formatters, per-type cmdlet dispatch, provider
        entry builders — instead of growing a parallel set of member-shaped
        builders that could drift from them.
        """
        return [
            RecordData(
                name=base.name,
                record_type=base.record_type,
                value=m.value,
                ttl=self.ttl if self.ttl is not None else base.ttl,
                priority=m.priority,
                weight=m.weight,
                port=m.port,
            )
            for m in self.members
        ]


@dataclass(frozen=True)
class RecordChange:
    """A single record mutation to be applied incrementally.

    The agent interprets ``op`` and ``record`` against its local daemon.
    """

    op: Literal["create", "update", "delete"]
    zone_name: str
    record: RecordData
    target_serial: int
    tsig_key_name: str | None = None
    op_id: str = ""  # caller-supplied UUID for ACK tracking
    # #783 — the complete desired RRset this op resolves to. Set on the
    # agentless path by ``record_ops``; ``None`` when the caller opted out.
    rrset: RRsetData | None = None


@dataclass(frozen=True)
class RecordChangeResult:
    """Per-op outcome returned by ``DNSDriver.apply_record_changes``.

    Batch dispatch never raises for a single failed record — one bad
    record shouldn't poison the rest of the batch. Instead, each op gets
    a ``RecordChangeResult`` with ``ok=False`` and ``error`` populated;
    the caller decides whether to surface as a 500, a partial success, or
    to ignore (e.g. an idempotent delete that the server reports as
    no-op). Whole-batch failures (connection refused, auth, malformed
    script) still raise from the driver.

    ``change`` is the original input echoed back verbatim so callers can
    zip results with their source list without re-tracking identity.
    """

    ok: bool
    change: RecordChange
    error: str | None = None


# ── Driver abstract base ──────────────────────────────────────────────────


class DNSDriver(ABC):
    """Abstract base class for DNS backend drivers.

    Drivers are pure renderers + single-record appliers. They do not manage
    daemon lifecycle (the agent does that). They must be stateless and safe
    to instantiate per call.
    """

    name: str = "abstract"

    # ── Rendering ─────────────────────────────────────────────────────────

    @abstractmethod
    def render_server_config(
        self, server: Any, options: ServerOptions, *, bundle: ConfigBundle | None = None
    ) -> str:
        """Render the daemon's top-level config (e.g. ``named.conf``)."""

    @abstractmethod
    def render_zone_config(self, zone: ZoneData) -> str:
        """Render the per-zone stanza to be included in the server config."""

    @abstractmethod
    def render_zone_file(self, zone: ZoneData, records: list[RecordData]) -> str:
        """Render an RFC 1035-format zone file."""

    @abstractmethod
    def render_rpz_zone(self, blocklist: EffectiveBlocklistData) -> str:
        """Render an RPZ zone file (or equivalent) from an effective blocklist."""

    # ── Runtime (agent-side; control plane only *formulates* these) ──────

    @abstractmethod
    async def apply_record_change(self, server: Any, change: RecordChange) -> None:
        """Apply a single record change to the daemon (loopback RFC 2136 / API)."""

    async def apply_record_changes(
        self, server: Any, changes: Sequence[RecordChange]
    ) -> list[RecordChangeResult]:
        """Apply many record changes to the same server.

        Default implementation: sequential loop calling ``apply_record_change``
        for each op. Per-op exceptions are caught and surfaced as
        ``RecordChangeResult(ok=False)`` so one failure doesn't abort the
        batch. Agent-based drivers (BIND9) inherit this unchanged — there's
        no connection setup to amortise, so the loop is just fine.

        Agentless drivers that pay a per-call connection cost (Windows DNS
        over WinRM) override this to ship the whole batch in one round
        trip; see ``WindowsDNSDriver.apply_record_changes``.
        """
        results: list[RecordChangeResult] = []
        for change in changes:
            try:
                await self.apply_record_change(server, change)
                results.append(RecordChangeResult(ok=True, change=change))
            except Exception as exc:  # noqa: BLE001 — per-op isolation
                results.append(RecordChangeResult(ok=False, change=change, error=str(exc)))
        return results

    @abstractmethod
    async def reload_config(self, server: Any) -> None:
        """Instruct the daemon to re-read its full config (e.g. ``rndc reconfig``)."""

    @abstractmethod
    async def reload_zone(self, server: Any, zone_name: str) -> None:
        """Instruct the daemon to reload a single zone."""

    # ── Validation / introspection ────────────────────────────────────────

    @abstractmethod
    def validate_config(self, bundle: ConfigBundle) -> tuple[bool, list[str]]:
        """Validate a bundle before apply. Returns (ok, errors)."""

    @abstractmethod
    def capabilities(self) -> dict[str, Any]:
        """Return a dict describing what this driver supports."""

    # ── Dynamic-update ACLs (issue #641) ─────────────────────────────────

    @property
    def dynamic_update_caps(self) -> DynamicUpdateCaps:
        """What this backend can express for dynamic-update (RFC 2136) ACLs.

        Default is "unsupported entirely" (every flag False). BIND9 /
        PowerDNS / Windows override; cloud drivers inherit this default so
        the API 422s the feature for them.
        """
        return DynamicUpdateCaps()

    async def apply_dynamic_update_mode(self, server: Any, zone_name: str, mode: str) -> None:
        """Push a coarse zone-level dynamic-update mode to an agentless server.

        Only meaningful for drivers whose ``dynamic_update_caps`` set
        ``coarse_enum_only`` (Windows DNS maps the ACL to a
        None/Secure/NonsecureAndSecure zone enum over WinRM). Agent-based
        drivers (BIND9 / PowerDNS) deliver the ACL through the config bundle,
        so this is a no-op for them.
        """
        return None

    def validate_update_acl(self, zone_name: str, entries: Sequence[UpdateAclEntry]) -> list[str]:
        """Validate an ACL against this driver's capabilities.

        Returns a list of human-readable *warnings* for lossy-but-accepted
        mappings (e.g. an IP entry on Windows opens the zone wider than the
        CIDR). Raises :class:`ValueError` (surfaced by the API as a 422)
        when an entry is hard-unsupported. An empty warning list + no raise
        means the ACL renders exactly as written.
        """
        caps = self.dynamic_update_caps
        if not (
            caps.supports_ip_acl
            or caps.supports_tsig_acl
            or caps.supports_name_scoping
            or caps.coarse_enum_only
        ):
            raise ValueError(
                f"{self.name} does not support dynamic-update ACLs "
                f"(no RFC 2136 surface for zone {zone_name})"
            )
        warnings: list[str] = []
        for e in entries:
            if e.match_kind == "ip":
                if caps.coarse_enum_only:
                    warnings.append(
                        f"IP entry {e.ip_cidr!r}: {self.name} cannot restrict dynamic "
                        "updates to a source range — enabling opens the zone to any "
                        "nonsecure client, not just this CIDR. Prefer a TSIG/secure grant."
                    )
                elif not caps.supports_ip_acl:
                    raise ValueError(
                        f"{self.name} cannot authorize dynamic updates by source IP "
                        f"({e.ip_cidr!r}); use a TSIG key instead."
                    )
                else:
                    warnings.append(
                        f"IP entry {e.ip_cidr!r} is UDP-spoofable; a TSIG key is "
                        "strongly recommended for any writer outside a trusted segment."
                    )
            elif e.match_kind == "tsig_key":
                if not caps.supports_tsig_acl:
                    raise ValueError(
                        f"{self.name} cannot authorize dynamic updates by TSIG key "
                        f"({e.tsig_key_name!r})."
                    )
            else:
                raise ValueError(f"unknown match_kind {e.match_kind!r}")
            if e.action == "deny" and not caps.supports_name_scoping:
                raise ValueError(
                    f"{self.name} has no update-policy surface, so a 'deny' entry "
                    "cannot be expressed (deny is only meaningful for BIND9 "
                    "update-policy). Use grant-only ACLs on this backend."
                )
            if (e.name_scope or e.name_pattern) and not caps.supports_name_scoping:
                raise ValueError(
                    f"{self.name} cannot scope a dynamic-update grant to a name "
                    "pattern; drop name_scope/name_pattern for this backend."
                )
            if e.record_types and not caps.supports_per_type:
                raise ValueError(
                    f"{self.name} cannot restrict a dynamic-update grant to specific "
                    "record types; drop record_types for this backend."
                )
        # Fine-grained (update-policy) is TSIG-identity only — it cannot match
        # on source IP, and the renderer picks ONE clause for the whole zone.
        # So when any entry forces the zone onto the update-policy path
        # (name-scope / per-type / deny), an IP entry in the same ACL is
        # unsatisfiable, and name-scoped ruletypes that take a name need one.
        if caps.supports_name_scoping:
            needs_policy = any(
                e.action == "deny" or e.name_scope or e.name_pattern or e.record_types
                for e in entries
            )
            if needs_policy:
                ip_entries = [e.ip_cidr for e in entries if e.match_kind == "ip"]
                if ip_entries:
                    raise ValueError(
                        "this ACL uses name-scoped / per-type / deny grants, which "
                        "render as BIND update-policy (TSIG-identity only). Remove the "
                        f"IP entr{'y' if len(ip_entries) == 1 else 'ies'} "
                        f"({', '.join(str(c) for c in ip_entries)}) — update-policy "
                        "cannot match on source IP."
                    )
                for e in entries:
                    if e.name_scope in ("subdomain", "name", "wildcard", "self") and not (
                        e.name_pattern and e.name_pattern.strip()
                    ):
                        raise ValueError(
                            f"name_scope={e.name_scope!r} requires a name_pattern "
                            "(the FQDN / subtree the grant applies to)."
                        )
        return warnings


__all__ = [
    "AclData",
    "BlocklistEntry",
    "ConfigBundle",
    "DNSDriver",
    "DynamicUpdateCaps",
    "EffectiveBlocklistData",
    "RecordChange",
    "RecordChangeResult",
    "RecordData",
    "ServerOptions",
    "TrustAnchorData",
    "TsigKey",
    "UpdateAclEntry",
    "ViewData",
    "ZoneData",
]
