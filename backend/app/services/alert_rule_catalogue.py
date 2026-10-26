"""Alert rule-type catalogue (#1997).

The editor used to carry a hand-kept list of rule types and the fields each
one shows, which knew 23 of the ~64 types in ``alerts.RULE_TYPES`` — so for
the rest, a threshold could only be set through the API. This module is the
one place that says, per type, what it is called and which of the six
operator-editable parameter columns it actually reads, and
``GET /alerts/rule-types`` serves it; the frontend renders from it.

Which columns a type reads is a fact about its evaluator, not a UI choice, so
it is **checked against the evaluator source** by
``tests/test_alert_rule_catalogue.py`` (an AST scan of every ``rule.<column>``
read reachable from the dispatch in ``evaluate_all``). A type missing here, a
column an evaluator reads that is not declared, or one declared that nothing
reads, fails that test — the catalogue cannot drift quietly the way the
frontend union did.

``default`` is what the evaluator uses when the column is NULL, so a stored
NULL is shown as "uses <default>" rather than being rewritten. ``initial`` is
what a NEW rule's form starts from (the same unless the shipped suggestion
differs from the evaluator's fallback).
"""

from __future__ import annotations

from pydantic import BaseModel

from app.services import alerts as a
from app.services.backup.health import STALE_AFTER_RUNS_DEFAULT
from app.services.dns_threat import aggregate as threat

# Columns an operator can set on a rule.
PARAM_COLUMNS = (
    "threshold_percent",
    "threshold_days",
    "min_free_addresses",
    "server_type",
    "classification",
    "change_scope",
)


class ParamOption(BaseModel):
    value: str
    label: str


class ParamSpec(BaseModel):
    """One editable parameter of a rule type."""

    name: str
    label: str
    kind: str  # "integer" | "select"
    unit: str | None = None  # "%", "days", "count", ...
    min: int | None = None
    max: int | None = None
    # What the evaluator uses when the stored value is NULL (None = it has
    # no fallback: the parameter is required or simply unused when unset).
    default: int | str | None = None
    # Starting value for a new rule's form; falls back to ``default``.
    initial: int | str | None = None
    hint: str | None = None
    options: list[ParamOption] = []


class RuleTypeSpec(BaseModel):
    rule_type: str
    label: str
    group: str
    description: str | None = None
    params: list[ParamSpec] = []
    # A type the platform seeds and drives itself (#2748): it is described
    # so its Edit dialog can say so, but an operator cannot create one, so
    # the editor leaves it out of the New-rule picker.
    system_driven: bool = False


def _pct(label: str, default: int | None, hint: str, *, initial: int | None = None) -> ParamSpec:
    return ParamSpec(
        name="threshold_percent",
        label=label,
        kind="integer",
        unit="%",
        min=0,
        max=100,
        default=default,
        initial=initial,
        hint=hint,
    )


def _count(
    label: str,
    default: int | None,
    hint: str,
    *,
    min_: int = 0,
    max_: int | None = None,
    initial: int | None = None,
    name: str = "threshold_percent",
) -> ParamSpec:
    # ``threshold_percent`` is reused as a raw count by several rules; a
    # count has no upper bound of its own (#2746), unlike ``_pct``.
    return ParamSpec(
        name=name,
        label=label,
        kind="integer",
        unit="count",
        min=min_,
        max=max_,
        default=default,
        initial=initial,
        hint=hint,
    )


def _days(label: str, default: int | None, hint: str, *, min_: int = 1) -> ParamSpec:
    return ParamSpec(
        name="threshold_days",
        label=label,
        kind="integer",
        unit="days",
        min=min_,
        max=3650,
        default=default,
        hint=hint,
    )


_EXPIRY_HINT = (
    "Soft fire at threshold; severity escalates to warning at threshold/4 and "
    "critical at threshold/12 (e.g. 30 → 7.5 → 2.5 d)."
)


def _expiry() -> ParamSpec:
    return _days("Threshold (days)", a._DEFAULT_EXPIRING_THRESHOLD_DAYS, _EXPIRY_HINT)


def _recency(default: int, what: str) -> ParamSpec:
    return _days(
        "Recency window (days)",
        default,
        f"Only {what} within this many days are reported. Default {default}.",
    )


def _floor(label: str, default: int, hint: str) -> ParamSpec:
    # ``min_free_addresses`` is reused as an absolute floor by these rules;
    # the API validator requires >= 1.
    return ParamSpec(
        name="min_free_addresses",
        label=label,
        kind="integer",
        unit="count",
        min=1,
        default=default,
        hint=hint,
    )


# (rule_type, label, group, params). Order is display order within a group.
_SPECS: list[tuple[str, str, str, list[ParamSpec]]] = [
    # ── Infrastructure ─────────────────────────────────────────────────
    (
        a.RULE_TYPE_SUBNET_UTILIZATION,
        "Subnet utilization",
        "IPAM",
        [
            _pct(
                "Threshold (%)",
                90,
                "Fires when subnet utilization ≥ this. PTP / loopback subnets "
                "(prefix > utilization_max_prefix_*) are excluded.",
            )
        ],
    ),
    (
        a.RULE_TYPE_STALE_IP_COUNT,
        "Stale IP count (address-space hygiene)",
        "IPAM",
        [
            _count(
                "Stale IP count threshold",
                a._STALE_IP_DEFAULT_COUNT_THRESHOLD,
                "Fires when a subnet holds at least this many allocated IPs that "
                "haven't been seen on the wire in the window below. Reads the "
                "discovery last-seen signal; never-seen rows are excluded (chase "
                "those from the Stale-IP report).",
                min_=1,
            ),
            _days(
                "Stale window (days)",
                a._STALE_IP_DEFAULT_DAYS,
                "An allocated IP counts as stale once its last-seen timestamp is "
                "older than this. Default 90.",
            ),
        ],
    ),
    (a.RULE_TYPE_DECOM_EXPIRING, "Subnet decommission approaching", "IPAM", [_expiry()]),
    (
        a.RULE_TYPE_IP_FREE_BUT_RESPONDING,
        "IP marked free but responding",
        "IPAM",
        [_recency(a._FREE_RESPONDING_RECENCY_DAYS, "responses seen")],
    ),
    (
        a.RULE_TYPE_STALE_RESERVATION,
        "Stale reservation",
        "IPAM",
        [
            _days(
                "Idle window (days)",
                a._STALE_RESERVATION_DAYS,
                "A reservation unused for longer than this is reported.",
            )
        ],
    ),
    (
        a.RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE,
        "Unknown MAC in static range",
        "IPAM",
        [_recency(a._SQUAT_RECENCY_DAYS, "sightings")],
    ),
    (
        a.RULE_TYPE_NEW_MAC_SEEN,
        "New MAC seen",
        "IPAM",
        [
            _recency(a._NEW_MAC_SEEN_RECENCY_DAYS, "first sightings"),
            ParamSpec(
                name="classification",
                label="Randomised MACs",
                kind="select",
                default="",
                hint="Locally-administered (randomised) MACs are excluded by "
                "default; modern phones rotate them per network.",
                options=[
                    ParamOption(value="", label="Exclude randomised MACs"),
                    ParamOption(value="all", label="Include randomised MACs"),
                ],
            ),
        ],
    ),
    (
        a.RULE_TYPE_ROGUE_DHCP,
        "Rogue DHCP server",
        "DHCP",
        [_recency(a._ROGUE_DHCP_RECENCY_DAYS, "sightings")],
    ),
    (
        a.RULE_TYPE_ROGUE_RA,
        "Rogue IPv6 router advertisement",
        "IPAM",
        [_recency(a._ROGUE_RA_RECENCY_DAYS, "sightings")],
    ),
    (a.RULE_TYPE_IP_BLOCKLISTED, "IP on a reputation blocklist", "IPAM", []),
    # ── DHCP ───────────────────────────────────────────────────────────
    (
        a.RULE_TYPE_DHCP_POOL_EXHAUSTION,
        "DHCP pool exhaustion (dynamic pool pressure)",
        "DHCP",
        [
            # No ``default``: the evaluator falls back to 90% only when BOTH
            # this and the free-address floor are empty, so a null here does
            # not mean 90% once a floor is set.
            _pct(
                "Occupancy threshold (%)",
                None,
                "Fires when a dynamic DHCP pool's live occupancy (active leases ÷ "
                "pool size) reaches this. Orthogonal to subnet utilization, which "
                "counts allocated IPAM rows — a pool can be exhausted while the "
                "subnet looks empty. Empty uses 90% only while the free-address "
                "floor below is also empty; with a floor set, empty means no "
                "percent check.",
                initial=90,
            ),
            ParamSpec(
                name="min_free_addresses",
                label="Minimum free addresses (optional)",
                kind="integer",
                unit="count",
                min=1,
                hint="Also fire when fewer than this many addresses are free in "
                "the pool, regardless of percent. Leave empty to use the percent "
                "threshold only.",
            ),
        ],
    ),
    (
        a.RULE_TYPE_DHCP_PACKETS_DROPPED,
        "DHCP packets dropped before being read",
        "DHCP",
        [
            _floor(
                "Minimum dropped packets",
                a._DHCP_PACKET_LOSS_MIN_DEFAULT,
                "Fires when the kernel socket dropped at least this many packets "
                "over the window.",
            )
        ],
    ),
    (
        a.RULE_TYPE_DHCP_SCOPE_UNCOORDINATED,
        "DHCP scope served by uncoordinated servers",
        "DHCP",
        [],
    ),
    (
        a.RULE_TYPE_WOL_WAKE_FAILED,
        "Wake-on-LAN failed",
        "DHCP",
        [_recency(a._WOL_WAKE_FAILED_RECENCY_DAYS, "failures")],
    ),
    # ── DNS ────────────────────────────────────────────────────────────
    (
        a.RULE_TYPE_DNS_NXDOMAIN_SPIKE,
        "DNS NXDOMAIN spike",
        "DNS",
        [
            _pct(
                "NXDOMAIN ratio (%)",
                a._DNS_NXDOMAIN_RATIO_DEFAULT,
                "Fires when this share of a server's queries over the window are NXDOMAIN…",
            ),
            _floor(
                "Minimum NXDOMAIN count",
                a._DNS_NXDOMAIN_MIN_COUNT_DEFAULT,
                "…and at least this many NXDOMAIN answers, so a quiet server does not page.",
            ),
        ],
    ),
    (
        a.RULE_TYPE_DNS_QUERY_RATE_SPIKE,
        "DNS query-rate spike",
        "DNS",
        [
            _pct(
                "Increase over prior window (%)",
                a._DNS_QUERY_RATE_SPIKE_PCT_DEFAULT,
                "Fires when the window's query total exceeds the prior equal "
                "window by this much. The default (200) is above what this field "
                "accepts (0–100): leave it empty to use it.",
            ),
            _floor(
                "Minimum queries",
                a._DNS_QUERY_RATE_MIN_DEFAULT,
                "…and clears this absolute query floor.",
            ),
        ],
    ),
    (
        a.RULE_TYPE_DNS_RATE_LIMIT_DROPPING,
        "DNS response rate limiting dropping",
        "DNS",
        [
            _floor(
                "Minimum dropped responses",
                a._DNS_RATE_LIMIT_DROP_MIN_DEFAULT,
                "Fires when response-rate-limiting dropped at least this many "
                "responses over the window.",
            )
        ],
    ),
    (
        a.RULE_TYPE_DNS_TUNNELING,
        "DNS tunneling suspected",
        "DNS",
        [
            _pct(
                "Score threshold",
                int(threat.ALERTING_SCORE),
                "Minimum detection score (0–100) for a client to open an event.",
            )
        ],
    ),
    (
        a.RULE_TYPE_DNS_BEACONING,
        "DNS beaconing suspected",
        "DNS",
        [
            _pct(
                "Score threshold",
                int(threat.BEACON_ALERTING_SCORE),
                "Minimum detection score (0–100) for a client to open an event.",
            )
        ],
    ),
    (
        a.RULE_TYPE_DNS_DGA,
        "DNS DGA suspected",
        "DNS",
        [
            _pct(
                "Score threshold",
                int(threat.DGA_ALERTING_SCORE),
                "Minimum detection score (0–100) for a client to open an event.",
            )
        ],
    ),
    (a.RULE_TYPE_DNS_POOL_HEALTH_STALE, "DNS pool health checks stale", "DNS", []),
    (a.RULE_TYPE_DNSSEC_MULTI_SIGNER, "DNSSEC zone signed by several servers", "DNS", []),
    (a.RULE_TYPE_DNS_RECORD_OP_FAILED, "DNS record operation failed", "DNS", []),
    (a.RULE_TYPE_DNS_AGENT_DUPLICATE_INSTANCE, "Two DNS agents on one server", "DNS", []),
    # ── Servers, agents, appliance ─────────────────────────────────────
    (
        a.RULE_TYPE_SERVER_UNREACHABLE,
        "Server unreachable",
        "Infrastructure",
        [
            ParamSpec(
                name="server_type",
                label="Server type",
                kind="select",
                default="any",
                options=[
                    ParamOption(value="any", label="DNS + DHCP"),
                    ParamOption(value="dns", label="DNS only"),
                    ParamOption(value="dhcp", label="DHCP only"),
                ],
            )
        ],
    ),
    (
        a.RULE_TYPE_NODE_PRESSURE,
        "Node resource pressure (PSI stalling)",
        "Infrastructure",
        [
            _pct(
                "Stall threshold (%)",
                50,
                "Warns when CPU or memory 'some' stalling holds at or above this "
                "across a 5-minute window — the share of wall time at least one "
                "task was blocked waiting for the resource. Separate from the "
                "fixed 1% memory 'full' floor, which is always critical: 'some' "
                "at 20% is a busy node, 'full' at 20% is a node doing no work. "
                "Silent on nodes whose kubelet does not report PSI (below "
                "Kubernetes 1.36).",
            )
        ],
    ),
    (a.RULE_TYPE_CLUSTER_DNS_DEGRADED, "Cluster DNS (CoreDNS) degraded", "Infrastructure", []),
    (a.RULE_TYPE_APPLIANCE_STORAGE_DEGRADED, "Appliance storage degraded", "Infrastructure", []),
    (
        a.RULE_TYPE_APPLIANCE_DISK_USAGE,
        "Appliance data partition (/var) filling",
        "Infrastructure",
        [
            _pct(
                "Warning threshold (%)",
                80,
                "Warns when a node's /var data partition is at least this full. "
                f"Separate from the fixed {a._APPLIANCE_DISK_CRITICAL_PCT}% critical "
                "level, a few points before the kubelet starts evicting pods at "
                "about 90% (ext4 keeps 5% of /var for root, so about 90% used "
                "leaves the kubelet its last 5%). Silent on nodes whose supervisor "
                "does not report /var.",
            )
        ],
    ),
    (a.RULE_TYPE_APPLIANCE_HEARTBEAT_STALE, "Appliance heartbeat lost", "Infrastructure", []),
    (a.RULE_TYPE_FIREWALL_APPLY_STALLED, "Firewall apply stalled", "Infrastructure", []),
    (a.RULE_TYPE_AGENT_CONFIG_REJECTED, "Agent rejected its configuration", "Infrastructure", []),
    (a.RULE_TYPE_AGENT_SPOOL_TRIMMED, "Agent spool trimmed", "Infrastructure", []),
    (a.RULE_TYPE_AGENT_DAEMON_DEGRADED, "Agent daemon degraded", "Infrastructure", []),
    (a.RULE_TYPE_AGENT_BUNDLE_RENDER_FAILED, "Agent bundle render failed", "Infrastructure", []),
    (a.RULE_TYPE_AUDIT_CHAIN_BROKEN, "Audit chain broken", "Infrastructure", []),
    (a.RULE_TYPE_SCHEMA_BEHIND_HEAD, "Database schema behind head", "Infrastructure", []),
    # ── Backup ─────────────────────────────────────────────────────────
    (a.RULE_TYPE_BACKUP_FAILED, "Backup failed", "Backup", []),
    (
        a.RULE_TYPE_BACKUP_STALE,
        "Backup stale",
        "Backup",
        [
            _count(
                "Missed runs",
                STALE_AFTER_RUNS_DEFAULT,
                "Fires when a scheduled backup target has had no successful run "
                "for this many scheduled runs, plus one hour. Default 2.",
                min_=1,
            )
        ],
    ),
    (a.RULE_TYPE_RESTORE_DRILL_FAILED, "Restore drill failed", "Backup", []),
    # ── Network (ASN / RPKI / BGP) ─────────────────────────────────────
    (a.RULE_TYPE_ASN_HOLDER_DRIFT, "ASN holder drift", "Network (ASN / RPKI / BGP)", []),
    (a.RULE_TYPE_ASN_WHOIS_UNREACHABLE, "ASN WHOIS unreachable", "Network (ASN / RPKI / BGP)", []),
    (a.RULE_TYPE_RPKI_ROA_EXPIRING, "RPKI ROA expiring", "Network (ASN / RPKI / BGP)", []),
    (a.RULE_TYPE_RPKI_ROA_EXPIRED, "RPKI ROA expired", "Network (ASN / RPKI / BGP)", []),
    (a.RULE_TYPE_BGP_PREFIX_HIJACK, "BGP prefix hijack", "Network (ASN / RPKI / BGP)", []),
    (
        a.RULE_TYPE_BGP_MORE_SPECIFIC,
        "BGP more-specific announced",
        "Network (ASN / RPKI / BGP)",
        [],
    ),
    (
        a.RULE_TYPE_BGP_LG_SESSION_DOWN,
        "Looking Glass BGP session down",
        "Network (ASN / RPKI / BGP)",
        [],
    ),
    (
        a.RULE_TYPE_BGP_LG_RPKI_INVALID_ROUTE,
        "Looking Glass RPKI-invalid route",
        "Network (ASN / RPKI / BGP)",
        [],
    ),
    (
        a.RULE_TYPE_BGP_LG_UNEXPECTED_ORIGIN,
        "Looking Glass unexpected origin",
        "Network (ASN / RPKI / BGP)",
        [],
    ),
    (
        a.RULE_TYPE_BGP_LG_MORE_SPECIFIC,
        "Looking Glass more-specific route",
        "Network (ASN / RPKI / BGP)",
        [],
    ),
    (
        a.RULE_TYPE_BGP_LG_ROUTE_FLAP,
        "Looking Glass route flapping",
        "Network (ASN / RPKI / BGP)",
        [
            _count(
                "Flap count",
                a._BGP_LG_FLAP_COUNT_DEFAULT,
                "Fires when a route's flap count reaches this and it flapped within the recent window.",
                min_=1,
            )
        ],
    ),
    (
        a.RULE_TYPE_BGP_LG_MISSING_ADVERTISEMENT,
        "Looking Glass missing advertisement",
        "Network (ASN / RPKI / BGP)",
        [],
    ),
    # ── Domains ────────────────────────────────────────────────────────
    (a.RULE_TYPE_DOMAIN_EXPIRING, "Domain expiring", "Domains (registry)", [_expiry()]),
    (a.RULE_TYPE_DOMAIN_NS_DRIFT, "Domain nameserver drift", "Domains (registry)", []),
    (
        a.RULE_TYPE_DOMAIN_REGISTRAR_CHANGED,
        "Domain registrar changed (transfer)",
        "Domains (registry)",
        [],
    ),
    (a.RULE_TYPE_DOMAIN_DNSSEC_CHANGED, "Domain DNSSEC status changed", "Domains (registry)", []),
    # ── Circuits / services ────────────────────────────────────────────
    (
        a.RULE_TYPE_CIRCUIT_TERM_EXPIRING,
        "Circuit term expiring",
        "Circuits (WAN transport)",
        [_expiry()],
    ),
    (
        a.RULE_TYPE_CIRCUIT_STATUS_CHANGED,
        "Circuit status changed (suspended / decom)",
        "Circuits (WAN transport)",
        [],
    ),
    (a.RULE_TYPE_SERVICE_TERM_EXPIRING, "Service term expiring", "Service catalog", [_expiry()]),
    (
        a.RULE_TYPE_SERVICE_RESOURCE_ORPHANED,
        "Service resource orphaned (target deleted)",
        "Service catalog",
        [],
    ),
    # ── Compliance ─────────────────────────────────────────────────────
    (
        a.RULE_TYPE_COMPLIANCE_CHANGE,
        "Compliance change (PCI / HIPAA / internet-facing)",
        "Compliance",
        [
            ParamSpec(
                name="classification",
                label="Classification",
                kind="select",
                initial="pci_scope",
                hint="Subnet flag this rule watches. Mutations against subnets / "
                "IPs / DHCP scopes whose subnet has the flag fire one event per "
                "audit row. Required: a rule without one can never fire.",
                options=[
                    ParamOption(value="pci_scope", label="PCI scope"),
                    ParamOption(value="hipaa_scope", label="HIPAA scope"),
                    ParamOption(value="internet_facing", label="Internet-facing"),
                ],
            ),
            ParamSpec(
                name="change_scope",
                label="Change scope",
                kind="select",
                default="any_change",
                hint="Which audit-log actions count. Update + create + delete "
                "cover the common cases; pick a narrower scope to reduce noise.",
                options=[
                    ParamOption(value="any_change", label="Any change (create + update + delete)"),
                    ParamOption(value="create", label="Create only"),
                    ParamOption(value="delete", label="Delete only"),
                ],
            ),
        ],
    ),
    # ── VoIP ───────────────────────────────────────────────────────────
    (
        a.RULE_TYPE_VOICE_LEASE_COUNT_BELOW,
        "Voice VLAN lease count below threshold",
        "VoIP",
        [
            _count(
                "Minimum active leases",
                1,
                "Fires when any subnet tagged subnet_role='voice' has fewer "
                "active DHCP leases than this. Set to roughly 50% of the "
                "expected phone fleet so brief reboots don't trigger but a real "
                "mass-disconnect does.",
                initial=10,
            )
        ],
    ),
    # ── Security / certificates ────────────────────────────────────────
    (a.RULE_TYPE_SECRET_EXPIRING, "Secret / certificate expiring", "Security", [_expiry()]),
    (
        a.RULE_TYPE_K3S_API_CERT_EXPIRING,
        "k3s API server certificate expiring",
        "Security",
        [_expiry()],
    ),
    (a.RULE_TYPE_TLS_CERT_EXPIRING, "Monitored TLS certificate expiring", "Security", [_expiry()]),
    (a.RULE_TYPE_TLS_CERT_CHAIN_INVALID, "Monitored TLS certificate chain invalid", "Security", []),
    (a.RULE_TYPE_TLS_CERT_UNREACHABLE, "Monitored TLS endpoint unreachable", "Security", []),
    (a.RULE_TYPE_TLS_CERT_CHANGED, "Monitored TLS certificate changed", "Security", []),
    (
        a.RULE_TYPE_TLS_CERT_ISSUER_CHANGED,
        "Monitored TLS certificate issuer changed",
        "Security",
        [],
    ),
    (a.RULE_TYPE_ACME_MANUAL_RENEWAL, "ACME certificate needs manual renewal", "Security", []),
]


# Behaviour notes for types whose whole story is "what fires, what resolves".
_DESCRIPTIONS: dict[str, str] = {
    a.RULE_TYPE_DOMAIN_NS_DRIFT: (
        "Fires for any domain whose operator-pinned expected_nameservers list "
        "differs from the registrar-reported actual_nameservers. Resolves when "
        "drift clears."
    ),
    a.RULE_TYPE_DOMAIN_REGISTRAR_CHANGED: (
        "Fires once per registrar transition (e.g. a transfer). Auto-resolves "
        "after 7 days; can be marked resolved manually before then. The first "
        "observation per domain is recorded as a baseline without paging."
    ),
    a.RULE_TYPE_DOMAIN_DNSSEC_CHANGED: (
        "Fires once when a domain's dnssec_signed flag flips at the parent "
        "zone (DS records appearing or disappearing). Auto-resolves after 7 "
        "days; can be marked resolved manually."
    ),
    a.RULE_TYPE_CIRCUIT_STATUS_CHANGED: (
        "Fires once when a circuit transitions into suspended or decom. "
        "Routine active / pending flips during commissioning are excluded. "
        "Auto-resolves after 7 days; can be marked resolved manually."
    ),
    a.RULE_TYPE_SERVICE_RESOURCE_ORPHANED: (
        "Fires when a service has a resource link (VRF / subnet / circuit / "
        "etc.) whose target row was deleted out from under it. Resolves "
        "automatically when the operator detaches the orphan link or "
        "re-creates the target."
    ),
    a.RULE_TYPE_COMPLIANCE_CHANGE: (
        "On first enable, the rule baselines its watermark to now — it won't "
        "retro-fire on existing audit history. Each matching audit row opens "
        "one event that auto-resolves after 24 h. Inheritance from IP block / "
        "space is not supported today (classification flags only exist on "
        "subnet rows)."
    ),
}


# Seeded by the platform and opened by its own subsystem, deliberately not in
# ``RULE_TYPES`` (operators cannot create one) — but a stored rule of the type
# exists on every appliance, and its Edit dialog must be able to describe it.
_SYSTEM_DRIVEN_SPECS: list[RuleTypeSpec] = [
    RuleTypeSpec(
        rule_type=a._CLUSTER_UPGRADE_FAILED,
        label="Cluster upgrade failed",
        group="Infrastructure",
        description=(
            "Seeded by the platform. The rolling-upgrade orchestrator opens an "
            "event when an upgrade run fails, while this rule is enabled; it has "
            "no parameters to set."
        ),
        params=[],
        system_driven=True,
    ),
]


def build_catalogue() -> list[RuleTypeSpec]:
    """The catalogue, in display order (group, then declaration order)."""
    groups: list[str] = []
    for _, _, group, _ in _SPECS:
        if group not in groups:
            groups.append(group)
    ordered = sorted(_SPECS, key=lambda s: groups.index(s[2]))
    specs = [
        RuleTypeSpec(
            rule_type=rt,
            label=label,
            group=group,
            description=_DESCRIPTIONS.get(rt),
            params=params,
        )
        for rt, label, group, params in ordered
    ]
    specs.extend(_SYSTEM_DRIVEN_SPECS)
    return specs


def rule_type_names() -> set[str]:
    return {rt for rt, *_ in _SPECS}
