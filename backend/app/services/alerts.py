"""Alerts — rule evaluator + delivery.

Called once per minute from a Celery beat tick (see tasks/alerts.py).
For each enabled ``AlertRule`` we:

  1. Compute the set of subjects that currently match the rule.
  2. For each newly-matching subject with no existing open event,
     open a new ``AlertEvent`` and dispatch it to the configured
     delivery channels (syslog + webhook, reusing the platform-level
     audit-forward targets).
  3. For each open event whose subject no longer matches, flip
     ``resolved_at`` to now.

The filter from ``PlatformSettings.utilization_max_prefix_*`` applies
to ``subnet_utilization`` rules so small PTP / loopback subnets can't
trip the alarm — same predicate the dashboard honours.

Domain rule types use a slightly different shape: the four match
families come from ``Domain`` row state (expiry date, drift flag,
registrar transition, dnssec transition). Two of them are
"transition-once" rules (``domain_registrar_changed`` /
``domain_dnssec_status_changed``) — the evaluator latches the
observed value into ``AlertEvent.last_observed_value`` so a single
flip fires exactly one event, and that event auto-resolves after
``_TRANSITION_AUTO_RESOLVE_DAYS`` (7 d) or when an operator marks
it resolved.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import AlertEvent, AlertRule
from app.models.asn import ASN, ASNRpkiRoa
from app.models.audit import AuditLog
from app.models.bgp_looking_glass import BGPLGPeer, BGPLGRoute, LookingGlassCollector
from app.models.bgp_monitor import BGPHijackDetection, BGPTrackedPrefix
from app.models.circuit import Circuit
from app.models.dhcp import (
    DHCPLease,
    DHCPObservedResponder,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    RAObservedRouter,
)
from app.models.dns import DNSServer, DNSZone
from app.models.domain import Domain
from app.models.ipam import IPAddress, IPBlock, IpMacHistory, Subnet
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.models.network_service import NetworkService, NetworkServiceResource
from app.models.overlay import OverlayNetwork
from app.models.ownership import Site
from app.models.settings import PlatformSettings
from app.models.tls_cert import (
    STATE_MISMATCH,
    STATE_UNREACHABLE,
    TLSCertTarget,
)
from app.models.vrf import VRF
from app.models.wol_schedule import (
    VERIFY_STATE_DONE,
    WolRun,
    WolRunTarget,
    WolSchedule,
)
from app.services import audit_forward, feature_modules
from app.services.bgp.hijack_monitor import (
    RPKI_INVALID,
    expected_origin_set,
    severity_for_rpki,
)
from app.services.wol_scheduler.verify import seen_since

logger = structlog.get_logger(__name__)


RULE_TYPE_SUBNET_UTILIZATION = "subnet_utilization"
RULE_TYPE_SERVER_UNREACHABLE = "server_unreachable"
# ASN / RPKI rule types — Phase 2 of issue #85.
RULE_TYPE_ASN_HOLDER_DRIFT = "asn_holder_drift"
RULE_TYPE_ASN_WHOIS_UNREACHABLE = "asn_whois_unreachable"
RULE_TYPE_RPKI_ROA_EXPIRING = "rpki_roa_expiring"
RULE_TYPE_RPKI_ROA_EXPIRED = "rpki_roa_expired"
# BGP prefix-hijack rule types — issue #527. Backed by the
# ``bgp_hijack_detection`` latch table populated by
# ``app.tasks.bgp_hijack_poll`` (+ the optional RIS Live consumer). The
# matcher reads active (unresolved, unacknowledged) detection rows;
# per-detection severity (critical for RPKI-invalid, warning for
# RPKI-unknown) rides through as a severity override.
RULE_TYPE_BGP_PREFIX_HIJACK = "bgp_prefix_hijack"
RULE_TYPE_BGP_MORE_SPECIFIC = "bgp_more_specific_announced"
# BGP Looking Glass internal-RIB alert family — issue #566 Phase 5.
# Companion to the #527 public-table hijack monitor above: that watches
# the public routing table via RIPEstat/RIS Live, these watch the
# operator's OWN live table via the receive-only Looking Glass
# collector (bgp_lg_peer / bgp_lg_route). unexpected_origin and
# more_specific deliberately reuse the SAME BGPTrackedPrefix config
# table #527 already has (an operator's "prefixes I own + expected
# origin ASN" list, curated once at /asns/{id}/tracked-prefixes) —
# both the external and internal monitors read it.
RULE_TYPE_BGP_LG_SESSION_DOWN = "bgp_lg_session_down"
RULE_TYPE_BGP_LG_RPKI_INVALID_ROUTE = "bgp_lg_rpki_invalid_route"
RULE_TYPE_BGP_LG_UNEXPECTED_ORIGIN = "bgp_lg_unexpected_origin"
RULE_TYPE_BGP_LG_MORE_SPECIFIC = "bgp_lg_more_specific"
RULE_TYPE_BGP_LG_ROUTE_FLAP = "bgp_lg_route_flap"
RULE_TYPE_BGP_LG_MISSING_ADVERTISEMENT = "bgp_lg_missing_advertisement"
# Domain rule types — Phase 2 of issue #87.
RULE_TYPE_DOMAIN_EXPIRING = "domain_expiring"
RULE_TYPE_DOMAIN_NS_DRIFT = "domain_nameserver_drift"
RULE_TYPE_DOMAIN_REGISTRAR_CHANGED = "domain_registrar_changed"
RULE_TYPE_DOMAIN_DNSSEC_CHANGED = "domain_dnssec_status_changed"
# Circuit rule types — alerting hooks for issue #93.
RULE_TYPE_CIRCUIT_TERM_EXPIRING = "circuit_term_expiring"
RULE_TYPE_CIRCUIT_STATUS_CHANGED = "circuit_status_changed"
# Service catalog rule types — alerting hooks for issue #94.
RULE_TYPE_SERVICE_TERM_EXPIRING = "service_term_expiring"
RULE_TYPE_SERVICE_RESOURCE_ORPHANED = "service_resource_orphaned"
# Compliance change alerts — issue #105. One rule type with two
# params (``classification`` + ``change_scope``) covers every flag
# without exploding into N near-identical rule_type rows.
RULE_TYPE_COMPLIANCE_CHANGE = "compliance_change"
RULE_TYPE_AUDIT_CHAIN_BROKEN = "audit_chain_broken"
# Issue #565 — the Celery worker/beat found the DB schema behind the
# bundled Alembic head ("code deployed before migrate ran"). Subject =
# the platform (a single singleton event). Managed directly by the
# ``app.tasks.schema_check`` periodic task (like ``audit_chain_broken``
# above), not the generic evaluator — the task opens/resolves the
# event itself off the version-vs-head comparison.
RULE_TYPE_SCHEMA_BEHIND_HEAD = "schema_behind_head"
# Voice-VLAN client-count drop — issue #112 phase 2. Counts active
# DHCP leases on every subnet tagged ``subnet_role='voice'``; fires
# when the count drops below ``threshold_percent`` (reused as a raw
# count threshold for this rule type — operators set it to e.g. 10
# meaning "alert me when fewer than 10 phones are reachable").
RULE_TYPE_VOICE_LEASE_COUNT_BELOW = "voice_lease_count_below"

# Issue #183 Phase 6 — k3s server cert expiry. Subject = appliance.
# Same threshold-escalation shape as ``circuit_term_expiring`` /
# ``domain_expiring``: warning at threshold_days, escalating to
# critical as expiry approaches. Default threshold 30 d.
RULE_TYPE_K3S_API_CERT_EXPIRING = "k3s_api_cert_expiring"

# Address-space hygiene — issue #45. Fires when a subnet holds more than
# ``threshold_percent`` (re-used as a raw count) allocated IPs whose
# ``last_seen_at`` is older than ``threshold_days`` (default 90). The
# companion to the Stale-IP report: the report is the operator-driven
# drilldown, this is the passive "your hygiene is slipping" feed.
RULE_TYPE_STALE_IP_COUNT = "stale_ip_count"

# A dynamic DHCP pool whose live occupancy has reached ``threshold_percent``
# (assigned ÷ range size) OR whose free-address count has dropped below
# ``min_free_addresses``. Orthogonal to ``subnet_utilization`` — that counts
# allocated IPAM rows, this counts active DHCP leases inside the pool range,
# so a pool can be exhausted (clients failing to get a lease) while the IPAM
# subnet shows low allocated-row utilisation. Issue #339.
RULE_TYPE_DHCP_POOL_EXHAUSTION = "dhcp_pool_exhaustion"

# Issue #285 Phase 2d — fleet firewall drift. Subject = appliance. Fires
# when the control-plane-rendered firewall hash (FirewallApplyState.
# rendered_hash) hasn't been applied by the host runner (applied_hash)
# past a grace window, AND the node's last apply was a clean ``ok`` — so
# it's a genuine stall, NOT an apply error (its own ``error:*`` chip) or a
# deliberate auto-revert (``reverted`` — alarming on those would never
# resolve since applied_hash != rendered_hash permanently). Distinct from
# agent-offline: the message cross-references the supervisor's last_seen_at
# to say whether the supervisor itself is stale or just the host runner.
RULE_TYPE_FIREWALL_APPLY_STALLED = "firewall.apply_stalled"

# Issue #76 — internal cert / API-token / secret expiry. One rule spans
# multiple credential tables (supervisor mTLS certs + API tokens with an
# expiry), so the subject_type is the generic "secret" and the subject_id
# encodes the source + row id (``appliance_cert:<id>`` / ``api_token:<id>``)
# to keep each credential's event distinct. Severity escalates like the
# other ``*_expiring`` rules (threshold/4 → warning, threshold/12 →
# critical). Catches the "we forgot to rotate" 3am-page failure mode.
RULE_TYPE_SECRET_EXPIRING = "secret_expiring"

# Issue #882 — an agent reported that it could NOT apply the config we sent
# and has reverted to its last-known-good (or has nothing to revert to).
# Subject = the dns_server / dhcp_server / looking_glass_collector row.
#
# Deliberately NOT folded into ``server_unreachable``: that rule is about
# an agent we cannot hear from, and this one fires on an agent that is
# heartbeating perfectly, whose daemon is healthy, and whose answers are
# simply not the ones the operator configured. Reachability alerting is
# what makes such a divergence invisible — the server looks fine on every
# other signal, which is exactly why a revert needs its own alarm rather
# than a health check.
#
# Severity comes from the reported status, not from the rule: ``reverted``
# is a warning (serving, wrong config), ``revert_failed`` / ``no_previous``
# are critical (may not be serving at all).
RULE_TYPE_AGENT_CONFIG_REJECTED = "agent_config_rejected"

# Issue #983 Phase 2 item 7 — node resource pressure from PSI (Pressure Stall
# Information), GA in Kubernetes 1.36. Subject = the node NAME (there is no DB
# row for a cluster node).
#
# This is the alarm #980 needed and nothing could raise: the appliance dropped
# relayed DHCP under CPU pressure with every dashboard green, because
# utilisation cannot distinguish a node at 70% CPU with a run queue from a
# node at 70% without one. PSI measures the thing that actually hurts — the
# share of wall-clock time tasks spent STALLED waiting for a resource.
#
# "Sustained" needs no state here, which is the neat part: the kernel already
# publishes 10 / 60 / 300-second rolling averages, so the 300 s window IS the
# sustained reading. Evaluating avg300 makes a burst and a condition different
# numbers rather than the same number seen twice.
#
# Two thresholds that deliberately do NOT share a knob:
#   * ``some`` (at least one task stalled) is compared against the rule's
#     ``threshold_percent``.
#   * ``full`` on MEMORY (every runnable task stalled) has its own fixed
#     floor. ``some`` at 20% is a busy node; ``full`` at 20% is a node that
#     spent a fifth of five minutes doing no work at all. One operator knob
#     cannot mean both, and reusing it would make whichever they tuned for
#     wrong for the other.
# CPU ``full`` is not evaluated at all: the kernel reports it as 0 at node
# level by definition, so a threshold on it could only ever be dead code.
RULE_TYPE_NODE_PRESSURE = "node_pressure"

# Issue #985 — cluster DNS (CoreDNS) degraded. Subject is the CLUSTER, not a
# node: CoreDNS is a cluster-scoped service and "which node" is already inside
# the message.
#
# We have acted on cluster DNS since #590 / #750 (``ensure_coredns_ha`` matches
# replicas and spread to the node count) and shown nothing about it, so a
# CoreDNS that is down, single-replica or co-located read as "everything
# healthy" until an unrelated pod restart failed to resolve
# ``spatium-control-spatiumddi-api.spatium.svc``.
#
# Two severities, because they are two different faults:
#   * WARNING — fewer ready replicas than ``ensure_coredns_ha`` targets, or
#     two replicas parked on the same node. Cluster DNS still answers; it just
#     will not survive losing that node (#633's failure exactly).
#   * CRITICAL — no ready replicas, or the resolve probe failed. The probe is
#     the load-bearing one: replica counts say the pods exist, the probe says
#     the path works, and a probe failure with healthy replicas points at
#     kube-proxy or the CNI rather than at CoreDNS.
RULE_TYPE_CLUSTER_DNS_DEGRADED = "cluster_dns_degraded"

# Issue #999 Part A — storage redundancy. Subject = appliance.
#
# The alarm the appliance has never had, and the reason #999 ships
# monitoring BEFORE it ships the ability to install onto a mirror: a
# mirrored root with no degraded-array alarm is a mirror that silently
# becomes a single disk. The operator pays for two disks, the array loses
# a member at 03:00, and the box keeps serving perfectly until the
# survivor dies — strictly worse than never mirroring, because it
# displaced the backup discipline they would otherwise have kept.
#
# Severity is decided per finding by ``evaluate_storage`` and keys off
# REDUNDANCY REMAINING rather than off the state string: ``2 of 3`` in a
# three-way mirror and ``1 of 2`` in a pair both report "degraded", and
# only the second has nothing left to lose. The rule's own severity is
# just the floor.
#
# Silent where the reading does not exist — a supervisor too old to
# collect storage state ships no ``storage`` key, and that is UNKNOWN,
# not a clean bill of health.
RULE_TYPE_APPLIANCE_STORAGE_DEGRADED = "appliance_storage_degraded"


class AlertDataUnavailable(Exception):
    """A rule could not be evaluated because its input is temporarily gone.

    Distinct from "no subjects matched", and the distinction is load-bearing:
    ``evaluate_all`` RESOLVES every open event whose subject is absent from
    this pass's matches. So a matcher that returns ``[]`` when it simply could
    not read anything closes the operator's open events, and re-opens them on
    the next successful tick — a notification flap once a minute, under
    exactly the load the rule exists to report.

    Raising this instead skips the rule for one pass, leaving open events
    open and opening nothing new. "We do not know" is not "it recovered".
    """


# Percent of wall time, averaged over 300 s, with EVERY runnable task stalled
# on memory. Fixed rather than operator-tunable in v1, same as the other
# rules' fixed windows.
_NODE_PRESSURE_FULL_CRITICAL_PCT = 1.0
_NODE_PRESSURE_RULE_NAME = "Node under sustained resource pressure"
_CLUSTER_DNS_RULE_NAME = "Cluster DNS degraded"
_APPLIANCE_STORAGE_RULE_NAME = "Appliance storage redundancy degraded"


# Issue #46 — planned-decommission awareness. Subject = subnet. Fires
# when a subnet's ``decom_date`` falls within ``threshold_days`` (default
# 30). Same threshold-escalation shape as the other ``*_expiring`` rules
# (warning at threshold/4 → critical at threshold/12); a past-due decom
# date (negative days) is always critical. Catches the "we scheduled this
# segment for retirement and forgot" failure mode.
RULE_TYPE_DECOM_EXPIRING = "decom_expiring"

# DNS query-behaviour anomalies — issue #371. Subject = dns_server. Evaluated
# on the 60 s tick against the per-server ``dns_metric_sample`` rcode deltas
# the agents already report (no new collection). Both reuse the generic
# AlertRule int columns instead of a bespoke window column:
#   * ``dns_nxdomain_spike`` — fires when, over the trailing window, a server's
#     NXDOMAIN ratio (nxdomain ÷ queries_total) reaches ``threshold_percent``
#     AND the absolute NXDOMAIN count reaches ``min_free_addresses`` (the
#     low-traffic guard, so a server answering 3 queries / 2 NXDOMAIN doesn't
#     page). Catches DGA beacons / broken-client search-domain storms.
#   * ``dns_query_rate_spike`` — fires when the trailing window's query total
#     exceeds the prior equal-length window by ``threshold_percent`` AND clears
#     the ``min_free_addresses`` absolute floor (so tiny servers don't page on
#     a 3→9 query "300% spike"). A cold prior window counts as a spike once the
#     floor is cleared.
# The window itself is a fixed module constant (not operator-tunable in v1) —
# same approach as the firewall / transition rules' fixed grace windows.
RULE_TYPE_DNS_NXDOMAIN_SPIKE = "dns_nxdomain_spike"
RULE_TYPE_DNS_QUERY_RATE_SPIKE = "dns_query_rate_spike"
# Response Rate Limiting actively dropping (#146 Phase 3). Subject =
# dns_server. Open-while-true: fires when RateDropped summed over the window
# clears the floor, auto-resolves when the flood subsides.
RULE_TYPE_DNS_RATE_LIMIT_DROPPING = "dns_rate_limit_dropping"

# A DHCP server losing packets it never got to read (#980). Subject =
# dhcp_server. Open-while-true, same shape as the RRL rule above.
#
# This is deliberately NOT folded into ``dhcp_pool_exhaustion`` or any
# reachability check, because it is invisible to both: the server is up,
# heartbeating, has free addresses, and answers 100 % of the packets that
# reach it. The loss is in the kernel's socket buffer, on a node whose CPU
# the receive thread is not getting in time, and the only place it appears
# is the counter this rule reads. Measured on kea-dhcp4 3.0.3: a run that
# lost 9,700 datagrams that way left ``pkt4-receive-drop`` at 0 and every
# other signal green.
#
# It fires on ``socket_drop`` ONLY, never on ``receive_drop``, even though
# both are reported. ``pkt4-receive-drop`` counts packets Kea read and threw
# away *on purpose* as well as by accident: verified against kea-dhcp4 3.0.3,
# a client matching a ``DROP`` client-class — which is exactly what the
# shipped DHCP MAC blocklist renders — increments it once per blocked packet.
# Kea's HA hook drops out-of-scope queries in ``hot-standby`` the same way.
# So a rule that counted it would fire permanently, and never auto-resolve,
# on two ordinary correctly-working configurations. Deliberate policy drops
# are not loss.
RULE_TYPE_DHCP_PACKETS_DROPPED = "dhcp_packets_dropped"

# Issue #1110 — a DHCP scope served by two or more servers that do not
# coordinate: Windows DHCP members holding it with no failover relationship
# covering it on both, over overlapping ranges; or a Windows member holding a
# scope a Kea member of the same group also serves. Each server hands out the
# same addresses to different clients, and neither reports a problem — both
# scopes look healthy, both servers answer, and the first symptom is two
# machines with one address. Subject = the group + scope CIDR (a scope held on
# Windows need not have a SpatiumDDI row). Reads the topology poll's stored
# observations through the same report the group's Windows failover panel
# shows, so the alarm and the panel cannot disagree.
RULE_TYPE_DHCP_SCOPE_UNCOORDINATED = "dhcp_scope_uncoordinated"

# Active IP reconciliation hygiene alerts — issue #369. Subject = ip_address.
# Reuse the on-the-wire liveness signal (IPAddress.last_seen_at) the discovery
# sweep + SNMP poll already write + the ip_mac_history observation log; no new
# collectors. The window for each is ``threshold_days`` (reused).
#   * ip_free_but_responding — an 'available' row that answered within the last
#     threshold_days (default 1). "IPAM says free, host is up."
#   * stale_reservation — a 'reserved'/'static_dhcp' row last seen > threshold_days
#     ago (default 90). The gap stale_ip_count deliberately leaves (allocated-only).
#   * unknown_mac_in_static_range — a 'reserved'/'static_dhcp' row whose
#     ip_mac_history holds a recently-observed (≤ threshold_days, default 7) MAC
#     differing from the recorded one — a squat.
RULE_TYPE_IP_FREE_BUT_RESPONDING = "ip_free_but_responding"
RULE_TYPE_STALE_RESERVATION = "stale_reservation"
RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE = "unknown_mac_in_static_range"

# Rogue DHCP server detection — issue #370. Subject = dhcp_responder. Fires on
# dhcp_observed_responder rows classified ``rogue`` (a DHCP server answering on
# a managed segment that isn't a known group member and isn't allowlisted),
# observed within ``threshold_days`` (default 1). The agent's active probe is
# opt-in, so this only has data on segments running the probe.
RULE_TYPE_ROGUE_DHCP = "rogue_dhcp"
_ROGUE_DHCP_RECENCY_DAYS = 1

# Scheduled Wake-on-LAN failed to bring hosts up — issue #596 Phase 2.
# Subject = **wol_schedule**, deliberately NOT the run: a 15-minute schedule
# would otherwise open ~96 events a day. One open event per failing schedule,
# carrying the blast-radius rollup.
#
# Fires when a schedule's LATEST finalised run (``verify_state='done'``, started
# within ``threshold_days``) left SENT hosts unconfirmed AND a fresh passive
# re-check still can't see them. That re-check is what makes the alert
# recovery-aware: as stragglers boot and some other subsystem (SNMP ARP/FDB, a
# DHCP lease, an nmap sweep) stamps ``IPAddress.last_seen_at``, the matcher stops
# matching and the shared evaluator loop auto-resolves the event — no separate
# resolve path. A clean next run, or the failing run ageing out of the window,
# resolves it too.
#
# Ad-hoc runs (``schedule_id IS NULL``) never match: they have no schedule
# subject. Their outcome lives in History + the copilot tools.
RULE_TYPE_WOL_WAKE_FAILED = "wol_wake_failed"
# How far back a failing run stays alertable. One day: a lab PC left off over a
# weekend shouldn't pin an alert open from Friday to Monday.
_WOL_WAKE_FAILED_RECENCY_DAYS = 1
# Hostnames sampled into the alert message before it collapses to "+N more".
_WOL_WAKE_FAILED_SAMPLE = 5

# Rogue IPv6 Router-Advertisement detection — issue #524. Subject = ra_router.
# Fires on ra_observed_router rows classified ``rogue`` (an RA source that
# isn't on the group's expected-router allowlist), observed within
# ``threshold_days`` (default 1). The agent's passive RA sniffer is opt-in, so
# this only has data on segments running the sniffer.
RULE_TYPE_ROGUE_RA = "rogue_ra"
_ROGUE_RA_RECENCY_DAYS = 1

# New-device (arpwatch) detection — issue #459. Subject = ip_mac_observation
# (composite ``ip_id:mac``). Fires on ip_mac_history rows classified ``new``
# (a MAC never seen before, not allowlisted, not on the known fleet) observed
# within ``threshold_days`` (default 7). Locally-administered (randomised) MACs
# are excluded by default to avoid a reconnection storm — set the rule's
# ``classification`` to ``"all"`` to include them. Auto-resolves once the MAC is
# acknowledged / allowlisted (reclassified) or ages out of the window.
RULE_TYPE_NEW_MAC_SEEN = "new_mac_seen"
_NEW_MAC_SEEN_RECENCY_DAYS = 7

# TLS certificate monitoring — issue #118. Subject = tls_cert (one per
# tls_cert_target). ``tls_cert_expiring`` is a standard escalating-expiry
# rule (info → warning → critical as not_after nears, like domain_expiring);
# ``tls_cert_chain_invalid`` / ``tls_cert_unreachable`` are standard
# open-while-true rules; ``tls_cert_changed`` is a transition-once rule that
# latches the fingerprint pair and auto-resolves after the window.
RULE_TYPE_TLS_CERT_EXPIRING = "tls_cert_expiring"
RULE_TYPE_TLS_CERT_CHAIN_INVALID = "tls_cert_chain_invalid"
RULE_TYPE_TLS_CERT_UNREACHABLE = "tls_cert_unreachable"
RULE_TYPE_TLS_CERT_CHANGED = "tls_cert_changed"
# Cert-rotation deviation (#118 Phase 3) — the issuing CA changed (a
# normally-ACME cert coming back from a different issuer); transition-once.
RULE_TYPE_TLS_CERT_ISSUER_CHANGED = "tls_cert_issuer_changed"
# DNSBL / RBL reputation (#528) — recurring-condition latch: fires while a
# public-facing IP is listed on ≥1 enabled blocklist, auto-resolves when the
# sweep finds it delisted (the shared open/resolve loop handles both).
RULE_TYPE_IP_BLOCKLISTED = "ip_blocklisted"

# ``restore_drill_failed`` (issue #702) — a restore-verification drill
# replayed a target's newest archive into a scratch database and an
# assertion did not hold. Subject is the **backup target**, so a target
# failing every night holds one open event instead of opening a new one
# per drill. Deliberately matches only ``state="failed"`` (the archive
# is not restorable), never ``state="error"`` (the drill couldn't run —
# says nothing about the backup, and paging on it would train operators
# to ignore the rule). Auto-resolves when the target's next drill
# passes.
RULE_TYPE_RESTORE_DRILL_FAILED = "restore_drill_failed"

# ``dns_tunneling_suspected`` (issue #699) — a client's DNS behaviour
# scored above the tunneling threshold in a recent hourly window.
# Subject is the **client IP**, so a host tunnelling for six hours holds
# one open event rather than six. Auto-resolves when the client's recent
# windows drop back below the threshold, which is what makes it safe to
# leave armed: a one-off spike closes itself on the next tick.
RULE_TYPE_DNS_TUNNELING = "dns_tunneling_suspected"

# ``dns_beaconing_suspected`` (issue #699) — a client queried one name
# on a metronomic cadence. Subject is the client, like tunneling.
#
# Seeded DISABLED, unlike tunneling: a health check every 30 s is
# beaconing by any timing measure and scores ~100, so on a typical
# network this rule fires on monitoring infrastructure the moment it is
# switched on. It is genuinely useful once an operator has muted their
# known pollers — which is exactly the workflow the mute feature
# provides — but arriving pre-armed would teach people to ignore it.
RULE_TYPE_DNS_BEACONING = "dns_beaconing_suspected"

# ``dns_dga_suspected`` (issue #699) — a client queried a crop of
# algorithmically-generated domain names. Subject is the client, like
# the other two.
#
# Seeded DISABLED, for a reason specific to this detection rather than
# beaconing's: the issue originally specified scoring NXDOMAIN-heavy
# clients, and the BIND9 query log carries no rcode, so the score rests
# on name plausibility alone (see ``services/dns_threat/dga.py``). That
# is a weaker basis than tunneling's four independent signals, and
# hashed-CDN / shortlink traffic shares the shape — so it wants an
# operator who has looked at their own baseline first.
RULE_TYPE_DNS_DGA = "dns_dga_suspected"
# The alerting bar lives in ``dns_threat.aggregate`` next to
# ``INTERESTING_SCORE`` so the two stay a visible pair rather than
# drifting apart in separate modules — "worth a look on a dashboard"
# and "page me at 03:00" are deliberately different bars. Resolved via
# a function-local import in the matcher below (module-level would drag
# the aggregator into every alerts import).
# Only consider windows this recent, so a finding from last week doesn't
# keep an event open after the behaviour stopped.
_DNS_TUNNEL_WINDOW = timedelta(hours=6)
# Unreachable only pages after a couple of consecutive failures so a
# single transient handshake blip doesn't fire.
_TLS_CERT_UNREACHABLE_MIN_FAILURES = 2

RULE_TYPES = frozenset(
    {
        RULE_TYPE_SUBNET_UTILIZATION,
        RULE_TYPE_SERVER_UNREACHABLE,
        RULE_TYPE_ASN_HOLDER_DRIFT,
        RULE_TYPE_ASN_WHOIS_UNREACHABLE,
        RULE_TYPE_RPKI_ROA_EXPIRING,
        RULE_TYPE_RPKI_ROA_EXPIRED,
        RULE_TYPE_BGP_PREFIX_HIJACK,
        RULE_TYPE_BGP_MORE_SPECIFIC,
        RULE_TYPE_BGP_LG_SESSION_DOWN,
        RULE_TYPE_BGP_LG_RPKI_INVALID_ROUTE,
        RULE_TYPE_BGP_LG_UNEXPECTED_ORIGIN,
        RULE_TYPE_BGP_LG_MORE_SPECIFIC,
        RULE_TYPE_BGP_LG_ROUTE_FLAP,
        RULE_TYPE_BGP_LG_MISSING_ADVERTISEMENT,
        RULE_TYPE_DOMAIN_EXPIRING,
        RULE_TYPE_DOMAIN_NS_DRIFT,
        RULE_TYPE_DOMAIN_REGISTRAR_CHANGED,
        RULE_TYPE_DOMAIN_DNSSEC_CHANGED,
        RULE_TYPE_CIRCUIT_TERM_EXPIRING,
        RULE_TYPE_CIRCUIT_STATUS_CHANGED,
        RULE_TYPE_SERVICE_TERM_EXPIRING,
        RULE_TYPE_SERVICE_RESOURCE_ORPHANED,
        RULE_TYPE_COMPLIANCE_CHANGE,
        RULE_TYPE_AUDIT_CHAIN_BROKEN,
        RULE_TYPE_SCHEMA_BEHIND_HEAD,
        RULE_TYPE_VOICE_LEASE_COUNT_BELOW,
        RULE_TYPE_K3S_API_CERT_EXPIRING,
        RULE_TYPE_STALE_IP_COUNT,
        RULE_TYPE_DHCP_POOL_EXHAUSTION,
        RULE_TYPE_FIREWALL_APPLY_STALLED,
        RULE_TYPE_SECRET_EXPIRING,
        RULE_TYPE_AGENT_CONFIG_REJECTED,
        RULE_TYPE_DHCP_SCOPE_UNCOORDINATED,
        RULE_TYPE_NODE_PRESSURE,
        RULE_TYPE_CLUSTER_DNS_DEGRADED,
        RULE_TYPE_APPLIANCE_STORAGE_DEGRADED,
        RULE_TYPE_DECOM_EXPIRING,
        RULE_TYPE_DNS_NXDOMAIN_SPIKE,
        RULE_TYPE_DNS_QUERY_RATE_SPIKE,
        RULE_TYPE_DNS_RATE_LIMIT_DROPPING,
        RULE_TYPE_IP_FREE_BUT_RESPONDING,
        RULE_TYPE_STALE_RESERVATION,
        RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE,
        RULE_TYPE_ROGUE_DHCP,
        RULE_TYPE_ROGUE_RA,
        RULE_TYPE_WOL_WAKE_FAILED,
        RULE_TYPE_NEW_MAC_SEEN,
        RULE_TYPE_TLS_CERT_EXPIRING,
        RULE_TYPE_TLS_CERT_CHAIN_INVALID,
        RULE_TYPE_TLS_CERT_UNREACHABLE,
        RULE_TYPE_TLS_CERT_CHANGED,
        RULE_TYPE_TLS_CERT_ISSUER_CHANGED,
        RULE_TYPE_IP_BLOCKLISTED,
        RULE_TYPE_RESTORE_DRILL_FAILED,
        RULE_TYPE_DNS_TUNNELING,
        RULE_TYPE_DNS_BEACONING,
        RULE_TYPE_DNS_DGA,
    }
)

# IP-hygiene window defaults (issue #369), each reused as ``threshold_days``.
_FREE_RESPONDING_RECENCY_DAYS = 1
_STALE_RESERVATION_DAYS = 90
_SQUAT_RECENCY_DAYS = 7
# Defensive cap on per-IP hygiene events opened per tick — a badly-misconfigured
# discovery run shouldn't open thousands of AlertEvents in one 60 s pass. The
# matcher logs when it truncates (no silent cap).
_IP_HYGIENE_MAX_EVENTS = 500

# DNS query-anomaly evaluation window + defaults (issue #371). 15 min spans
# ~15 one-minute buckets / 3 five-minute buckets — long enough to smooth a
# single noisy bucket, short enough to page within a quarter hour.
_DNS_ANOMALY_WINDOW = timedelta(minutes=15)
_DNS_NXDOMAIN_RATIO_DEFAULT = 40  # % of queries that are NXDOMAIN
_DNS_NXDOMAIN_MIN_COUNT_DEFAULT = 200  # absolute NXDOMAIN floor over the window
_DNS_QUERY_RATE_SPIKE_PCT_DEFAULT = 200  # current ≥ prior × (1 + 200%) = ×3
_DNS_QUERY_RATE_MIN_DEFAULT = 1000  # absolute query floor over the window
# RRL actively-dropping floor (#146 Phase 3): RateDropped summed over the
# window must clear this to fire — a sustained drop stream means the server
# is shedding a flood, i.e. likely under attack. Below it, a few drops from
# an over-eager client are just noise.
_DNS_RATE_LIMIT_DROP_MIN_DEFAULT = 100

# DHCP packet-loss evaluation window + floor (#980). Same 15 min as the DNS
# anomaly rules, for the same reason: long enough to smooth one noisy bucket,
# short enough to page inside a quarter hour.
#
# The floor is 1 — ANY confirmed loss fires. That is deliberate and unlike
# the RRL rule's 100: RRL dropping a few responses is the feature working as
# designed, whereas a DHCP datagram the kernel discarded before the server
# could read it is never intended behaviour and always costs a client a full
# retransmit round (4 s and up). A floor of 1 is only safe because the rule
# reads ``socket_drop`` alone — see the rule-type comment for why
# ``receive_drop`` would make it fire forever on a working MAC blocklist.
# The floor is still an operator knob (``min_free_addresses``, reused as a
# raw count like the other DHCP rules) for a site that would rather hear
# about it only past a threshold.
_DHCP_PACKET_LOSS_WINDOW = timedelta(minutes=15)
_DHCP_PACKET_LOSS_MIN_DEFAULT = 1

# Issue #285 Phase 2d — how long a control-plane-rendered firewall hash may
# go un-applied (ok-status) before it's "stalled". Comfortably larger than
# the worst-case render→heartbeat→apply→report round-trip (1-2 heartbeats),
# so the normal one-tick lag never alarms. Anchored on a ``stalled_since``
# watermark the matcher stamps on first observation (NOT last_rendered_at,
# which the server bumps every heartbeat).
_FIREWALL_STALE_GRACE = timedelta(minutes=3)
_FIREWALL_APPLY_STALLED_RULE_NAME = "Firewall apply stalled"

# Default stale-IP alert params when the rule doesn't pin them.
_STALE_IP_DEFAULT_COUNT_THRESHOLD = 10
_STALE_IP_DEFAULT_DAYS = 90

# Compliance-change rule constants. Keep in lock-step with the
# Subnet model in ``backend/app/models/ipam.py`` — only flags that
# exist as Subnet columns can be matched. Inheritance from
# block / space is intentionally deferred (the schema doesn't carry
# the flags above subnet level today; revisit when block/space-level
# classification lands).
COMPLIANCE_CLASSIFICATIONS: frozenset[str] = frozenset(
    {"pci_scope", "hipaa_scope", "internet_facing"}
)
_CLASSIFICATION_LABEL: dict[str, str] = {
    "pci_scope": "PCI",
    "hipaa_scope": "HIPAA",
    "internet_facing": "internet-facing",
}

COMPLIANCE_CHANGE_SCOPES: frozenset[str] = frozenset({"any_change", "create", "delete"})
_COMPLIANCE_CHANGE_SCOPE_ACTIONS: dict[str, frozenset[str]] = {
    "any_change": frozenset({"create", "update", "delete"}),
    "create": frozenset({"create"}),
    "delete": frozenset({"delete"}),
}

# Compliance events are point-in-time notifications, not ongoing
# conditions. Keep them open just long enough to surface on the
# alerts dashboard, then auto-resolve.
_COMPLIANCE_CHANGE_AUTO_RESOLVE_HOURS = 24

# Cap the audit-row scan per pass — guards against a runaway backfill
# if a rule sat disabled for a long time then got flipped on. The
# watermark advances by however many rows we processed, so the next
# tick picks up where this one left off.
_COMPLIANCE_CHANGE_SCAN_LIMIT = 1000

# Resource types in audit_log we know how to map back to a Subnet for
# classification lookup. Anything outside this set is skipped with a
# logged debug. The map values name a mapper function below.
_COMPLIANCE_RESOURCE_TYPES: frozenset[str] = frozenset({"subnet", "ip_address", "dhcp_scope"})

# Resource-kind → SQLAlchemy model for the orphan sweep. Mirrors the
# router's ``_KIND_MODEL`` map. ``overlay_network`` lit up alongside
# #95 so the sweep covers it too.
_ORPHAN_RESOURCE_MODELS: dict[str, Any] = {
    "vrf": VRF,
    "subnet": Subnet,
    "ip_block": IPBlock,
    "dns_zone": DNSZone,
    "dhcp_scope": DHCPScope,
    "circuit": Circuit,
    "site": Site,
    "overlay_network": OverlayNetwork,
}

# ``circuit_status_changed`` — destination statuses that are
# operator-noteworthy. ``active`` ↔ ``pending`` flips during
# commissioning are routine and don't fire.
_CIRCUIT_STATUS_CHANGE_DESTS: frozenset[str] = frozenset({"suspended", "decom"})

# BGP Looking Glass alert-family constants (issue #566 Phase 5).
# Fixed windows, not operator-tunable columns — same precedent as
# _FIREWALL_STALE_GRACE / _DNS_ANOMALY_WINDOW above.
#
# session_down: a peer flapping momentarily (TCP reset, brief
# reconnect) shouldn't page; only a sustained down state does. Anchored
# on BGPLGPeer.down_since, which THIS module stamps (see
# _matching_bgp_lg_session_down_subjects) — mirrors
# _FIREWALL_STALE_GRACE's stalled_since pattern exactly.
_BGP_LG_SESSION_DOWN_GRACE = timedelta(minutes=2)

# route_flap: a route counts as "flapping" once its lifetime
# withdraw-count crosses the floor AND the most recent flap was within
# this trailing window — so a route that flapped a lot long ago but has
# been stable since ages out instead of paging forever.
_BGP_LG_FLAP_WINDOW = timedelta(minutes=10)
_BGP_LG_FLAP_COUNT_DEFAULT = 5

# Defensive cap mirroring _IP_HYGIENE_MAX_EVENTS — a freshly-enabled
# rule against a large RIB shouldn't open thousands of AlertEvents in
# one 60s tick. Logs a warning when truncated (no silent cap).
_BGP_LG_MAX_EVENTS = 500

# Default consecutive-failure threshold for ``asn_whois_unreachable``.
_ASN_WHOIS_UNREACHABLE_THRESHOLD = 3

# Default expiring threshold when ``domain_expiring`` doesn't pin one.
_DEFAULT_EXPIRING_THRESHOLD_DAYS = 30

# Auto-resolve window for the two "fires once on transition" domain
# rule types (registrar / DNSSEC change). Transitions don't resolve
# themselves the way threshold-bound conditions do, so we time-box
# the open event. Operators can also manually resolve at any point.
_TRANSITION_AUTO_RESOLVE_DAYS = 7


def _prefix_len(network: str) -> tuple[int, int] | None:
    """Return (prefix_len, family) — family is 4 or 6. None on parse error."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return None
    return net.prefixlen, net.version


def _include_subnet(subnet: Subnet, settings: PlatformSettings | None) -> bool:
    """Mirror of frontend/src/lib/utilization.ts:includeInUtilization."""
    if settings is None:
        return True
    parsed = _prefix_len(str(subnet.network))
    if parsed is None:
        return True
    prefix, family = parsed
    max_prefix = (
        settings.utilization_max_prefix_ipv4
        if family == 4
        else settings.utilization_max_prefix_ipv6
    )
    return prefix <= max_prefix


# ── Subject evaluation ─────────────────────────────────────────────────────


async def _matching_subnet_subjects(
    db: AsyncSession,
    rule: AlertRule,
    settings: PlatformSettings | None,
) -> list[tuple[str, str, str]]:
    """Return [(subject_id, display, message), ...] for a subnet_utilization rule."""
    threshold = rule.threshold_percent if rule.threshold_percent is not None else 90
    res = await db.execute(select(Subnet).where(Subnet.utilization_percent >= threshold))
    subnets = list(res.scalars().all())
    matches: list[tuple[str, str, str]] = []
    for s in subnets:
        if not _include_subnet(s, settings):
            continue
        pct = float(s.utilization_percent)
        display = f"{s.network}" + (f" — {s.name}" if s.name else "")
        message = (
            f"Subnet {display} utilisation {pct:.1f}% (threshold {threshold}%) — "
            f"{s.allocated_ips}/{s.total_ips} IPs allocated"
        )
        matches.append((str(s.id), display, message))
    return matches


async def _matching_voice_lease_count_below_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Voice-VLAN subnets where active-lease count has fallen below
    ``rule.threshold_percent`` (re-used as a raw count threshold).

    Useful for catching mass-disconnect events on a phone fleet — if
    a switch / PoE upstream / SBC goes down, every phone drops its
    lease and the count plummets. Operator picks the threshold per
    deployment (typical: ~50% of expected fleet size).
    """
    threshold = int(rule.threshold_percent) if rule.threshold_percent is not None else 1
    # Voice-tagged subnets only — `subnet_role='voice'` is the gate.
    voice_subnets = list(
        (await db.execute(select(Subnet).where(Subnet.subnet_role == "voice"))).scalars().all()
    )
    if not voice_subnets:
        return []

    # Count active leases per voice subnet. ``DHCPLease`` carries
    # ``ip_address`` (INET) + ``state`` — we count rows whose IP is
    # inside the subnet CIDR and state == 'active'. PostgreSQL's
    # ``<<`` (contained-by-network) is the natural operator.
    matches: list[tuple[str, str, str]] = []
    for s in voice_subnets:
        cidr = str(s.network) if s.network else None
        if not cidr:
            continue
        # ``<<`` is the Postgres "is contained by" operator on inet /
        # cidr types. The bind parameter is a plain string so we cast
        # it explicitly with ``::cidr`` — without the cast asyncpg
        # picks VARCHAR and Postgres rejects the operator.
        count = (
            await db.execute(
                select(func.count(DHCPLease.id))
                .where(DHCPLease.state == "active")
                .where(text("ip_address << CAST(:c AS cidr)").bindparams(c=cidr))
            )
        ).scalar_one()
        if int(count or 0) >= threshold:
            continue
        display = f"{s.network}" + (f" — {s.name}" if s.name else "")
        message = (
            f"Voice subnet {display} has {int(count or 0)} active lease(s) "
            f"(threshold {threshold}) — possible mass-disconnect event"
        )
        matches.append((str(s.id), display, message))
    return matches


async def _matching_dhcp_pool_exhaustion_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Dynamic DHCP pools that have hit ``threshold_percent`` occupancy OR
    dropped below ``min_free_addresses`` free addresses (issue #339).

    Occupancy is live, from active ``DHCPLease`` rows inside the pool range
    (see :func:`app.services.dhcp.pool_occupancy.compute_pool_occupancy_batch`),
    so it works for Kea and Windows alike. Only ``pool_type='dynamic'`` pools
    are considered — excluded / reserved ranges never hand out leases. With
    neither threshold set the rule defaults to 90% occupancy so a bare
    enable still does something sensible.
    """
    from app.services.dhcp.pool_occupancy import compute_pool_occupancy_batch

    pct_threshold = rule.threshold_percent
    min_free = rule.min_free_addresses
    if pct_threshold is None and min_free is None:
        pct_threshold = 90

    pools = list(
        (await db.execute(select(DHCPPool).where(DHCPPool.pool_type == "dynamic"))).scalars().all()
    )
    if not pools:
        return []

    # Resolve scope display names in one query (pool → scope name).
    scope_ids = {p.scope_id for p in pools}
    scope_rows = (
        await db.execute(select(DHCPScope.id, DHCPScope.name).where(DHCPScope.id.in_(scope_ids)))
    ).all()
    scope_names: dict[uuid.UUID, str] = {row[0]: row[1] for row in scope_rows}

    # One batched lease query for all pools rather than one per pool (N+1).
    occ_by_pool = await compute_pool_occupancy_batch(db, pools)

    matches: list[tuple[str, str, str]] = []
    for pool in pools:
        occ = occ_by_pool[pool.id]
        if occ.total <= 0:
            continue
        over_pct = pct_threshold is not None and occ.percent >= pct_threshold
        under_free = min_free is not None and occ.free < min_free
        if not (over_pct or under_free):
            continue
        scope_name = scope_names.get(pool.scope_id) or ""
        pool_label = pool.name or f"{pool.start_ip}–{pool.end_ip}"
        display = pool_label + (f" ({scope_name})" if scope_name else "")
        reasons = []
        if over_pct:
            reasons.append(f"{occ.percent:.1f}% occupied (threshold {pct_threshold}%)")
        if under_free:
            reasons.append(f"{occ.free} free (floor {min_free})")
        message = (
            f"DHCP pool {display} — {', '.join(reasons)}; "
            f"{occ.assigned}/{occ.total} addresses leased"
        )
        matches.append((str(pool.id), display, message))
    return matches


async def _matching_stale_ip_count_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Subnets holding ≥ ``threshold_percent`` (raw count) allocated IPs
    whose ``last_seen_at`` is older than ``threshold_days`` (default 90).

    Reads the same discovery (#23) liveness signal the Stale-IP report
    uses. ``include_never_seen`` is intentionally off for the alert —
    never-seen rows are noisy (often in discovery-disabled subnets), so
    the alert fires only on the high-confidence "seen, then went dark"
    signal. Operators chase the full list, including never-seen, from the
    report page.
    """
    from app.services.ipam.stale_ips import count_stale_per_subnet

    threshold = (
        int(rule.threshold_percent)
        if rule.threshold_percent is not None
        else _STALE_IP_DEFAULT_COUNT_THRESHOLD
    )
    stale_days = (
        int(rule.threshold_days) if rule.threshold_days is not None else _STALE_IP_DEFAULT_DAYS
    )
    counts = await count_stale_per_subnet(db, stale_days=stale_days, include_never_seen=False)
    over = {sid: n for sid, n in counts.items() if n >= max(1, threshold)}
    if not over:
        return []

    subnets = list(
        (await db.execute(select(Subnet).where(Subnet.id.in_(over.keys())))).scalars().all()
    )
    matches: list[tuple[str, str, str]] = []
    for s in subnets:
        n = over[s.id]
        display = f"{s.network}" + (f" — {s.name}" if s.name else "")
        message = (
            f"Subnet {display} has {n} stale allocated IP(s) not seen on the "
            f"wire in {stale_days}+ days (threshold {threshold}) — review for "
            f"deprecation from the Stale-IP report"
        )
        matches.append((str(s.id), display, message))
    return matches


async def _matching_ip_free_but_responding_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """``available`` IPs that answered on the wire within the recency window
    (issue #369, case 1) — "IPAM says free, host is up"."""
    days = rule.threshold_days if rule.threshold_days is not None else _FREE_RESPONDING_RECENCY_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    rows = (
        (
            await db.execute(
                select(IPAddress)
                .where(
                    IPAddress.status == "available",
                    IPAddress.last_seen_at.is_not(None),
                    IPAddress.last_seen_at >= cutoff,
                )
                .limit(_IP_HYGIENE_MAX_EVENTS)
            )
        )
        .scalars()
        .all()
    )
    if len(rows) >= _IP_HYGIENE_MAX_EVENTS:
        logger.warning("ip_free_but_responding_truncated", cap=_IP_HYGIENE_MAX_EVENTS)
    matches: list[tuple[str, str, str]] = []
    for r in rows:
        via = f" via {r.last_seen_method}" if r.last_seen_method else ""
        message = (
            f"IP {r.address} is marked 'available' but answered on the wire{via} "
            f"at {r.last_seen_at.isoformat() if r.last_seen_at else '?'} (within "
            f"{days}d) — reclaim it as allocated/discovered or investigate the host."
        )
        matches.append((str(r.id), str(r.address), message))
    return matches


async def _matching_stale_reservation_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """``reserved`` / ``static_dhcp`` IPs not seen within ``threshold_days``
    (issue #369, case 2). The gap ``stale_ip_count`` leaves (allocated-only).
    High-confidence: requires the row to have been seen at least once."""
    days = rule.threshold_days if rule.threshold_days is not None else _STALE_RESERVATION_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    rows = (
        (
            await db.execute(
                select(IPAddress)
                .where(
                    IPAddress.status.in_(("reserved", "static_dhcp")),
                    IPAddress.last_seen_at.is_not(None),
                    IPAddress.last_seen_at < cutoff,
                )
                .limit(_IP_HYGIENE_MAX_EVENTS)
            )
        )
        .scalars()
        .all()
    )
    if len(rows) >= _IP_HYGIENE_MAX_EVENTS:
        logger.warning("stale_reservation_truncated", cap=_IP_HYGIENE_MAX_EVENTS)
    matches: list[tuple[str, str, str]] = []
    for r in rows:
        label = str(r.address) + (f" ({r.hostname})" if r.hostname else "")
        message = (
            f"{r.status} IP {label} hasn't been seen on the wire since "
            f"{r.last_seen_at.isoformat() if r.last_seen_at else '?'} (> {days}d) — "
            f"verify the host still exists or release the reservation."
        )
        matches.append((str(r.id), str(r.address), message))
    return matches


async def _matching_unknown_mac_in_static_range_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """``reserved`` / ``static_dhcp`` IPs whose ip_mac_history holds a recently
    observed MAC differing from the recorded one (issue #369, case 3) — a squat.

    The discovery sweep + SNMP poll log every observed MAC into ip_mac_history
    (see services.ipam.discovery.record_mac_observation); operator-set
    ``mac_address`` is never overwritten, so a differing recent history row is
    a genuine "someone else is answering on this IP" signal.
    """
    days = rule.threshold_days if rule.threshold_days is not None else _SQUAT_RECENCY_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    rows = (
        await db.execute(
            select(IPAddress, IpMacHistory.mac_address, IpMacHistory.last_seen)
            .join(IpMacHistory, IpMacHistory.ip_address_id == IPAddress.id)
            .where(
                IPAddress.status.in_(("reserved", "static_dhcp")),
                IPAddress.mac_address.is_not(None),
                IpMacHistory.mac_address != IPAddress.mac_address,
                IpMacHistory.last_seen >= cutoff,
            )
            .limit(_IP_HYGIENE_MAX_EVENTS)
        )
    ).all()
    # One event per IP — keep the most-recent offending observation if several.
    by_ip: dict[uuid.UUID, tuple[IPAddress, str, datetime]] = {}
    for ip_row, obs_mac, obs_at in rows:
        prev = by_ip.get(ip_row.id)
        if prev is None or obs_at > prev[2]:
            by_ip[ip_row.id] = (ip_row, str(obs_mac), obs_at)
    matches: list[tuple[str, str, str]] = []
    for ip_id, (ip_row, obs_mac, obs_at) in by_ip.items():
        message = (
            f"IP {ip_row.address} ({ip_row.status}) is recorded with MAC "
            f"{ip_row.mac_address} but a different MAC {obs_mac} answered at "
            f"{obs_at.isoformat()} — possible squatter or a device that moved."
        )
        matches.append((str(ip_id), str(ip_row.address), message))
    return matches


async def _matching_rogue_dhcp_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """dhcp_observed_responder rows classified ``rogue`` + seen within the
    recency window (issue #370). Auto-resolves once a responder stops being
    seen as rogue (operator allowlists it → reclassified, or it goes away)."""
    days = rule.threshold_days if rule.threshold_days is not None else _ROGUE_DHCP_RECENCY_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    rows = (
        (
            await db.execute(
                select(DHCPObservedResponder).where(
                    DHCPObservedResponder.classification == "rogue",
                    DHCPObservedResponder.last_seen_at >= cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[str, str, str]] = []
    for r in rows:
        display = f"{r.source_ip} (server-id {r.server_identifier})"
        offered = f", offered {r.offered_ip}" if r.offered_ip else ""
        message = (
            f"Unrecognised DHCP server answering on a managed segment: "
            f"source {r.source_ip}, server-id {r.server_identifier}"
            f"{f', MAC {r.source_mac}' if r.source_mac else ''}{offered}. "
            f"Not a known group member or allowlisted — investigate a rogue / "
            f"misconfigured DHCP server, or acknowledge it if expected."
        )
        matches.append((str(r.id), display, message))
    return matches


async def _matching_rogue_ra_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """ra_observed_router rows classified ``rogue`` + seen within the recency
    window (issue #524). Auto-resolves once a router stops being seen as rogue
    (operator allowlists it → reclassified, or it goes away)."""
    days = rule.threshold_days if rule.threshold_days is not None else _ROGUE_RA_RECENCY_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    rows = (
        (
            await db.execute(
                select(RAObservedRouter).where(
                    RAObservedRouter.classification == "rogue",
                    RAObservedRouter.last_seen_at >= cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[str, str, str]] = []
    for r in rows:
        display = str(r.source_ip)
        prefixes = ", ".join(r.prefixes or []) or "none advertised"
        message = (
            f"Unrecognised IPv6 router advertising on a managed segment: "
            f"source {r.source_ip}"
            f"{f', MAC {r.source_mac}' if r.source_mac else ''} "
            f"(M={int(r.managed_flag)} O={int(r.other_flag)}, prefixes: {prefixes}). "
            f"Not on the RA allowlist — investigate a rogue / misconfigured "
            f"router, or acknowledge it if expected."
        )
        matches.append((str(r.id), display, message))
    return matches


async def _matching_restore_drill_failed_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Backup targets whose most recent finished drill failed.

    Subject is the **target**, not the drill run, so a target failing
    every night holds one open event rather than opening a fresh one
    per drill.

    Only the latest *finished* drill counts. ``running`` rows are
    skipped so a drill in flight neither opens nor resolves anything,
    and ``error`` rows are skipped so an unreachable destination
    doesn't masquerade as a bad archive — an ``error`` leaves whatever
    the previous verdict was standing, which is the honest reading:
    we still don't know any more than we did.

    Restricted to targets that are **enabled with drills scheduled**.
    The manual run-now endpoint will drill a target whose drills are
    off, so without this filter a single ad-hoc failure could open a
    critical event that nothing can ever resolve: the documented
    resolution is "the target's next drill passes", and a target with
    no schedule has no next drill. Switching drills (or the target)
    off now resolves the event on the following tick, which also gives
    operators a reachable way out.

    When the latest finished drill passes, the target stops matching
    and the shared evaluator loop auto-resolves its open event.
    """
    from app.models.backup import BackupTarget, RestoreDrill  # noqa: PLC0415

    rn = func.row_number().over(
        partition_by=RestoreDrill.target_id,
        order_by=RestoreDrill.started_at.desc(),
    )
    ranked = (
        select(
            RestoreDrill.target_id.label("target_id"),
            RestoreDrill.state.label("state"),
            RestoreDrill.filename.label("filename"),
            RestoreDrill.assertions.label("assertions"),
            RestoreDrill.finished_at.label("finished_at"),
            rn.label("rn"),
        )
        .where(RestoreDrill.state.in_(("passed", "failed")))
        .subquery()
    )
    rows = (
        await db.execute(
            select(
                ranked.c.target_id,
                ranked.c.state,
                ranked.c.filename,
                ranked.c.assertions,
                ranked.c.finished_at,
                BackupTarget.name,
            )
            .join(BackupTarget, BackupTarget.id == ranked.c.target_id)
            .where(
                ranked.c.rn == 1,
                ranked.c.state == "failed",
                BackupTarget.enabled.is_(True),
                BackupTarget.drill_enabled.is_(True),
            )
        )
    ).all()

    matches: list[tuple[str, str, str]] = []
    for target_id, _state, filename, assertions, finished_at, target_name in rows:
        failed = [
            a.get("name", "?")
            for a in (assertions or [])
            if isinstance(a, dict) and a.get("status") == "fail"
        ]
        detail = ", ".join(failed) if failed else "no assertion detail recorded"
        when = finished_at.isoformat() if finished_at is not None else "unknown time"
        # "the archive didn't survive" is the wrong story when the
        # failing check is that there IS no archive — the operator
        # would go hunting for corruption instead of finding an empty
        # destination. Branch on the actual finding.
        if "archive_available" in failed:
            message = (
                f"Restore drill FAILED for backup target '{target_name}': the "
                f"destination holds no archives to restore from (checked at "
                f"{when}). There is currently no recovery path from this "
                f"target — confirm its backups are running."
            )
        else:
            message = (
                f"Restore drill FAILED for backup target '{target_name}': the newest "
                f"archive ({filename or 'unknown'}) did not survive a test restore at "
                f"{when}. Failed checks: {detail}. This archive is not a reliable "
                f"recovery path — investigate before you need it."
            )
        matches.append((str(target_id), target_name, message))
    return matches


async def _matching_dns_tunneling_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Clients whose recent DNS behaviour scored as tunneling (#699).

    Subject is the **client IP**, not the window: a host tunnelling for
    six hours should hold one open event, not six. The matcher looks at
    the client's highest-scoring window inside the trailing window, so
    the event auto-resolves once the behaviour stops and the recent
    windows fall back below threshold — no bespoke resolve path.

    ``allowlisted`` windows are excluded structurally rather than by
    score: they are already scored 0, but being explicit keeps the
    intent readable when someone later tunes the threshold down.
    """
    from app.models.dns_threat import DNSClientWindow  # noqa: PLC0415
    from app.models.dns_threat_mute import DNSThreatMute  # noqa: PLC0415
    from app.services.dns_threat.aggregate import ALERTING_SCORE  # noqa: PLC0415

    threshold = rule.threshold_percent if rule.threshold_percent is not None else ALERTING_SCORE
    since = datetime.now(UTC) - _DNS_TUNNEL_WINDOW
    rows = (
        await db.execute(
            select(
                DNSClientWindow.client_ip,
                func.max(DNSClientWindow.tunnel_score).label("peak"),
                func.sum(DNSClientWindow.query_count).label("queries"),
                func.count().label("windows"),
            )
            .where(
                DNSClientWindow.window_start >= since,
                DNSClientWindow.allowlisted.is_(False),
                DNSClientWindow.tunnel_score >= threshold,
                # Operator-muted clients don't page. A host someone has
                # already reviewed and cleared shouldn't keep waking
                # people up — and without this the only way to stop it
                # is disabling the rule, which silences every OTHER
                # client too.
                DNSClientWindow.client_ip.not_in(
                    select(DNSThreatMute.client_ip).where(
                        or_(
                            DNSThreatMute.muted_until.is_(None),
                            DNSThreatMute.muted_until > datetime.now(UTC),
                        )
                    )
                ),
            )
            .group_by(DNSClientWindow.client_ip)
        )
    ).all()
    if not rows:
        return []

    # Fetch the worst window per matching client for the message detail —
    # a score with no "why" is not actionable at 03:00.
    # One statement for the worst window per matching client, instead of
    # a SELECT per client inside the 60 s tick. An operator who lowers
    # the threshold to survey their estate turns that loop into 1 + N
    # with N = every client over the threshold — hundreds of serialised
    # round-trips a minute on a busy resolver, inside evaluate_all,
    # which is also running every other rule type.
    ids = [r[0] for r in rows]
    ranked = (
        select(
            DNSClientWindow.client_ip.label("ip"),
            DNSClientWindow.top_parent.label("top_parent"),
            DNSClientWindow.tunnel_signals.label("signals"),
            func.row_number()
            .over(
                partition_by=DNSClientWindow.client_ip,
                order_by=DNSClientWindow.tunnel_score.desc(),
            )
            .label("rn"),
        )
        .where(
            DNSClientWindow.client_ip.in_(ids),
            DNSClientWindow.window_start >= since,
        )
        .subquery()
    )
    worst_by_ip = {
        str(r.ip): r for r in (await db.execute(select(ranked).where(ranked.c.rn == 1))).all()
    }

    matches: list[tuple[str, str, str]] = []
    for client_ip, peak, queries, windows in rows:
        ip = str(client_ip)
        worst = worst_by_ip.get(ip)
        top_signals = ""
        if worst is not None and worst.signals:
            top = sorted(
                (sig for sig in worst.signals if isinstance(sig, dict)),
                key=lambda sig: sig.get("contribution", 0),
                reverse=True,
            )[:2]
            top_signals = "; ".join(str(sig.get("detail", "")) for sig in top if sig.get("detail"))
        parent = worst.top_parent if worst is not None else None
        message = (
            f"DNS client {ip} scored {peak:.0f}/100 for tunneling behaviour across "
            f"{windows} hourly window(s) ({queries} queries)"
            + (f", concentrated on {parent}" if parent else "")
            + ". "
            + (f"{top_signals}. " if top_signals else "")
            + "DNS tunneling is an exfiltration path that firewalls do not see — "
            "check what this host is running before assuming it is benign."
        )
        matches.append((ip, ip, message))
    return matches


async def _matching_dns_beaconing_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Clients that queried one name on a metronomic cadence (#699).

    Same subject and windowing as the tunneling matcher — the client,
    over the trailing window — so a host beaconing for hours holds one
    open event and it auto-resolves when the pattern stops. Muted
    clients are excluded for the same reason they are there: this rule
    needs the mute workflow more than tunneling does, because
    legitimate pollers score just as high as callbacks.

    The message leads with the NAME and the period, not the score. A
    monitoring agent and a C2 beacon are indistinguishable by timing,
    so the only thing that makes a finding actionable is letting the
    operator recognise their own infrastructure at a glance.
    """
    from app.models.dns_threat import DNSClientWindow  # noqa: PLC0415
    from app.models.dns_threat_mute import DNSThreatMute  # noqa: PLC0415
    from app.services.dns_threat.aggregate import (  # noqa: PLC0415
        BEACON_ALERTING_SCORE,
    )

    threshold = (
        rule.threshold_percent if rule.threshold_percent is not None else BEACON_ALERTING_SCORE
    )
    since = datetime.now(UTC) - _DNS_TUNNEL_WINDOW
    rn = func.row_number().over(
        partition_by=DNSClientWindow.client_ip,
        order_by=DNSClientWindow.beacon_score.desc(),
    )
    ranked = (
        select(
            DNSClientWindow.client_ip.label("ip"),
            DNSClientWindow.beacon_score.label("score"),
            DNSClientWindow.beacon_detail.label("detail"),
            rn.label("rn"),
        )
        .where(
            DNSClientWindow.window_start >= since,
            DNSClientWindow.beacon_score >= threshold,
            DNSClientWindow.client_ip.not_in(
                select(DNSThreatMute.client_ip).where(
                    or_(
                        DNSThreatMute.muted_until.is_(None),
                        DNSThreatMute.muted_until > datetime.now(UTC),
                    )
                )
            ),
        )
        .subquery()
    )
    rows = (await db.execute(select(ranked).where(ranked.c.rn == 1))).all()

    matches: list[tuple[str, str, str]] = []
    for r in rows:
        ip = str(r.ip)
        message = (
            f"DNS client {ip} shows periodic callback behaviour " f"({r.score:.0f}/100). {r.detail}"
        )
        matches.append((ip, ip, message))
    return matches


async def _matching_dns_dga_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Clients that queried a crop of generated domain names (#699).

    Same subject and windowing as the tunneling and beaconing matchers —
    the client, over the trailing window — so a host running a DGA for
    hours holds one open event and it auto-resolves when the crop stops.
    Muted clients are excluded, as with the other two.

    The message leads with the domain count and a sample of the worst
    names rather than the score alone. "212 domains, worst
    xkqjfhwbz.com" is something an operator can act on; a bare 84 is
    not, and this detection in particular needs the evidence visible
    because hashed-CDN and shortlink traffic shares the shape.
    """
    from app.models.dns_threat import DNSClientWindow  # noqa: PLC0415
    from app.models.dns_threat_mute import DNSThreatMute  # noqa: PLC0415
    from app.services.dns_threat.aggregate import DGA_ALERTING_SCORE  # noqa: PLC0415

    threshold = rule.threshold_percent if rule.threshold_percent is not None else DGA_ALERTING_SCORE
    since = datetime.now(UTC) - _DNS_TUNNEL_WINDOW
    rn = func.row_number().over(
        partition_by=DNSClientWindow.client_ip,
        order_by=DNSClientWindow.dga_score.desc(),
    )
    ranked = (
        select(
            DNSClientWindow.client_ip.label("ip"),
            DNSClientWindow.dga_score.label("score"),
            DNSClientWindow.dga_detail.label("detail"),
            rn.label("rn"),
        )
        .where(
            DNSClientWindow.window_start >= since,
            DNSClientWindow.dga_score >= threshold,
            DNSClientWindow.client_ip.not_in(
                select(DNSThreatMute.client_ip).where(
                    or_(
                        DNSThreatMute.muted_until.is_(None),
                        DNSThreatMute.muted_until > datetime.now(UTC),
                    )
                )
            ),
        )
        .subquery()
    )
    rows = (await db.execute(select(ranked).where(ranked.c.rn == 1))).all()

    matches: list[tuple[str, str, str]] = []
    for r in rows:
        ip = str(r.ip)
        message = (
            f"DNS client {ip} queried a crop of algorithmically-generated domain "
            f"names ({r.score:.0f}/100). {r.detail}"
        )
        matches.append((ip, ip, message))
    return matches


async def _matching_wol_wake_failed_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """Schedules whose latest finalised wake left hosts that are STILL not up.

    Subject is the **schedule**, so a 15-minute schedule that fails every fire
    holds one open event rather than opening ~96 a day.

    Per candidate schedule (``verify_enabled`` AND ``verify_alert_enabled``):

    1. Take its most recent run with ``verify_state='done'`` started inside
       ``threshold_days``. Only a finalised run is judged — a run mid-re-wake has
       not given up yet. Ad-hoc runs are excluded structurally: they carry
       ``schedule_id IS NULL`` and so belong to no schedule.
    2. Collect the SENT targets that never confirmed (``verified IS NOT TRUE`` —
       both the probed-down rows and the couldn't-probe NULL rows).
    3. **Re-check them passively, right now.** A target whose ``IPAddress`` has
       been seen since that run started has come up on its own since the verify
       gave up, so it no longer counts. A target with no IPAM row
       (``ip_address_id IS NULL``) can't be re-checked and stays counted.

    If nothing is still down, the schedule stops matching and the shared
    evaluator loop auto-resolves its open event. That re-check is the whole
    recovery story: no bespoke resolve path, and a lab PC that boots twenty
    minutes late closes its own alert on the next 60 s tick.
    """
    days = rule.threshold_days if rule.threshold_days is not None else _WOL_WAKE_FAILED_RECENCY_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))

    schedules = (
        (
            await db.execute(
                select(WolSchedule).where(
                    WolSchedule.verify_enabled.is_(True),
                    WolSchedule.verify_alert_enabled.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    if not schedules:
        return []
    by_id = {s.id: s for s in schedules}

    # Latest DONE run per candidate schedule, within the window, in ONE query —
    # a window function instead of a per-schedule lookup, so the query count
    # doesn't scale with the schedule count on every 60 s tick. Only the runs
    # that actually failed (``unverified_count > 0``) then get the target + seen
    # re-check below, which for a healthy fleet is zero further work.
    rn = func.row_number().over(
        partition_by=WolRun.schedule_id,
        order_by=WolRun.started_at.desc(),
    )
    ranked = (
        select(
            WolRun.id.label("run_id"),
            WolRun.schedule_id.label("schedule_id"),
            WolRun.started_at.label("started_at"),
            WolRun.sent_count.label("sent_count"),
            WolRun.unverified_count.label("unverified_count"),
            rn.label("rn"),
        )
        .where(
            WolRun.schedule_id.in_(list(by_id)),
            WolRun.verify_state == VERIFY_STATE_DONE,
            WolRun.started_at >= cutoff,
        )
        .subquery()
    )
    failing_runs = (
        await db.execute(
            select(
                ranked.c.run_id,
                ranked.c.schedule_id,
                ranked.c.started_at,
                ranked.c.sent_count,
            ).where(ranked.c.rn == 1, ranked.c.unverified_count > 0)
        )
    ).all()
    if not failing_runs:
        return []

    # All unconfirmed SENT targets across every failing run, in ONE query.
    targets_by_run: dict[Any, list[WolRunTarget]] = {}
    all_targets = (
        (
            await db.execute(
                select(WolRunTarget).where(
                    WolRunTarget.run_id.in_([r.run_id for r in failing_runs]),
                    WolRunTarget.sent.is_(True),
                    WolRunTarget.verified.is_not(True),
                )
            )
        )
        .scalars()
        .all()
    )
    for t in all_targets:
        targets_by_run.setdefault(t.run_id, []).append(t)

    matches: list[tuple[str, str, str]] = []
    for run in failing_runs:
        unconfirmed = targets_by_run.get(run.run_id, [])
        if not unconfirmed:
            continue
        # The seen re-check is per-run (each run's wake instant is its own
        # anchor), but only for the handful of runs that actually failed.
        seen = await seen_since(
            db,
            [t.ip_address_id for t in unconfirmed if t.ip_address_id is not None],
            run.started_at,
        )
        still_down = [
            t for t in unconfirmed if t.ip_address_id is None or t.ip_address_id not in seen
        ]
        if not still_down:
            continue  # every straggler has since been observed — auto-resolve

        sched = by_id[run.schedule_id]
        sample = ", ".join(
            t.address or "(no address)" for t in still_down[:_WOL_WAKE_FAILED_SAMPLE]
        )
        more = len(still_down) - _WOL_WAKE_FAILED_SAMPLE
        if more > 0:
            sample += f" (+{more} more)"
        message = (
            f"{len(still_down)} of {run.sent_count} host(s) sent a magic packet by "
            f"'{sched.name}' did not come up, and are still not visible on the "
            f"network. Re-woken up to {sched.verify_retries} time(s), verified via "
            f"'{sched.verify_method}'. Hosts: {sample}. Resolves automatically once "
            f"they are seen, or after a clean run."
        )
        matches.append((str(sched.id), sched.name, message))
    return matches


async def _matching_new_mac_seen_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """ip_mac_history rows classified ``new`` + first seen within the recency
    window (issue #459) — a MAC never seen before, not allowlisted, not on the
    known fleet. One event per ``(ip, mac)`` pair so two MACs on one IP both
    surface. Auto-resolves once acknowledged / allowlisted (reclassified) or the
    sighting ages out of the window.

    Locally-administered (randomised) MACs are excluded unless the rule's
    ``classification`` is ``"all"`` — modern phones rotate them per network and
    would otherwise storm the operator on every reconnect.
    """
    days = rule.threshold_days if rule.threshold_days is not None else _NEW_MAC_SEEN_RECENCY_DAYS
    cutoff = datetime.now(UTC) - timedelta(days=max(1, days))
    include_randomized = (rule.classification or "").lower() == "all"
    conds = [
        IpMacHistory.classification == "new",
        IpMacHistory.first_seen >= cutoff,
    ]
    if not include_randomized:
        conds.append(IpMacHistory.is_randomized.is_(False))
    rows = (
        await db.execute(
            select(
                IPAddress, IpMacHistory.mac_address, IpMacHistory.first_seen, IpMacHistory.source
            )
            .join(IpMacHistory, IpMacHistory.ip_address_id == IPAddress.id)
            .where(*conds)
            .order_by(IpMacHistory.first_seen.desc())
            .limit(_IP_HYGIENE_MAX_EVENTS)
        )
    ).all()
    matches: list[tuple[str, str, str]] = []
    for ip_row, obs_mac, first_at, source in rows:
        subject_id = f"{ip_row.id}:{obs_mac}"
        display = f"{ip_row.address} ({obs_mac})"
        message = (
            f"New device: MAC {obs_mac} first seen on {ip_row.address} at "
            f"{first_at.isoformat()} (source: {source}). Not previously known, "
            f"allowlisted, or part of the allocated fleet — acknowledge, add to "
            f"the allowlist, or block it."
        )
        matches.append((subject_id, display, message))
    return matches


async def _dns_server_names(db: AsyncSession, server_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    """Resolve DNS server ids → display names in one query (issue #371)."""
    if not server_ids:
        return {}
    rows = (
        await db.execute(select(DNSServer.id, DNSServer.name).where(DNSServer.id.in_(server_ids)))
    ).all()
    return {row[0]: row[1] for row in rows}


async def _matching_dns_nxdomain_spike_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """DNS servers whose trailing-window NXDOMAIN ratio + count cross the rule
    thresholds (issue #371). Reads the per-server ``dns_metric_sample`` deltas
    the agents already report; no new collection.
    """
    ratio_threshold = (
        rule.threshold_percent
        if rule.threshold_percent is not None
        else _DNS_NXDOMAIN_RATIO_DEFAULT
    )
    min_count = (
        rule.min_free_addresses
        if rule.min_free_addresses is not None
        else _DNS_NXDOMAIN_MIN_COUNT_DEFAULT
    )
    since = datetime.now(UTC) - _DNS_ANOMALY_WINDOW
    rows = (
        await db.execute(
            select(
                DNSMetricSample.server_id,
                func.sum(DNSMetricSample.queries_total).label("q"),
                func.sum(DNSMetricSample.nxdomain).label("nx"),
            )
            .where(DNSMetricSample.bucket_at >= since)
            .group_by(DNSMetricSample.server_id)
        )
    ).all()
    if not rows:
        return []
    names = await _dns_server_names(db, [r.server_id for r in rows])
    win_min = int(_DNS_ANOMALY_WINDOW.total_seconds() // 60)
    matches: list[tuple[str, str, str]] = []
    for r in rows:
        q = int(r.q or 0)
        nx = int(r.nx or 0)
        if nx < min_count or q <= 0:
            continue
        ratio = nx / q * 100
        if ratio < ratio_threshold:
            continue
        name = names.get(r.server_id) or str(r.server_id)
        message = (
            f"DNS server {name} — {nx} NXDOMAIN responses ({ratio:.0f}% of {q} "
            f"queries) in the last {win_min} min (threshold {ratio_threshold}% / "
            f"floor {min_count}). Possible DGA beacon, broken client, or "
            f"mistyped-search-domain storm."
        )
        matches.append((str(r.server_id), name, message))
    return matches


async def _matching_dns_query_rate_spike_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """DNS servers whose trailing-window query total spikes vs the prior
    equal-length window (issue #371)."""
    pct = (
        rule.threshold_percent
        if rule.threshold_percent is not None
        else _DNS_QUERY_RATE_SPIKE_PCT_DEFAULT
    )
    floor = (
        rule.min_free_addresses
        if rule.min_free_addresses is not None
        else _DNS_QUERY_RATE_MIN_DEFAULT
    )
    now = datetime.now(UTC)
    cur_since = now - _DNS_ANOMALY_WINDOW
    prev_since = now - 2 * _DNS_ANOMALY_WINDOW

    async def _sums(lower: datetime, upper: datetime | None) -> dict[uuid.UUID, int]:
        stmt = select(
            DNSMetricSample.server_id,
            func.sum(DNSMetricSample.queries_total),
        ).where(DNSMetricSample.bucket_at >= lower)
        if upper is not None:
            stmt = stmt.where(DNSMetricSample.bucket_at < upper)
        stmt = stmt.group_by(DNSMetricSample.server_id)
        return {sid: int(q or 0) for sid, q in (await db.execute(stmt)).all()}

    cur = await _sums(cur_since, None)
    if not cur:
        return []
    prev = await _sums(prev_since, cur_since)
    names = await _dns_server_names(db, list(cur.keys()))
    win_min = int(_DNS_ANOMALY_WINDOW.total_seconds() // 60)
    matches: list[tuple[str, str, str]] = []
    for sid, q_cur in cur.items():
        if q_cur < floor:
            continue
        q_prev = prev.get(sid, 0)
        # A cold prior window: any current ≥ floor is a spike. Otherwise the
        # current window must exceed the prior by pct%.
        threshold_val = q_prev * (1 + pct / 100) if q_prev > 0 else float(floor)
        if q_cur < threshold_val:
            continue
        name = names.get(sid) or str(sid)
        if q_prev > 0:
            message = (
                f"DNS server {name} — query-rate spike: {q_cur} queries in the "
                f"last {win_min} min vs {q_prev} in the prior {win_min} min "
                f"(+{(q_cur / q_prev - 1) * 100:.0f}%, threshold +{pct}%)."
            )
        else:
            message = (
                f"DNS server {name} — {q_cur} queries in the last {win_min} min "
                f"from a cold prior window (floor {floor})."
            )
        matches.append((str(sid), name, message))
    return matches


async def _matching_dns_rate_limit_dropping_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """DNS servers whose Response Rate Limiting is actively shedding a flood
    (#146 Phase 3): RateDropped summed over the trailing window clears the
    floor. Open-while-true — auto-resolves when the flood subsides."""
    floor = (
        rule.min_free_addresses
        if rule.min_free_addresses is not None
        else _DNS_RATE_LIMIT_DROP_MIN_DEFAULT
    )
    since = datetime.now(UTC) - _DNS_ANOMALY_WINDOW
    stmt = (
        select(
            DNSMetricSample.server_id,
            func.sum(DNSMetricSample.rate_dropped).label("dropped"),
            func.sum(DNSMetricSample.rate_slipped).label("slipped"),
        )
        .where(DNSMetricSample.bucket_at >= since)
        .group_by(DNSMetricSample.server_id)
    )
    rows = (await db.execute(stmt)).all()
    hits = {sid: (int(d or 0), int(s or 0)) for sid, d, s in rows if int(d or 0) >= floor}
    if not hits:
        return []
    names = await _dns_server_names(db, list(hits.keys()))
    win_min = int(_DNS_ANOMALY_WINDOW.total_seconds() // 60)
    matches: list[tuple[str, str, str]] = []
    for sid, (dropped, slipped) in hits.items():
        name = names.get(sid) or str(sid)
        message = (
            f"DNS server {name} — Response Rate Limiting dropped {dropped} "
            f"responses in the last {win_min} min ({slipped} slipped/truncated); "
            f"the server is shedding a query flood (floor {floor}). Investigate a "
            "possible amplification attempt or misbehaving client."
        )
        matches.append((str(sid), name, message))
    return matches


async def _matching_dhcp_packets_dropped_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str]]:
    """DHCP servers the kernel dropped packets for over the window (#980).

    Fires on ``socket_drop`` alone: packets discarded because Kea's receive
    buffer was full, so Kea never read them. That is unambiguous loss nobody
    asked for, which is why a floor of one packet is reasonable.

    **``receive_drop`` is deliberately not part of the test**, though the
    message reports it when present. Kea's ``pkt4-receive-drop`` counts
    packets it read and discarded *on purpose* as well as by accident —
    verified against kea-dhcp4 3.0.3, a client matching a ``DROP``
    client-class increments it once per packet, and a ``DROP`` class is
    exactly what the shipped DHCP MAC blocklist renders. Kea's HA hook drops
    out-of-scope queries in ``hot-standby`` the same way. Counting it would
    make this rule fire permanently, and never auto-resolve, on two ordinary
    working configurations.

    NULL is not zero. A server whose agent predates #980, or cannot read
    ``/proc/net/udp``, reports no ``socket_drop`` at all; ``SUM`` over its
    rows is NULL and the server is skipped rather than treated as loss-free.
    Note this is tested on ``socket_drop`` specifically and not on the pair:
    ``receive_drop`` always arrives from a #980 agent, so a combined test
    would read an unmeasurable server as measured-and-clean.

    Open-while-true: auto-resolves once a window passes with no loss.
    """
    floor = (
        rule.min_free_addresses
        if rule.min_free_addresses is not None
        else _DHCP_PACKET_LOSS_MIN_DEFAULT
    )
    since = datetime.now(UTC) - _DHCP_PACKET_LOSS_WINDOW
    rows = (
        await db.execute(
            select(
                DHCPMetricSample.server_id,
                func.sum(DHCPMetricSample.socket_drop).label("sock"),
                func.sum(DHCPMetricSample.receive_drop).label("recv"),
                func.sum(DHCPMetricSample.discover).label("disc"),
            )
            .where(DHCPMetricSample.bucket_at >= since)
            .group_by(DHCPMetricSample.server_id)
        )
    ).all()
    if not rows:
        return []

    hits: dict[uuid.UUID, tuple[int, int | None, int]] = {}
    for r in rows:
        if r.sock is None:
            continue  # unmeasured — skipped, not vouched for
        sock = int(r.sock)
        if sock < floor or sock <= 0:
            continue
        hits[r.server_id] = (sock, None if r.recv is None else int(r.recv), int(r.disc or 0))
    if not hits:
        return []

    name_rows = (
        await db.execute(
            select(DHCPServer.id, DHCPServer.name).where(DHCPServer.id.in_(list(hits.keys())))
        )
    ).all()
    names: dict[uuid.UUID, str] = {row[0]: row[1] for row in name_rows}

    win_min = int(_DHCP_PACKET_LOSS_WINDOW.total_seconds() // 60)
    matches: list[tuple[str, str, str]] = []
    for sid, (sock, recv, disc) in hits.items():
        name = names.get(sid) or str(sid)
        message = (
            f"DHCP server {name} lost {sock} packet(s) in the last {win_min} min: "
            "the kernel discarded them because the server's receive buffer was "
            "full, so it never read them. Usually means the node is short of "
            f"CPU. It answered {disc} DISCOVER(s) over the same window, so every "
            "server-side counter reads healthy — the loss is upstream of them and "
            "costs each affected client a full retransmit round."
        )
        if recv:
            # Reported, never alerted on: this number legitimately includes
            # MAC-blocklist and HA out-of-scope drops.
            message += (
                f" Separately, {recv} packet(s) were read and then discarded by "
                "Kea — that figure also counts deliberate drops (a blocklisted "
                "MAC, or an HA standby declining an out-of-scope query) and is "
                "not necessarily a fault."
            )
        matches.append((str(sid), name, message))
    return matches


async def _matching_asn_drift_subjects(
    db: AsyncSession, rule: AlertRule  # noqa: ARG001 — symmetry with sibling evaluators
) -> list[tuple[str, str, str]]:
    """Every ``asn`` row currently in ``whois_state="drift"``."""
    res = await db.execute(select(ASN).where(ASN.whois_state == "drift"))
    matches: list[tuple[str, str, str]] = []
    for row in res.scalars().all():
        display = f"AS{row.number}" + (f" ({row.name})" if row.name else "")
        new_holder = row.holder_org or "<unknown>"
        message = f"AS{row.number} WHOIS holder changed — current holder: {new_holder}"
        matches.append((str(row.id), display, message))
    return matches


async def _matching_asn_unreachable_subjects(
    db: AsyncSession, rule: AlertRule  # noqa: ARG001
) -> list[tuple[str, str, str]]:
    """Every ``asn`` row whose ``whois_data.consecutive_failures`` has
    crossed the threshold and is currently in ``whois_state="unreachable"``.

    ``consecutive_failures`` lives inside the JSONB ``whois_data`` blob
    (the refresh task increments it on every failed RDAP fetch and
    resets it on success). Reading it via ORM gives us the live value
    without a JSONB query expression.
    """
    res = await db.execute(select(ASN).where(ASN.whois_state == "unreachable"))
    matches: list[tuple[str, str, str]] = []
    for row in res.scalars().all():
        data = row.whois_data if isinstance(row.whois_data, dict) else {}
        try:
            failures = int(data.get("consecutive_failures") or 0)
        except (TypeError, ValueError):
            failures = 0
        if failures < _ASN_WHOIS_UNREACHABLE_THRESHOLD:
            continue
        display = f"AS{row.number}" + (f" ({row.name})" if row.name else "")
        message = f"AS{row.number} WHOIS unreachable — {failures} consecutive RDAP fetch failures"
        matches.append((str(row.id), display, message))
    return matches


async def _matching_rpki_roa_expiring_subjects(
    db: AsyncSession, rule: AlertRule  # noqa: ARG001
) -> list[tuple[str, str, str]]:
    """Every ROA in ``state="expiring_soon"``.

    The refresh task derives the state ladder; the alert evaluator
    just reads it. Severity is operator-chosen on the rule itself —
    soft / warning / critical for <30d / <7d / <24h respectively;
    operators create N rules with different severities + filters
    when they want graduated alerting.
    """
    res = await db.execute(select(ASNRpkiRoa).where(ASNRpkiRoa.state == "expiring_soon"))
    matches: list[tuple[str, str, str]] = []
    now = datetime.now(UTC)
    for roa in res.scalars().all():
        # Resolve the parent AS for a human-friendly display string.
        parent = await db.get(ASN, roa.asn_id)
        parent_label = f"AS{parent.number}" if parent is not None else "AS?"
        display = f"{parent_label} {roa.prefix}-{roa.max_length}"
        when = ""
        if roa.valid_to is not None:
            delta = roa.valid_to - now
            days = max(0, delta.days)
            when = f" — expires in {days}d"
        message = (
            f"RPKI ROA {parent_label} {roa.prefix} maxLen {roa.max_length} "
            f"({roa.trust_anchor}) is expiring soon{when}"
        )
        matches.append((str(roa.id), display, message))
    return matches


async def _matching_rpki_roa_expired_subjects(
    db: AsyncSession, rule: AlertRule  # noqa: ARG001
) -> list[tuple[str, str, str]]:
    """Every ROA in ``state="expired"``."""
    res = await db.execute(select(ASNRpkiRoa).where(ASNRpkiRoa.state == "expired"))
    matches: list[tuple[str, str, str]] = []
    for roa in res.scalars().all():
        parent = await db.get(ASN, roa.asn_id)
        parent_label = f"AS{parent.number}" if parent is not None else "AS?"
        display = f"{parent_label} {roa.prefix}-{roa.max_length}"
        message = (
            f"RPKI ROA {parent_label} {roa.prefix} maxLen {roa.max_length} "
            f"({roa.trust_anchor}) has expired"
        )
        matches.append((str(roa.id), display, message))
    return matches


async def _matching_bgp_hijack_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001 — symmetry with sibling evaluators
    detection_kind: str,
) -> list[tuple[str, str, str, str | None]]:
    """Every active ``bgp_hijack_detection`` of ``detection_kind``.

    "Active" = ``resolved_at IS NULL`` (announcement still observed and
    within the delist window) AND ``acknowledged = False`` (operator
    hasn't muted it). The detection table is the latch; the poll task
    resolves rows on delist so the standard evaluator auto-resolves the
    ``AlertEvent`` when the subject stops matching.

    Per-detection severity (``critical`` for RPKI-invalid, ``warning``
    for RPKI-unknown) rides through as the tuple's severity override.
    """
    res = await db.execute(
        select(BGPHijackDetection).where(
            BGPHijackDetection.detection_kind == detection_kind,
            BGPHijackDetection.resolved_at.is_(None),
            BGPHijackDetection.acknowledged.is_(False),
        )
    )
    matches: list[tuple[str, str, str, str | None]] = []
    for row in res.scalars().all():
        kind_label = (
            "announcing" if detection_kind == "prefix_hijack" else "announcing more-specific"
        )
        display = f"{row.observed_prefix} ← AS{row.observed_origin_asn}"
        message = (
            f"BGP hijack: AS{row.observed_origin_asn} is {kind_label} "
            f"{row.observed_prefix} (tracked prefix {row.tracked_prefix}, "
            f"expected origin AS{row.expected_origin_asn}) — "
            f"RPKI {row.rpki_status}"
        )
        matches.append((str(row.id), display, message, row.severity))
    return matches


async def _matching_bgp_lg_session_down_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001 — symmetry with sibling evaluators
    now: datetime,
) -> list[tuple[str, str, str]]:
    """``bgp_lg_session_down`` — an enabled peer whose session is not
    Established, sustained past a grace window.

    Grace is anchored on ``BGPLGPeer.down_since``, a watermark THIS
    function stamps on first non-established observation and clears the
    moment the session re-establishes — mirrors
    ``_matching_firewall_apply_stalled_subjects``'s ``stalled_since``
    pattern exactly. A converged session auto-resolves via
    ``evaluate_all``'s standard "subject no longer matches" diff; no
    explicit resolve logic needed here.
    """
    rows = (
        await db.execute(
            select(BGPLGPeer, LookingGlassCollector)
            .join(LookingGlassCollector, LookingGlassCollector.id == BGPLGPeer.collector_id)
            .where(BGPLGPeer.enabled.is_(True))
        )
    ).all()

    matches: list[tuple[str, str, str]] = []
    for peer, collector in rows:
        if peer.session_state == "established":
            if peer.down_since is not None:
                peer.down_since = None
            continue
        if peer.down_since is None:
            peer.down_since = now  # first observation — start the grace clock
            continue
        if (now - peer.down_since) <= _BGP_LG_SESSION_DOWN_GRACE:
            continue
        collector_note = (
            f"collector '{collector.name}' is also reporting {collector.status}"
            if collector.status != "active"
            else f"collector '{collector.name}' is reporting normally"
        )
        display = f"{peer.name} (AS{peer.peer_asn} @ {peer.peer_address})"
        message = (
            f"BGP Looking Glass session '{peer.name}' to AS{peer.peer_asn} "
            f"({peer.peer_address}) has been {peer.session_state} since "
            f"{peer.down_since.isoformat()} — last known {peer.prefixes_received} "
            f"prefixes received; {collector_note}."
        )
        matches.append((str(peer.id), display, message))
    return matches


async def _matching_bgp_lg_rpki_invalid_route_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001
) -> list[tuple[str, str, str, str | None]]:
    """``bgp_lg_rpki_invalid_route`` — every active learned route whose
    RPKI status is ``invalid`` (computed at ingest via
    ``derive_rpki_status_batch``, no re-validation needed here). Always
    rides in at ``critical`` severity via a severity override — RPKI
    invalidity on YOUR OWN table is the strongest possible in-network
    leak/misconfig signal (mirrors ``severity_for_rpki``'s "invalid ⇒
    critical" mapping from the #527 hijack monitor)."""
    rows = (
        await db.execute(
            select(BGPLGRoute, BGPLGPeer)
            .join(BGPLGPeer, BGPLGPeer.id == BGPLGRoute.peer_id)
            .where(BGPLGRoute.rpki_status == RPKI_INVALID, BGPLGRoute.withdrawn_at.is_(None))
            .limit(_BGP_LG_MAX_EVENTS)
        )
    ).all()
    matches: list[tuple[str, str, str, str | None]] = []
    for route, peer in rows:
        display = f"{route.prefix} ← AS{route.origin_asn}"
        message = (
            f"RPKI-invalid route in the Looking Glass RIB: {route.prefix} originated by "
            f"AS{route.origin_asn}, learned from peer '{peer.name}' (AS{peer.peer_asn}) — "
            f"no covering ROA authorises this origin/length."
        )
        matches.append((str(route.id), display, message, severity_for_rpki(RPKI_INVALID)))
    if len(rows) >= _BGP_LG_MAX_EVENTS:
        logger.warning("bgp_lg_rpki_invalid_route_truncated", cap=_BGP_LG_MAX_EVENTS)
    return matches


async def _matching_bgp_lg_unexpected_origin_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001
) -> list[tuple[str, str, str]]:
    """``bgp_lg_unexpected_origin`` — an owned tracked prefix (exact
    CIDR match against ``BGPTrackedPrefix``) learned in the live RIB
    with an origin ASN outside ``expected_origin_set(tracked)``. Same
    "internal hijack / fat-fingered redistribute / route leak" shape as
    #527's exact-prefix detector, reading the internal RIB instead of
    RIPEstat."""
    rows = (
        await db.execute(
            select(BGPLGRoute, BGPTrackedPrefix, BGPLGPeer)
            .join(BGPTrackedPrefix, BGPTrackedPrefix.prefix == BGPLGRoute.prefix)
            .join(BGPLGPeer, BGPLGPeer.id == BGPLGRoute.peer_id)
            .where(
                BGPTrackedPrefix.enabled.is_(True),
                BGPLGRoute.withdrawn_at.is_(None),
                BGPLGRoute.origin_asn.is_not(None),
            )
            .limit(_BGP_LG_MAX_EVENTS)
        )
    ).all()
    matches: list[tuple[str, str, str]] = []
    for route, tracked, peer in rows:
        if route.origin_asn in expected_origin_set(tracked):
            continue
        display = (
            f"{route.prefix} ← AS{route.origin_asn} (expected AS{tracked.expected_origin_asn})"
        )
        message = (
            f"Tracked prefix {tracked.prefix} is learned with unexpected origin "
            f"AS{route.origin_asn} (expected AS{tracked.expected_origin_asn}) via peer "
            f"'{peer.name}' — possible internal leak or misconfigured redistribution."
        )
        matches.append((str(route.id), display, message))
    return matches


async def _matching_bgp_lg_more_specific_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001
) -> list[tuple[str, str, str]]:
    """``bgp_lg_more_specific`` — a route STRICTLY more specific
    (Postgres ``<<``, contained-and-not-equal) than an owned tracked
    aggregate, with an unexpected origin. The classic internal
    sub-prefix leak that wins BGP best-path over your aggregate via
    longest-match. Same origin-allowlist semantics as
    ``_matching_bgp_lg_unexpected_origin_subjects`` — only the
    containment operator differs (exact ``==`` there, strict ``<<``
    here)."""
    rows = (
        await db.execute(
            select(BGPLGRoute, BGPTrackedPrefix, BGPLGPeer)
            .join(BGPTrackedPrefix, BGPLGRoute.prefix.op("<<")(BGPTrackedPrefix.prefix))
            .join(BGPLGPeer, BGPLGPeer.id == BGPLGRoute.peer_id)
            .where(
                BGPTrackedPrefix.enabled.is_(True),
                BGPLGRoute.withdrawn_at.is_(None),
                BGPLGRoute.origin_asn.is_not(None),
            )
            .limit(_BGP_LG_MAX_EVENTS)
        )
    ).all()
    matches: list[tuple[str, str, str]] = []
    for route, tracked, peer in rows:
        if route.origin_asn in expected_origin_set(tracked):
            continue
        display = f"{route.prefix} (more-specific of {tracked.prefix}) ← AS{route.origin_asn}"
        message = (
            f"More-specific {route.prefix} of owned aggregate {tracked.prefix} learned with "
            f"unexpected origin AS{route.origin_asn} (expected AS{tracked.expected_origin_asn}) "
            f"via peer '{peer.name}' — this sub-prefix wins best-path over your aggregate."
        )
        matches.append((str(route.id), display, message))
    return matches


async def _matching_bgp_lg_route_flap_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str]]:
    """``bgp_lg_route_flap`` — an active route whose lifetime flap count
    (``BGPLGRoute.flap_count``, bumped once per absence-withdraw in
    ``routes_ingest.py``) has crossed ``rule.threshold_percent`` (reused
    as a raw flap-count floor — same int-as-count convention as
    ``voice_lease_count_below`` / ``stale_ip_count``), AND the most
    recent flap (``last_flap_at``) is within the trailing
    ``_BGP_LG_FLAP_WINDOW``. The recency gate is what makes this a
    "currently unstable" predicate rather than a permanent scar —
    once no new flap lands for the window, the route drops out of the
    match set and the AlertEvent auto-resolves via the standard diff.
    """
    threshold = rule.threshold_percent or _BGP_LG_FLAP_COUNT_DEFAULT
    since = now - _BGP_LG_FLAP_WINDOW
    rows = (
        await db.execute(
            select(BGPLGRoute, BGPLGPeer)
            .join(BGPLGPeer, BGPLGPeer.id == BGPLGRoute.peer_id)
            .where(
                BGPLGRoute.flap_count >= threshold,
                BGPLGRoute.last_flap_at.is_not(None),
                BGPLGRoute.last_flap_at >= since,
            )
            .limit(_BGP_LG_MAX_EVENTS)
        )
    ).all()
    matches: list[tuple[str, str, str]] = []
    win_min = int(_BGP_LG_FLAP_WINDOW.total_seconds() // 60)
    for route, peer in rows:
        display = f"{route.prefix} via {peer.name}"
        message = (
            f"Route {route.prefix} via peer '{peer.name}' (AS{peer.peer_asn}) has flapped "
            f"{route.flap_count} times, most recently {route.last_flap_at.isoformat()} "
            f"(threshold {threshold} within the trailing ~{win_min} min) — unstable path."
        )
        matches.append((str(route.id), display, message))
    return matches


async def _matching_bgp_lg_missing_advertisement_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001
) -> list[tuple[str, str, str]]:
    """``bgp_lg_missing_advertisement`` — a subnet flagged
    ``bgp_should_advertise`` with NO active learned route covering it
    (Postgres ``>>=``, contains-or-equal) across ANY peer.

    Deliberately does NOT wait on Phase 3's ``matched_subnet_id``
    resolution — that FK is populated by a longest-prefix-match
    reconcile that may not exist yet. This does the CIDR containment
    check directly against ``BGPLGRoute.prefix`` so the alert works
    whether or not Phase 3 has landed. ``Subnet``'s global soft-delete
    query filter (``app.db._filter_soft_deleted``) already excludes
    trashed subnets — no explicit ``deleted_at`` predicate needed.
    """
    covering_exists = (
        select(BGPLGRoute.id)
        .where(BGPLGRoute.withdrawn_at.is_(None), BGPLGRoute.prefix.op(">>=")(Subnet.network))
        .correlate(Subnet)
        .exists()
    )
    rows = (
        (
            await db.execute(
                select(Subnet)
                .where(Subnet.bgp_should_advertise.is_(True), ~covering_exists)
                .limit(_BGP_LG_MAX_EVENTS)
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[str, str, str]] = []
    for subnet in rows:
        display = f"{subnet.network} ({subnet.name})" if subnet.name else str(subnet.network)
        message = (
            f"Subnet {subnet.network} is flagged 'should advertise via BGP' but no active "
            f"Looking Glass peer is currently learning a covering route — check redistribution "
            f"on your edge routers."
        )
        matches.append((str(subnet.id), display, message))
    return matches


# Suppress the unused-import warning for ``timedelta`` when this module
# is read in isolation — used in expiring-soon message rendering.
_ = timedelta


async def _matching_server_subjects(
    db: AsyncSession, rule: AlertRule
) -> list[tuple[str, str, str]]:
    """Return matches for a server_unreachable rule."""
    server_type = rule.server_type or "any"
    matches: list[tuple[str, str, str]] = []

    if server_type in ("dns", "any"):
        res = await db.execute(
            select(DNSServer).where(
                or_(DNSServer.status == "unreachable", DNSServer.status == "error")
            )
        )
        for s in res.scalars().all():
            display = f"DNS {s.name}"
            message = f"DNS server {s.name} is {s.status}"
            matches.append((f"dns:{s.id}", display, message))

    if server_type in ("dhcp", "any"):
        res = await db.execute(
            select(DHCPServer).where(
                or_(DHCPServer.status == "unreachable", DHCPServer.status == "error")
            )
        )
        for s in res.scalars().all():
            display = f"DHCP {s.name}"
            message = f"DHCP server {s.name} is {s.status}"
            matches.append((f"dhcp:{s.id}", display, message))

    return matches


# ── Domain rule evaluators ──────────────────────────────────────────


_SEVERITY_ORDER = ("info", "warning", "critical")


def _severity_rank(severity: str) -> int:
    """Ordinal rank for an alert severity: ``info < warning < critical``.

    Unknown / unexpected values rank as ``warning`` (1) — same default
    the pre-existing escalation helper used. Shared by the expiring-rule
    escalation helper and the ``evaluate_all`` open-event loop so an
    already-open ``*_expiring`` event can be bumped up (never down) as
    its expiry date nears.
    """
    return {"info": 0, "warning": 1, "critical": 2}.get(severity, 1)


def _escalate_severity_for_expiring(
    base_severity: str,
    *,
    threshold_days: int,
    days_to_expiry: float,
) -> str:
    """For ``domain_expiring`` we widen the rule's base severity based
    on how close the actual expiry is — the issue spec calls for soft
    at threshold / warning at threshold/4 / critical at threshold/12.

    The base severity acts as a *floor*: a rule authored with
    ``severity="critical"`` always fires critical; a rule authored
    with ``severity="info"`` upgrades to warning / critical as the
    expiry window narrows. This way operators get one rule per
    domain (or zero — defaults to warning at threshold/4), not three.
    """

    base_rank = _severity_rank(base_severity)
    actual_rank = 0  # info at the soft threshold

    # Avoid division blowups for absurdly small thresholds. Floor of 1.
    safe = max(1, threshold_days)
    if days_to_expiry <= safe / 12:
        actual_rank = 2  # critical
    elif days_to_expiry <= safe / 4:
        actual_rank = 1  # warning

    final = max(base_rank, actual_rank)
    return _SEVERITY_ORDER[final]


async def _matching_domain_expiring_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for the
    ``domain_expiring`` rule type. Severity escalates per the
    threshold/4 / threshold/12 boundaries.
    """
    threshold_days = rule.threshold_days or _DEFAULT_EXPIRING_THRESHOLD_DAYS
    cutoff = now + timedelta(days=threshold_days)

    rows = (
        (
            await db.execute(
                select(Domain)
                .where(Domain.expires_at.is_not(None))
                .where(Domain.expires_at <= cutoff)
            )
        )
        .scalars()
        .all()
    )

    matches: list[tuple[str, str, str, str]] = []
    for d in rows:
        # Defensive coerce — Postgres returns timezone-aware, but
        # tests may construct naive datetimes.
        exp = d.expires_at
        if exp is None:
            continue
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        delta = exp - now
        days_to_expiry = delta.total_seconds() / 86400.0

        sev = _escalate_severity_for_expiring(
            rule.severity,
            threshold_days=threshold_days,
            days_to_expiry=days_to_expiry,
        )

        if days_to_expiry <= 0:
            descriptor = "expired"
        elif days_to_expiry < 1:
            descriptor = "expires within 24 h"
        else:
            descriptor = f"expires in {int(days_to_expiry)} day(s)"

        message = (
            f"Domain {d.name} {descriptor} (expires_at "
            f"{exp.isoformat()}, threshold {threshold_days} d)"
        )
        matches.append((str(d.id), d.name, message, sev))
    return matches


async def _matching_tls_cert_expiring_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """``tls_cert_expiring`` — escalating-expiry rule over the latest-known
    ``not_after`` per enabled target (same severity ramp as domain_expiring).
    Auto-resolves via the generic loop once the cert is renewed past the
    cutoff (not_after moves out → no longer returned)."""
    threshold_days = rule.threshold_days or _DEFAULT_EXPIRING_THRESHOLD_DAYS
    cutoff = now + timedelta(days=threshold_days)
    rows = (
        (
            await db.execute(
                select(TLSCertTarget).where(
                    TLSCertTarget.enabled.is_(True),
                    TLSCertTarget.not_after.is_not(None),
                    TLSCertTarget.not_after <= cutoff,
                    # NOTE: intentionally NOT excluding unreachable here — a
                    # cert's expiry is a fact from the last good probe, so a
                    # briefly-unreachable endpoint near expiry should keep the
                    # expiring event OPEN (excluding it makes the generic loop
                    # resolve→reopen → notification flap on a flapping host).
                    # The unreachable rule co-fires to signal the data is stale.
                )
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[str, str, str, str]] = []
    for t in rows:
        exp = t.not_after
        if exp is None:
            continue
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        days_to_expiry = (exp - now).total_seconds() / 86400.0
        sev = _escalate_severity_for_expiring(
            rule.severity,
            threshold_days=threshold_days,
            days_to_expiry=days_to_expiry,
        )
        if days_to_expiry <= 0:
            descriptor = "expired"
        elif days_to_expiry < 1:
            descriptor = "expires within 24 h"
        else:
            descriptor = f"expires in {int(days_to_expiry)} day(s)"
        label = t.display_name or t.host
        message = (
            f"TLS cert for {label} {descriptor} (not_after "
            f"{exp.isoformat()}, threshold {threshold_days} d)"
        )
        matches.append((str(t.id), label, message, sev))
    return matches


async def _matching_tls_cert_chain_invalid_subjects(
    db: AsyncSession, rule: AlertRule
) -> list[tuple[str, str, str]]:
    """``tls_cert_chain_invalid`` — fires for a reachable, unexpired cert
    that isn't usable: an untrusted chain (self-signed / wrong CA / broken
    chain → ``chain_valid IS FALSE``) OR a trusted chain served on the wrong
    hostname (SAN/CN mismatch → ``chain_valid IS TRUE`` but the probed name
    isn't covered). ``derive_tls_state`` buckets BOTH as ``STATE_MISMATCH``
    (expiry + unreachable take precedence in that ordering), so keying on the
    state covers the hostname-mismatch case the rule advertises without
    double-paging an expired or down cert (owned by the expiring /
    unreachable rules). Auto-resolves once a probe validates + name-matches."""
    rows = (
        (
            await db.execute(
                select(TLSCertTarget).where(
                    TLSCertTarget.enabled.is_(True),
                    TLSCertTarget.state == STATE_MISMATCH,
                )
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[str, str, str]] = []
    for t in rows:
        label = t.display_name or t.host
        if t.chain_valid is False:
            detail = t.chain_error or "certificate chain did not validate"
        else:
            # Trusted chain, wrong name — the SAN-drift case the module advertises.
            detail = "certificate served does not match the expected hostname (SAN mismatch)"
        message = f"TLS cert for {label} invalid: {detail}"
        matches.append((str(t.id), label, message))
    return matches


async def _matching_tls_cert_unreachable_subjects(
    db: AsyncSession, rule: AlertRule
) -> list[tuple[str, str, str]]:
    """``tls_cert_unreachable`` — fires while the endpoint can't be probed,
    gated on a couple of consecutive failures so a single transient blip
    doesn't page. Auto-resolves on the next successful probe."""
    rows = (
        (
            await db.execute(
                select(TLSCertTarget).where(
                    TLSCertTarget.enabled.is_(True),
                    TLSCertTarget.state == STATE_UNREACHABLE,
                    TLSCertTarget.consecutive_failures >= _TLS_CERT_UNREACHABLE_MIN_FAILURES,
                )
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[str, str, str]] = []
    for t in rows:
        label = t.display_name or t.host
        message = (
            f"TLS endpoint {label} unreachable "
            f"({t.consecutive_failures} consecutive failures): "
            f"{t.last_error or 'probe failed'}"
        )
        matches.append((str(t.id), label, message))
    return matches


async def _evaluate_tls_cert_transition_rule(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
    *,
    value_attr: str = "fingerprint_sha256",
    what: str = "fingerprint",
) -> tuple[int, int, int, int, int]:
    """Transition-once rule over a per-target cert attribute, modelled on
    :func:`_evaluate_domain_transition_rule`. ``value_attr`` selects the
    watched column:

    * ``fingerprint_sha256`` (``tls_cert_changed``) — any cert swap;
      legitimate on renewal, suspicious otherwise.
    * ``issuer_cn`` (``tls_cert_issuer_changed``) — the issuing CA changed,
      i.e. cert-rotation *deviation* (a normally-ACME cert coming back from a
      different issuer). Higher-signal than a plain fingerprint change.

    First sighting records a silent baseline; open events auto-resolve after
    ``_TRANSITION_AUTO_RESOLVE_DAYS``."""
    targets = await audit_forward._load_targets()  # noqa: SLF001

    opened = resolved = delivered_syslog = delivered_webhook = delivered_smtp = 0

    open_res = await db.execute(
        select(AlertEvent).where(
            AlertEvent.rule_id == rule.id,
            AlertEvent.resolved_at.is_(None),
        )
    )
    open_events = list(open_res.scalars().all())
    open_by_subject: dict[str, AlertEvent] = {ev.subject_id: ev for ev in open_events}

    cutoff = now - timedelta(days=_TRANSITION_AUTO_RESOLVE_DAYS)
    for ev in list(open_events):
        if ev.fired_at < cutoff:
            ev.resolved_at = now
            resolved += 1
            del open_by_subject[ev.subject_id]

    last_event_res = await db.execute(
        select(AlertEvent).where(AlertEvent.rule_id == rule.id).order_by(AlertEvent.fired_at.desc())
    )
    last_event_by_subject: dict[str, AlertEvent] = {}
    for ev in last_event_res.scalars().all():
        last_event_by_subject.setdefault(ev.subject_id, ev)

    rows = (
        (await db.execute(select(TLSCertTarget).where(TLSCertTarget.enabled.is_(True))))
        .scalars()
        .all()
    )
    for t in rows:
        subject_id = str(t.id)
        current_value = getattr(t, value_attr)
        if open_by_subject.get(subject_id) is not None:
            continue

        prior_event = last_event_by_subject.get(subject_id)
        if prior_event is not None and isinstance(prior_event.last_observed_value, dict):
            prior_value = prior_event.last_observed_value.get("to")
        else:
            prior_value = None

        label = t.display_name or t.host
        if prior_event is None:
            if current_value is None:
                continue
            db.add(
                AlertEvent(
                    rule_id=rule.id,
                    subject_type="tls_cert",
                    subject_id=subject_id,
                    subject_display=label,
                    severity="info",
                    message=f"Initial TLS cert {what} baseline for {label}: {current_value}",
                    fired_at=now,
                    resolved_at=now,
                    last_observed_value={"from": None, "to": current_value},
                )
            )
            continue

        if current_value is None or current_value == prior_value:
            continue

        message = f"TLS cert {what} for {label} changed: {prior_value} → {current_value}"
        event = AlertEvent(
            rule_id=rule.id,
            subject_type="tls_cert",
            subject_id=subject_id,
            subject_display=label,
            severity=rule.severity,
            message=message,
            fired_at=now,
            last_observed_value={"from": prior_value, "to": current_value},
        )
        db.add(event)
        await db.flush()
        ds, dw, dm = await _deliver(rule, event, targets)
        event.delivered_syslog = ds
        event.delivered_webhook = dw
        event.delivered_smtp = dm
        opened += 1
        if ds:
            delivered_syslog += 1
        if dw:
            delivered_webhook += 1
        if dm:
            delivered_smtp += 1

    return opened, resolved, delivered_syslog, delivered_webhook, delivered_smtp


async def _matching_domain_drift_subjects(
    db: AsyncSession, rule: AlertRule
) -> list[tuple[str, str, str]]:
    """``domain_nameserver_drift`` — fires for every domain whose
    operator-set ``expected_nameservers`` doesn't match the
    last-observed ``actual_nameservers``."""
    rows = (
        (await db.execute(select(Domain).where(Domain.nameserver_drift.is_(True)))).scalars().all()
    )
    matches: list[tuple[str, str, str]] = []
    for d in rows:
        expected = sorted(d.expected_nameservers or [])
        actual = sorted(d.actual_nameservers or [])
        message = f"Domain {d.name} NS drift — " f"expected={expected!r}, actual={actual!r}"
        matches.append((str(d.id), d.name, message))
    return matches


async def _evaluate_domain_transition_rule(
    db: AsyncSession,
    rule: AlertRule,
    *,
    field_name: str,
    rule_label: str,
    now: datetime,
) -> tuple[int, int, int, int, int]:
    """Shared body for the two "fires once on transition" domain rules.

    Walks every Domain row, looks up the most recent open event for
    ``(rule, subject_id)``. When the current value of ``field_name``
    differs from the snapshot stored in that event's
    ``last_observed_value.to``, opens a new event with the snapshot
    ``{"from": <previous>, "to": <current>}``. Auto-resolves any open
    event older than ``_TRANSITION_AUTO_RESOLVE_DAYS`` days.

    Returns ``(opened, resolved, delivered_syslog, delivered_webhook,
    delivered_smtp)`` aligned with the main evaluator's accumulators.

    Note: this approach relies on each new transition's "from" being
    the previous "to", so re-firing on the same value-pair is
    suppressed by the existing-open-event check. A registrar that
    flips A→B→A within the auto-resolve window opens two events (the
    A→B transition, then B→A); that's the intended behaviour.
    """
    targets = await audit_forward._load_targets()  # noqa: SLF001

    opened = 0
    resolved = 0
    delivered_syslog = 0
    delivered_webhook = 0
    delivered_smtp = 0

    # Index existing OPEN events by subject_id so we can compare the
    # snapshot the last firing latched against the row's current value.
    open_res = await db.execute(
        select(AlertEvent).where(
            AlertEvent.rule_id == rule.id,
            AlertEvent.resolved_at.is_(None),
        )
    )
    open_events = list(open_res.scalars().all())
    open_by_subject: dict[str, AlertEvent] = {ev.subject_id: ev for ev in open_events}

    # Auto-resolve any open transition event whose age exceeds the
    # window. Time-bounding these is important — the alternative is a
    # UI cluttered with months-old "registrar changed" rows.
    cutoff = now - timedelta(days=_TRANSITION_AUTO_RESOLVE_DAYS)
    for ev in list(open_events):
        if ev.fired_at < cutoff:
            ev.resolved_at = now
            resolved += 1
            del open_by_subject[ev.subject_id]

    # We also need each domain's *previous* observed value (i.e. the
    # last "to" we latched into an event, regardless of whether that
    # event is still open). Without it the first transition after
    # rule-create has no "from" to record. Look up the most recent
    # event row per subject — open or resolved.
    last_event_res = await db.execute(
        select(AlertEvent).where(AlertEvent.rule_id == rule.id).order_by(AlertEvent.fired_at.desc())
    )
    last_event_by_subject: dict[str, AlertEvent] = {}
    for ev in last_event_res.scalars().all():
        if ev.subject_id not in last_event_by_subject:
            last_event_by_subject[ev.subject_id] = ev

    rows = (await db.execute(select(Domain))).scalars().all()
    for d in rows:
        subject_id = str(d.id)
        current_value = getattr(d, field_name)
        # Bool / nullable string both serialise into JSON cleanly.
        if open_by_subject.get(subject_id) is not None:
            # Already an open transition for this domain — wait it
            # out (will auto-resolve at the cutoff above).
            continue

        prior_event = last_event_by_subject.get(subject_id)
        if prior_event is not None and isinstance(prior_event.last_observed_value, dict):
            prior_value = prior_event.last_observed_value.get("to")
        else:
            prior_value = None

        # First-ever sighting (no prior event): record the "first
        # observation" silently — open + immediately resolve so we
        # have a baseline without paging the operator. Unset values
        # (registrar=NULL on a row that's never been refreshed) get
        # treated as "no observation yet" and skipped.
        if prior_event is None:
            if current_value is None:
                continue
            baseline = AlertEvent(
                rule_id=rule.id,
                subject_type="domain",
                subject_id=subject_id,
                subject_display=d.name,
                severity="info",
                message=f"Initial {rule_label} baseline for {d.name}: {current_value!r}",
                fired_at=now,
                resolved_at=now,
                last_observed_value={"from": None, "to": current_value},
            )
            db.add(baseline)
            continue

        if current_value == prior_value:
            continue

        # Real transition. Open a fresh event + deliver.
        message = f"Domain {d.name} {rule_label} changed: " f"{prior_value!r} → {current_value!r}"
        event = AlertEvent(
            rule_id=rule.id,
            subject_type="domain",
            subject_id=subject_id,
            subject_display=d.name,
            severity=rule.severity,
            message=message,
            fired_at=now,
            last_observed_value={"from": prior_value, "to": current_value},
        )
        db.add(event)
        await db.flush()  # populate event.id for delivery payload
        ds, dw, dm = await _deliver(rule, event, targets)
        event.delivered_syslog = ds
        event.delivered_webhook = dw
        event.delivered_smtp = dm
        opened += 1
        if ds:
            delivered_syslog += 1
        if dw:
            delivered_webhook += 1
        if dm:
            delivered_smtp += 1

    return opened, resolved, delivered_syslog, delivered_webhook, delivered_smtp


# ── Circuit rule evaluators ─────────────────────────────────────────


async def _matching_circuit_term_expiring_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for the
    ``circuit_term_expiring`` rule type. Mirrors ``domain_expiring`` —
    severity escalates per ``threshold/4`` / ``threshold/12`` so a
    single rule covers info / warning / critical without three
    separate rules.

    ``status='decom'`` rows are excluded — a decommissioned circuit
    expiring is not actionable. Soft-deleted rows are also excluded.
    """
    threshold_days = rule.threshold_days or _DEFAULT_EXPIRING_THRESHOLD_DAYS
    cutoff = (now + timedelta(days=threshold_days)).date()

    rows = (
        (
            await db.execute(
                select(Circuit)
                .where(Circuit.deleted_at.is_(None))
                .where(Circuit.status != "decom")
                .where(Circuit.term_end_date.is_not(None))
                .where(Circuit.term_end_date <= cutoff)
            )
        )
        .scalars()
        .all()
    )

    matches: list[tuple[str, str, str, str]] = []
    today = now.date()
    for c in rows:
        if c.term_end_date is None:
            continue
        days_to_expiry = (c.term_end_date - today).days
        sev = _escalate_severity_for_expiring(
            rule.severity,
            threshold_days=threshold_days,
            days_to_expiry=days_to_expiry,
        )
        if days_to_expiry <= 0:
            descriptor = "term has expired"
        elif days_to_expiry == 1:
            descriptor = "term expires tomorrow"
        else:
            descriptor = f"term expires in {days_to_expiry} day(s)"
        message = (
            f"Circuit {c.name} {descriptor} "
            f"(term_end_date {c.term_end_date.isoformat()}, threshold "
            f"{threshold_days} d)"
        )
        matches.append((str(c.id), c.name, message, sev))
    return matches


# ── Appliance k3s cert evaluator (#183 Phase 6) ────────────────────


async def _matching_k3s_api_cert_expiring_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for the
    ``k3s_api_cert_expiring`` rule type. Mirrors the
    ``circuit_term_expiring`` shape — severity escalates per
    ``threshold/4`` (warning) / ``threshold/12`` (critical) so one
    rule covers the 30 / 7-day expiry chain.

    Only matches appliances where the supervisor has reported
    ``k3s_api_cert_expires_at`` (k3s is the runtime). Soft-deleted
    rows are excluded — a revoked appliance's cert expiring is
    operator-actionable but not via this alert.
    """
    from app.models.appliance import Appliance  # noqa: PLC0415

    threshold_days = rule.threshold_days or _DEFAULT_EXPIRING_THRESHOLD_DAYS
    cutoff = now + timedelta(days=threshold_days)

    rows = (
        (
            await db.execute(
                select(Appliance)
                .where(Appliance.revoked_at.is_(None))
                .where(Appliance.k3s_api_cert_expires_at.is_not(None))
                .where(Appliance.k3s_api_cert_expires_at <= cutoff)
            )
        )
        .scalars()
        .all()
    )

    matches: list[tuple[str, str, str, str]] = []
    for a in rows:
        if a.k3s_api_cert_expires_at is None:
            continue
        delta = a.k3s_api_cert_expires_at - now
        days_to_expiry = delta.days
        sev = _escalate_severity_for_expiring(
            rule.severity,
            threshold_days=threshold_days,
            days_to_expiry=days_to_expiry,
        )
        if days_to_expiry <= 0:
            descriptor = "has expired"
        elif days_to_expiry == 1:
            descriptor = "expires tomorrow"
        else:
            descriptor = f"expires in {days_to_expiry} day(s)"
        message = (
            f"k3s API server cert on {a.hostname} {descriptor} "
            f"({a.k3s_api_cert_expires_at.isoformat()}, threshold "
            f"{threshold_days} d). k3s rotates this automatically; "
            f"a restart of k3s.service should pick up a refreshed cert."
        )
        matches.append((str(a.id), a.hostname, message, sev))
    return matches


async def _matching_secret_expiring_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for the
    ``secret_expiring`` rule type (#76). Scans every internal credential
    that carries an expiry and fires once per credential expiring within
    ``threshold_days``:

    * **Supervisor mTLS certs** (``appliance.cert_expires_at``) — the
      internal-CA-signed cert each appliance's supervisor presents on the
      agent-comms channel. (The k3s API-server cert has its own
      ``k3s_api_cert_expiring`` rule and is intentionally NOT duplicated.)
    * **API tokens** (``api_token.expires_at``) — active tokens with an
      expiry.

    ``subject_id`` is ``appliance_cert:<id>`` / ``api_token:<id>`` so each
    credential latches its own event; severity escalates per ``threshold/4``
    (warning) / ``threshold/12`` (critical). TSIG keys and ACME *accounts*
    carry no expiry of their own (their issued certs do — out of scope), so
    they contribute no subjects here.
    """
    from app.models.appliance import Appliance  # noqa: PLC0415
    from app.models.auth import APIToken  # noqa: PLC0415

    threshold_days = rule.threshold_days or _DEFAULT_EXPIRING_THRESHOLD_DAYS
    cutoff = now + timedelta(days=threshold_days)
    matches: list[tuple[str, str, str, str]] = []

    def _descriptor(days: int) -> str:
        if days <= 0:
            return "has expired"
        if days == 1:
            return "expires tomorrow"
        return f"expires in {days} day(s)"

    # 1. Supervisor mTLS certs (internal CA-signed; agent-comms channel).
    certs = (
        (
            await db.execute(
                select(Appliance)
                .where(Appliance.revoked_at.is_(None))
                .where(Appliance.cert_expires_at.is_not(None))
                .where(Appliance.cert_expires_at <= cutoff)
            )
        )
        .scalars()
        .all()
    )
    for a in certs:
        if a.cert_expires_at is None:
            continue
        days = (a.cert_expires_at - now).days
        sev = _escalate_severity_for_expiring(
            rule.severity, threshold_days=threshold_days, days_to_expiry=days
        )
        message = (
            f"Supervisor mTLS certificate for appliance {a.hostname} "
            f"{_descriptor(days)} ({a.cert_expires_at.isoformat()}, threshold "
            f"{threshold_days} d). Re-key it from the Fleet drilldown."
        )
        matches.append((f"appliance_cert:{a.id}", f"{a.hostname} supervisor cert", message, sev))

    # 2. API tokens with an expiry (active only).
    tokens = (
        (
            await db.execute(
                select(APIToken)
                .where(APIToken.is_active.is_(True))
                .where(APIToken.expires_at.is_not(None))
                .where(APIToken.expires_at <= cutoff)
            )
        )
        .scalars()
        .all()
    )
    for t in tokens:
        if t.expires_at is None:
            continue
        days = (t.expires_at - now).days
        sev = _escalate_severity_for_expiring(
            rule.severity, threshold_days=threshold_days, days_to_expiry=days
        )
        message = (
            f"API token '{t.name}' ({t.prefix}…) {_descriptor(days)} "
            f"({t.expires_at.isoformat()}, threshold {threshold_days} d). "
            f"Rotate it from Settings → API Tokens."
        )
        matches.append((f"api_token:{t.id}", f"{t.name} API token", message, sev))

    # 3. ACME-issued Web UI TLS certs (#438) — active letsencrypt certs
    #    nearing expiry. Distinct subject prefix from the supervisor cert
    #    so they latch independently. Phase-2 auto-renewal normally renews
    #    these well before this fires; an alert means renewal is stuck.
    from app.models.appliance import (  # noqa: PLC0415
        CERT_SOURCE_LETSENCRYPT,
        ApplianceCertificate,
    )

    web_certs = (
        (
            await db.execute(
                select(ApplianceCertificate)
                .where(ApplianceCertificate.source == CERT_SOURCE_LETSENCRYPT)
                .where(ApplianceCertificate.is_active.is_(True))
                .where(ApplianceCertificate.valid_to.is_not(None))
                .where(ApplianceCertificate.valid_to <= cutoff)
            )
        )
        .scalars()
        .all()
    )
    for c in web_certs:
        if c.valid_to is None:
            continue
        days = (c.valid_to - now).days
        sev = _escalate_severity_for_expiring(
            rule.severity, threshold_days=threshold_days, days_to_expiry=days
        )
        message = (
            f"Let's Encrypt Web UI certificate '{c.subject_cn or c.name}' "
            f"{_descriptor(days)} ({c.valid_to.isoformat()}, threshold "
            f"{threshold_days} d). Auto-renewal may be stuck — check "
            f"Appliance → Web UI Certificate."
        )
        matches.append(
            (f"appliance_cert_tls:{c.id}", f"{c.subject_cn or c.name} (LE)", message, sev)
        )

    return matches


async def _cluster_health_snapshot() -> dict[str, Any] | None:
    """The live cluster-health snapshot, or ``None`` off the appliance.

    Shared by the two rules that read it (``node_pressure`` and
    ``cluster_dns_degraded``) so they cannot disagree about what "unknown"
    means — the preamble was previously copied verbatim between them,
    including the message strings, so narrowing one bare ``except`` would
    have silently left the other wrong.

    **Deliberately NOT cached.** The review suggested memoizing this so
    the two rules share one gather per sweep, and a short-TTL module cache
    was tried — it broke ten ``node_pressure`` tests and, more to the
    point, it is wrong: a cache keyed on a clock answers the second rule
    with the first rule's snapshot, so a cluster that goes from healthy to
    unreadable inside the TTL keeps reporting healthy. Masking a health
    transition to save one kubeapi round trip per minute is a bad trade
    for an alerting path. The 60 s sweep can afford two gathers; the
    dashboard already does one every 2 s.

    Raises :class:`AlertDataUnavailable` when the cluster cannot be read —
    a kubeapi blip and a dead cluster look alike from here, and neither is
    evidence that a condition cleared, so returning ``[]`` would resolve
    every open event and re-open it a minute later.
    """
    import asyncio  # noqa: PLC0415

    from app.config import settings  # noqa: PLC0415

    if not settings.appliance_mode:
        return None

    from app.services.appliance import cluster_health  # noqa: PLC0415

    try:
        snap = await asyncio.to_thread(cluster_health.get_cluster_health)
    except Exception as exc:  # noqa: BLE001 - any read failure means "unknown"
        raise AlertDataUnavailable(f"cluster health unreadable: {exc}") from exc
    if not snap.get("available"):
        raise AlertDataUnavailable(f"cluster health unavailable: {snap.get('detail')}")
    return snap


async def _matching_cluster_dns_subjects(
    db: AsyncSession,  # noqa: ARG001
    rule: AlertRule,  # noqa: ARG001
) -> list[tuple[str, str, str, str | None]]:
    """``cluster_dns_degraded`` — CoreDNS down, thin, co-located, or not
    answering (#985).

    Reads the same ``get_cluster_health()`` snapshot the Cluster screen
    renders, so there is no new collector and no new permission. Running in
    the worker pod is a bonus rather than an accident: it gives the resolve
    probe a **second vantage**, since the dashboard's probe runs from
    whichever api replica served the request.

    ``None`` is never a match, in either direction. An unreadable snapshot,
    an unlistable ``kube-system``, or a cluster that labels its DNS
    differently all leave the counts unknown — and firing on unknown would
    alarm every BYO-chart install, while silently resolving on unknown would
    clear a real open event. So an unavailable block raises
    :class:`AlertDataUnavailable`, which leaves whatever was open standing.
    """
    snap = await _cluster_health_snapshot()
    if snap is None:
        return []

    cdns = snap.get("cluster_dns") or {}
    probe = cdns.get("resolve_probe") or {}
    probe_ran = bool(probe)
    probe_ok = probe.get("ok") is True

    if not cdns.get("available"):
        # The replica view is unknown. The probe may still have run — and if
        # it FAILED, that is a fact worth alerting on by itself, independent
        # of whether we could enumerate pods.
        if probe_ran and not probe_ok:
            return [
                (
                    "cluster",
                    "cluster DNS",
                    (
                        "Cluster DNS is not answering: "
                        f"{probe.get('error') or 'the resolve probe failed'}"
                        f"{_from_node_suffix(probe)}. Pods cannot resolve "
                        "*.svc.cluster.local, which breaks the api's route to Postgres "
                        "and Redis. Replica state could not be read "
                        f"({cdns.get('detail') or 'no detail'})."
                    ),
                    "critical",
                )
            ]
        raise AlertDataUnavailable(
            f"cluster DNS state unknown: {cdns.get('detail') or 'no detail'}"
        )

    ready = cdns.get("replicas_ready")
    expected = cdns.get("expected_replicas")
    spread_ok = cdns.get("spread_ok")
    nodes = cdns.get("nodes") or []

    reasons: list[str] = []
    severity: str | None = None

    if probe_ran and not probe_ok:
        reasons.append(
            f"the resolve probe failed ({probe.get('error') or 'no detail'})"
            f"{_from_node_suffix(probe)}"
        )
        severity = "critical"

    if ready == 0:
        reasons.append("no CoreDNS replica is ready")
        severity = "critical"
    elif ready is not None and expected is not None and ready < expected:
        reasons.append(f"{ready} of {expected} CoreDNS replicas ready")
        severity = severity or "warning"

    # ``len(nodes) < ready``, NOT ``len(set(nodes)) < len(nodes)``.
    #
    # The producer already emits ``sorted(set(ready_nodes))``, so the
    # deduplicated list can never contain duplicates and that test was
    # unsatisfiable — meaning #633's exact failure, the one arm of this
    # rule's WARNING severity, could never fire. The dashboard used a
    # different predicate and rendered amber, so the two surfaces
    # disagreed silently. Comparing distinct nodes against ready replicas
    # is the fact actually wanted, and it survives the dedup.
    if spread_ok is False and ready and ready > 1 and len(nodes) < ready:
        reasons.append(
            f"all {ready} ready replicas are on {len(nodes)} node"
            f"{'' if len(nodes) == 1 else 's'}"
            f" ({', '.join(nodes) if nodes else '?'}) — losing "
            f"{'it' if len(nodes) == 1 else 'one'} takes cluster DNS with it"
        )
        severity = severity or "warning"

    if not reasons:
        return []
    return [
        (
            "cluster",
            "cluster DNS",
            "Cluster DNS is degraded: "
            + "; ".join(reasons)
            + ". Every pod resolves *.svc.cluster.local through it, so this surfaces "
            "later as unrelated components failing to reach Postgres, Redis or the api.",
            severity,
        )
    ]


def _from_node_suffix(probe: dict[str, Any]) -> str:
    node = probe.get("from_node")
    return f" (probed from {node})" if node else ""


async def _matching_node_pressure_subjects(
    db: AsyncSession,  # noqa: ARG001
    rule: AlertRule,
) -> list[tuple[str, str, str, str | None]]:
    """``node_pressure`` — cluster nodes whose PSI shows sustained stalling.

    Reads the kubelet Summary API through the same ``get_cluster_health()``
    the Cluster screen uses, so there is no new collector and no new
    permission: whatever transport already works for the health panel works
    here (#983 Phase 2 item 6).

    NULL PSI is never a match. A kubelet older than 1.36 — or one with the
    feature off — reports nothing, and firing on that would alarm every node
    in the fleet on upgrade day while saying something false. It is the same
    rule the #882 matcher follows for an agent that has never reported.

    Runs in a worker thread: ``get_cluster_health`` is synchronous and does
    one HTTPS round trip per node, which would otherwise stall the event
    loop for the whole 60 s tick.
    """
    # Cluster health only exists on the appliance; everywhere else the
    # ServiceAccount is not mounted and every node would silently report no
    # PSI, so skip the round trip entirely.
    snap = await _cluster_health_snapshot()
    if snap is None:
        return []

    # ``is not None``, not ``or`` — the column is numeric and the form allows
    # 0, which ``or`` would silently rewrite to 50. Every other rule in this
    # file reads its threshold the same way. Note that 0 does mean what it
    # says: ``some >= 0`` matches every node that reports PSI at all, which is
    # a legitimate (if loud) way to ask "tell me about any stalling".
    threshold = float(rule.threshold_percent if rule.threshold_percent is not None else 50)
    matches: list[tuple[str, str, str, str | None]] = []
    for node in snap.get("nodes") or []:
        name = node.get("name")
        if not name:
            continue
        reasons: list[str] = []
        severity: str | None = None

        mem_full = _psi_avg300(node.get("psi_memory"), "full")
        if mem_full is not None and mem_full >= _NODE_PRESSURE_FULL_CRITICAL_PCT:
            reasons.append(
                f"memory full-stall {mem_full:.1f}% of the last 5 min "
                "(every runnable task blocked)"
            )
            severity = "critical"

        for label, key in (("CPU", "psi_cpu"), ("memory", "psi_memory")):
            some = _psi_avg300(node.get(key), "some")
            if some is not None and some >= threshold:
                reasons.append(
                    f"{label} stall {some:.1f}% of the last 5 min (threshold {threshold:.0f}%)"
                )
                severity = severity or "warning"

        if reasons:
            matches.append((str(name), str(name), "; ".join(reasons), severity))
    return matches


def _psi_avg300(psi: Any, kind: str) -> float | None:
    """``avg300`` for one ``some`` / ``full`` series, or None if unreported.

    None propagates all the way from the kubelet: it means the reading does
    not exist, which is a different fact from 0.0 (no pressure) and must not
    be compared against a threshold.
    """
    if not isinstance(psi, dict):
        return None
    series = psi.get(kind)
    if not isinstance(series, dict):
        return None
    val = series.get("avg300")
    # ``bool`` is an ``int`` subclass, so a JSON ``true`` would arrive as 1.0
    # and read as a real one-percent stall. Unreachable through the live path
    # today — ``cluster_health._parse_psi`` filters it first — but the two
    # functions parsing the same wire shape must not disagree about what
    # counts as a number, or a change to that filter turns into a phantom
    # alert here with nothing to point at.
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    return float(val)


async def _matching_agent_config_rejected_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001
) -> list[tuple[str, str, str, str | None]]:
    """``agent_config_rejected`` — every agent-managed server that reported a
    failed config apply on its last heartbeat (#882).

    Reads the ``config_apply_*`` columns the three heartbeat handlers write;
    no probing, no extra round-trip. Auto-resolves through ``evaluate_all``'s
    standard "subject no longer matches" diff the moment an agent reports
    ``ok`` again.

    NULL is deliberately not a match. It means the agent has never reported —
    a pre-#882 agent, or one of the agentless drivers (Windows DNS, the cloud
    DNS providers, ``technitium_api``) that has no apply loop at all. Firing
    on those would alarm every install on upgrade day and say nothing true.
    """
    from app.models.bgp_looking_glass import LookingGlassCollector  # noqa: PLC0415
    from app.models.dhcp import DHCPServer  # noqa: PLC0415
    from app.models.dns import DNSServer  # noqa: PLC0415
    from app.services.agents.config_apply import (  # noqa: PLC0415
        FAILED_STATUSES,
        SEVERITY_BY_STATUS,
        STATUS_NO_PREVIOUS,
        STATUS_REVERT_FAILED,
    )

    matches: list[tuple[str, str, str, str | None]] = []
    failed = sorted(FAILED_STATUSES)
    for model, kind in (
        (DNSServer, "DNS"),
        (DHCPServer, "DHCP"),
        (LookingGlassCollector, "Looking Glass collector"),
    ):
        rows = (
            (await db.execute(select(model).where(model.config_apply_status.in_(failed))))
            .scalars()
            .all()
        )
        for row in rows:
            status = row.config_apply_status or ""
            if status == STATUS_NO_PREVIOUS:
                what = (
                    "could not apply the configuration and had no previously-working "
                    "configuration to fall back to, so it may not be serving at all"
                )
            elif status == STATUS_REVERT_FAILED:
                what = (
                    "could not apply the configuration AND failed to roll back to the "
                    "previous one — its running state is unknown"
                )
            else:
                what = (
                    "rejected the configuration and rolled back to the last one that "
                    "worked, so it is healthy but NOT serving what is saved here"
                )
            detail = (row.config_apply_error or "").strip()
            message = (
                f"{kind} server '{row.name}' {what}. "
                f"Rejected config etag: {row.config_failed_etag or 'unknown'}."
                + (f" Daemon reported: {detail}" if detail else "")
            )
            subject_id = f"{model.__tablename__}:{row.id}"
            matches.append(
                (subject_id, f"{row.name} ({kind})", message, SEVERITY_BY_STATUS.get(status))
            )
    return matches


async def _matching_dhcp_scope_uncoordinated_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001
) -> list[tuple[str, str, str, str | None]]:
    """``dhcp_scope_uncoordinated`` — every scope the group failover report
    (#1110) marks ``uncoordinated``, in every group with a Windows member.

    ``unknown`` (a member's failover relationships could not be read) is
    deliberately not a match: it is a read failure the panel already shows,
    and paging on it would page on every denied read. Auto-resolves when the
    poll next reads the scope in a relationship, or on one server only.
    """
    from app.models.dhcp import DHCPServer, DHCPServerGroup  # noqa: PLC0415
    from app.services.dhcp.windows_failover_report import (  # noqa: PLC0415
        group_failover_report,
    )

    group_ids = (
        (
            await db.execute(
                select(DHCPServer.server_group_id)
                .where(
                    DHCPServer.driver == "windows_dhcp",
                    DHCPServer.server_group_id.is_not(None),
                )
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    matches: list[tuple[str, str, str, str | None]] = []
    for gid in group_ids:
        group = await db.get(DHCPServerGroup, gid)
        if group is None:
            continue
        report = await group_failover_report(db, group)
        for row in report["scopes"]:
            if row["verdict"] != "uncoordinated":
                continue
            matches.append(
                (
                    f"{group.id}:{row['cidr']}",
                    f"{row['cidr']} ({group.name})",
                    f"DHCP scope {row['cidr']} in server group '{group.name}': {row['detail']}",
                    "critical",
                )
            )
    return matches


async def _matching_firewall_apply_stalled_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for appliances
    whose control-plane-rendered firewall ruleset hasn't been applied by the
    host runner past the grace window (#285 Phase 2d).

    Gates hard on ``applied_status`` so it never false-fires:

    * ``error:*`` → the node's own *applied-error* state (distinct chip), not
      a stall.
    * ``reverted`` → a deliberate auto-revert (2c); alarming would never
      resolve since ``applied_hash != rendered_hash`` permanently.
    * only an ``ok`` node with a real ``rendered != applied`` mismatch counts.

    The grace is anchored on a ``stalled_since`` watermark the matcher stamps
    on first observation (and clears on convergence / a non-ok status), so a
    normal one-heartbeat render→apply lag never alarms and a converged node
    auto-resolves via ``evaluate_all``'s ``open_by_subject`` diff. The session
    commit at the end of ``evaluate_all`` persists the watermark mutations.
    """
    from app.models.appliance import Appliance  # noqa: PLC0415
    from app.models.firewall import FirewallApplyState  # noqa: PLC0415

    rows = (
        await db.execute(
            select(FirewallApplyState, Appliance)
            .join(Appliance, Appliance.id == FirewallApplyState.appliance_id)
            .where(Appliance.revoked_at.is_(None))
            .where(FirewallApplyState.rendered_hash.is_not(None))
        )
    ).all()

    matches: list[tuple[str, str, str, str]] = []
    for st, a in rows:
        converged = st.applied_hash == st.rendered_hash
        if converged or st.applied_status != "ok":
            # Not stalled (in sync, or an error/reverted state owns its own
            # signal) — clear the watermark so a later genuine stall starts a
            # fresh grace clock.
            if st.stalled_since is not None:
                st.stalled_since = None
            continue
        # ok-status node with a genuine mismatch.
        if st.stalled_since is None:
            st.stalled_since = now  # first observation — start the grace clock
            continue
        if (now - st.stalled_since) <= _FIREWALL_STALE_GRACE:
            continue  # still within grace — the normal render→apply lag
        # Sustained mismatch → fire. Cross-reference the Wave-E watchdog
        # (last_seen_at) so the operator knows whether the supervisor itself
        # is wedged or just the host firewall runner is the laggard.
        seen = a.last_seen_at
        if seen is not None and (now - seen) > _FIREWALL_STALE_GRACE:
            cause = f"the supervisor heartbeat is stale (last seen {seen.isoformat()})"
        else:
            cause = (
                "the supervisor is heartbeating but the host firewall runner "
                "hasn't applied the rendered ruleset"
            )
        message = (
            f"Firewall drift on {a.hostname}: control plane rendered "
            f"{st.rendered_hash[:12] if st.rendered_hash else 'none'} but the node "
            f"last applied {st.applied_hash[:12] if st.applied_hash else 'none'} — {cause}. "
            f"Check `journalctl -u spatium-firewall-reload` on the node."
        )
        matches.append((str(a.id), a.hostname, message, rule.severity))
    return matches


async def _matching_appliance_storage_subjects(
    db: AsyncSession,
    rule: AlertRule,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for appliances
    whose storage redundancy is degraded (#999 Part A).

    Reads the ``storage`` block the supervisor folds into its
    ``cluster_health`` JSONB and classifies it through
    ``services/appliance/storage_health.evaluate_storage`` — the same
    function the ``find_appliance_storage`` copilot tool and the Cluster
    screen's chip derive from, so an operator can never be told two
    different things about one array.

    Silent on three groups, each for its own reason:

    * **Revoked appliances** — a decommissioned box's array is not an
      operational problem, matching ``secret_expiring``'s treatment of
      revoked rows.
    * **Supervisors too old to report** — no ``storage`` key at all is
      UNKNOWN. Firing would be a guess; treating it as healthy would be
      a lie. It is simply not a match.
    * **Nodes with no arrays and no multipath** — the ordinary
      single-disk appliance, which reports an empty snapshot.

    **A reading that DISAPPEARS is handled differently from one that was
    never there**, and this is the subtle half. ``evaluate_all``
    resolves every open event whose subject is absent from a pass, so
    "not a match" means "recovered". An A/B slot rollback to a
    pre-#999 supervisor would therefore auto-resolve a live critical
    degraded-array event — announcing a recovery that did not happen, on
    a node whose mirror is still one disk from data loss. So an
    appliance that has an OPEN event for this rule and no current
    reading is re-matched at its existing severity, which the caller
    treats as a complete no-op (it never downgrades and never
    re-delivers on an unchanged severity) and which keeps the event
    standing until a real reading decides. That is per-subject what
    ``AlertDataUnavailable`` is per-rule; raising instead would make the
    whole rule inert across the fleet for as long as one old supervisor
    exists.

    One event per appliance rather than per array: the subject is the
    box, and an operator dealing with two degraded arrays on one node is
    dealing with one node. The message names every finding, worst first.
    """
    from app.models.alerts import AlertEvent  # noqa: PLC0415
    from app.models.appliance import (  # noqa: PLC0415
        APPLIANCE_STATE_APPROVED,
        Appliance,
    )
    from app.services.appliance.storage_health import (  # noqa: PLC0415
        evaluate_storage,
        worst_severity,
    )

    rows = list(
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.revoked_at.is_(None),
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                )
            )
        )
        .scalars()
        .all()
    )

    open_severity_by_subject: dict[str, str] = {
        ev.subject_id: ev.severity
        for ev in (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id,
                    AlertEvent.resolved_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    }

    matches: list[tuple[str, str, str, str]] = []
    for a in rows:
        subject_id = str(a.id)
        ch = a.cluster_health if isinstance(a.cluster_health, dict) else {}
        storage = ch.get("storage")
        if not isinstance(storage, dict):
            held = open_severity_by_subject.get(subject_id)
            if held is None:
                continue  # never reported — UNKNOWN, not healthy, not an alarm
            # Had a reading, lost it. Hold the open event rather than
            # resolving it into a false recovery.
            matches.append(
                (
                    subject_id,
                    a.hostname,
                    f"Storage on {a.hostname} can no longer be read — the "
                    "supervisor has stopped reporting array state (it may have "
                    "been rolled back to a slot that predates storage "
                    "monitoring). The last known state is left standing "
                    "because unknown is not recovered.",
                    held,
                )
            )
            continue
        findings = evaluate_storage(storage)
        if not findings:
            continue
        severity = worst_severity(findings) or rule.severity
        detail = " ".join(f.detail for f in findings)
        matches.append(
            (
                subject_id,
                a.hostname,
                f"Storage on {a.hostname}: {detail}",
                severity,
            )
        )
    return matches


async def _evaluate_circuit_status_changed_rule(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> tuple[int, int, int, int, int]:
    """``circuit_status_changed`` — fires once when a circuit's status
    transitions into ``suspended`` or ``decom``.

    The router stamps ``previous_status`` + ``last_status_change_at``
    on every status update (see
    ``backend/app/api/v1/circuits/router.py:_stamp_status_transition``)
    so this evaluator just keys events on ``last_status_change_at``:
    a new firing is keyed by the timestamp, and the most recent event
    for the subject latches that timestamp into
    ``last_observed_value.changed_at``. If we see a row whose current
    timestamp doesn't match the latched one we have a fresh transition
    to fire on. Auto-resolves after ``_TRANSITION_AUTO_RESOLVE_DAYS``.

    Routine ``active`` ↔ ``pending`` flips during commissioning are
    intentionally excluded — only the ``suspended`` / ``decom`` states
    surface to the operator.
    """
    targets = await audit_forward._load_targets()  # noqa: SLF001

    opened = 0
    resolved = 0
    delivered_syslog = 0
    delivered_webhook = 0
    delivered_smtp = 0

    # All open events for this rule, keyed by subject.
    open_res = await db.execute(
        select(AlertEvent).where(
            AlertEvent.rule_id == rule.id,
            AlertEvent.resolved_at.is_(None),
        )
    )
    open_events = list(open_res.scalars().all())
    open_by_subject: dict[str, AlertEvent] = {ev.subject_id: ev for ev in open_events}

    # Auto-resolve old open events.
    cutoff = now - timedelta(days=_TRANSITION_AUTO_RESOLVE_DAYS)
    for ev in list(open_events):
        if ev.fired_at < cutoff:
            ev.resolved_at = now
            resolved += 1
            del open_by_subject[ev.subject_id]

    # Most recent event (open or resolved) per subject — needed so we
    # can compare its latched ``changed_at`` against the row's current
    # ``last_status_change_at``. Without that, every evaluation pass
    # would re-fire on the same transition.
    last_event_res = await db.execute(
        select(AlertEvent).where(AlertEvent.rule_id == rule.id).order_by(AlertEvent.fired_at.desc())
    )
    last_event_by_subject: dict[str, AlertEvent] = {}
    for ev in last_event_res.scalars().all():
        if ev.subject_id not in last_event_by_subject:
            last_event_by_subject[ev.subject_id] = ev

    rows = (await db.execute(select(Circuit).where(Circuit.deleted_at.is_(None)))).scalars().all()
    for c in rows:
        subject_id = str(c.id)
        if c.last_status_change_at is None:
            continue
        if c.status not in _CIRCUIT_STATUS_CHANGE_DESTS:
            continue

        # Skip if there's an open event for this subject — wait for
        # the auto-resolve cutoff above.
        if subject_id in open_by_subject:
            continue

        # If the most recent event already latched this exact
        # ``last_status_change_at``, we've already fired for it.
        prior_event = last_event_by_subject.get(subject_id)
        if prior_event is not None and isinstance(prior_event.last_observed_value, dict):
            latched = prior_event.last_observed_value.get("changed_at")
            if latched == c.last_status_change_at.isoformat():
                continue

        from_label = c.previous_status or "<unset>"
        to_label = c.status
        message = f"Circuit {c.name} status: {from_label} → {to_label}"

        event = AlertEvent(
            rule_id=rule.id,
            subject_type="circuit",
            subject_id=subject_id,
            subject_display=c.name,
            severity=rule.severity,
            message=message,
            fired_at=now,
            last_observed_value={
                "from": c.previous_status,
                "to": c.status,
                "changed_at": c.last_status_change_at.isoformat(),
            },
        )
        db.add(event)
        await db.flush()
        ds, dw, dm = await _deliver(rule, event, targets)
        event.delivered_syslog = ds
        event.delivered_webhook = dw
        event.delivered_smtp = dm
        opened += 1
        if ds:
            delivered_syslog += 1
        if dw:
            delivered_webhook += 1
        if dm:
            delivered_smtp += 1

    return opened, resolved, delivered_syslog, delivered_webhook, delivered_smtp


# ── Service catalog rule evaluators ─────────────────────────────────


async def _matching_service_term_expiring_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for the
    ``service_term_expiring`` rule type. Mirrors the
    ``circuit_term_expiring`` shape — same severity escalation, same
    ``decom`` / soft-delete exclusions.
    """
    threshold_days = rule.threshold_days or _DEFAULT_EXPIRING_THRESHOLD_DAYS
    cutoff = (now + timedelta(days=threshold_days)).date()

    rows = (
        (
            await db.execute(
                select(NetworkService)
                .where(NetworkService.deleted_at.is_(None))
                .where(NetworkService.status != "decom")
                .where(NetworkService.term_end_date.is_not(None))
                .where(NetworkService.term_end_date <= cutoff)
            )
        )
        .scalars()
        .all()
    )

    matches: list[tuple[str, str, str, str]] = []
    today = now.date()
    for s in rows:
        if s.term_end_date is None:
            continue
        days_to_expiry = (s.term_end_date - today).days
        sev = _escalate_severity_for_expiring(
            rule.severity,
            threshold_days=threshold_days,
            days_to_expiry=days_to_expiry,
        )
        if days_to_expiry <= 0:
            descriptor = "term has expired"
        elif days_to_expiry == 1:
            descriptor = "term expires tomorrow"
        else:
            descriptor = f"term expires in {days_to_expiry} day(s)"
        message = (
            f"Service {s.name} {descriptor} "
            f"(term_end_date {s.term_end_date.isoformat()}, threshold "
            f"{threshold_days} d)"
        )
        matches.append((str(s.id), s.name, message, sev))
    return matches


async def _matching_decom_expiring_subjects(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> list[tuple[str, str, str, str]]:
    """Return ``[(subject_id, display, message, severity)]`` for the
    ``decom_expiring`` rule type (issue #46). Mirrors the
    ``service_term_expiring`` shape — same severity escalation, same
    soft-delete exclusion. A past-due decom date (negative days)
    surfaces a "decommission overdue" message at critical severity.
    """
    threshold_days = rule.threshold_days or _DEFAULT_EXPIRING_THRESHOLD_DAYS
    cutoff = (now + timedelta(days=threshold_days)).date()

    rows = (
        (
            await db.execute(
                select(Subnet)
                .where(Subnet.deleted_at.is_(None))
                .where(Subnet.decom_date.is_not(None))
                .where(Subnet.decom_date <= cutoff)
            )
        )
        .scalars()
        .all()
    )

    matches: list[tuple[str, str, str, str]] = []
    today = now.date()
    for s in rows:
        if s.decom_date is None:
            continue
        days_to_expiry = (s.decom_date - today).days
        sev = _escalate_severity_for_expiring(
            rule.severity,
            threshold_days=threshold_days,
            days_to_expiry=days_to_expiry,
        )
        display = s.name or s.network
        if days_to_expiry < 0:
            descriptor = f"decommission is {-days_to_expiry} day(s) overdue"
        elif days_to_expiry == 0:
            descriptor = "is scheduled for decommission today"
        elif days_to_expiry == 1:
            descriptor = "is scheduled for decommission tomorrow"
        else:
            descriptor = f"is scheduled for decommission in {days_to_expiry} day(s)"
        message = (
            f"Subnet {display} {descriptor} "
            f"(decom_date {s.decom_date.isoformat()}, threshold {threshold_days} d)"
        )
        matches.append((str(s.id), display, message, sev))
    return matches


async def _matching_service_resource_orphaned_subjects(
    db: AsyncSession,
    rule: AlertRule,  # noqa: ARG001 — symmetry with sibling evaluators
) -> list[tuple[str, str, str]]:
    """Every ``NetworkServiceResource`` join row whose target row no
    longer exists or is soft-deleted.

    The subject_id is the join row's own PK (not the missing target's
    ID) so that detaching the orphan link resolves the alert via the
    standard "subject no longer matches" branch in ``evaluate_all``.

    Soft-deleted services are skipped — their join rows are
    intentionally preserved during the trash window so a restore
    brings the bundle back intact, and surfacing alerts for them while
    they're in the trash bin would just be noise.
    """
    rows = (
        await db.execute(
            select(NetworkServiceResource, NetworkService.name)
            .join(
                NetworkService,
                NetworkServiceResource.service_id == NetworkService.id,
            )
            .where(NetworkService.deleted_at.is_(None))
        )
    ).all()

    matches: list[tuple[str, str, str]] = []
    for link, svc_name in rows:
        # ``overlay_network`` is reserved for #95 and the router blocks
        # attach attempts, so no orphan is possible. If a row somehow
        # exists, treat it as orphaned so the operator notices.
        model = _ORPHAN_RESOURCE_MODELS.get(link.resource_kind)
        if model is None:
            display = f"{svc_name}::{link.resource_kind}::{link.resource_id}"
            message = (
                f"Service {svc_name!r} has a resource link of unknown kind "
                f"{link.resource_kind!r} — manual review needed"
            )
            matches.append((str(link.id), display, message))
            continue

        target = await db.get(model, link.resource_id)
        is_orphan = target is None or getattr(target, "deleted_at", None) is not None
        if not is_orphan:
            continue

        display = f"{svc_name}::{link.resource_kind}::{link.resource_id}"
        message = (
            f"Service {svc_name!r} references {link.resource_kind} "
            f"{link.resource_id} but the target row no longer exists — "
            f"detach or re-attach to resolve"
        )
        matches.append((str(link.id), display, message))
    return matches


# ── Compliance change rule evaluator ────────────────────────────────


async def _resolve_compliance_subnet(
    db: AsyncSession,
    *,
    resource_type: str,
    resource_id: str,
    old_value: dict[str, Any] | None,
) -> Subnet | None:
    """Map an audit_log row's ``(resource_type, resource_id)`` back to
    the Subnet whose classification flags should be consulted.

    For ``subnet`` rows the resource itself IS the subnet. For
    ``ip_address`` and ``dhcp_scope`` rows we look up the live row to
    find its ``subnet_id``. On ``delete`` actions the live row is gone,
    so we fall back to the audit's ``old_value`` JSON if it carried a
    ``subnet_id``. Returns None when the subnet can't be identified
    — caller will skip the row.
    """
    try:
        rid_uuid = uuid.UUID(resource_id)
    except (ValueError, TypeError):
        return None

    if resource_type == "subnet":
        return await db.get(Subnet, rid_uuid)

    if resource_type == "ip_address":
        ip = await db.get(IPAddress, rid_uuid)
        if ip is not None:
            return await db.get(Subnet, ip.subnet_id)
        # Deleted — look in old_value.
        if old_value and "subnet_id" in old_value:
            try:
                sid = uuid.UUID(str(old_value["subnet_id"]))
            except (ValueError, TypeError):
                return None
            return await db.get(Subnet, sid)
        return None

    if resource_type == "dhcp_scope":
        scope = await db.get(DHCPScope, rid_uuid)
        if scope is not None and scope.subnet_id is not None:
            return await db.get(Subnet, scope.subnet_id)
        if old_value and "subnet_id" in old_value:
            try:
                sid = uuid.UUID(str(old_value["subnet_id"]))
            except (ValueError, TypeError):
                return None
            return await db.get(Subnet, sid)
        return None

    return None


async def _evaluate_compliance_change_rule(
    db: AsyncSession,
    rule: AlertRule,
    now: datetime,
) -> tuple[int, int, int, int, int]:
    """``compliance_change`` — fire one event per audit-log mutation
    against a subnet (or descendant IP / DHCP scope) whose
    classification flag matches ``rule.classification``.

    State model:

    * ``rule.last_scanned_audit_at`` is the high-water mark. NULL on
      a fresh rule means "never scanned" — we stamp it to ``now()``
      on the first pass so historical rows don't retro-fire when an
      operator first enables the rule.
    * Each audit row that matches opens one ``AlertEvent`` keyed by
      the audit row's UUID, so re-running the evaluator is idempotent.
    * Open events auto-resolve after
      ``_COMPLIANCE_CHANGE_AUTO_RESOLVE_HOURS``. Operators can also
      manually mark them resolved on the alerts page.

    Per-pass scan is capped at ``_COMPLIANCE_CHANGE_SCAN_LIMIT`` rows
    so a long-disabled rule flipping on doesn't pause the evaluator.
    """
    targets = await audit_forward._load_targets()  # noqa: SLF001

    opened = 0
    resolved = 0
    delivered_syslog = 0
    delivered_webhook = 0
    delivered_smtp = 0

    classification = rule.classification or ""
    if classification not in COMPLIANCE_CLASSIFICATIONS:
        logger.warning(
            "alert_compliance_unknown_classification",
            rule=str(rule.id),
            classification=classification,
        )
        return opened, resolved, delivered_syslog, delivered_webhook, delivered_smtp

    actions = _COMPLIANCE_CHANGE_SCOPE_ACTIONS.get(
        rule.change_scope or "any_change",
        _COMPLIANCE_CHANGE_SCOPE_ACTIONS["any_change"],
    )

    # Auto-resolve old open events for this rule.
    auto_resolve_cutoff = now - timedelta(hours=_COMPLIANCE_CHANGE_AUTO_RESOLVE_HOURS)
    open_res = await db.execute(
        select(AlertEvent).where(
            AlertEvent.rule_id == rule.id,
            AlertEvent.resolved_at.is_(None),
        )
    )
    for ev in open_res.scalars().all():
        if ev.fired_at < auto_resolve_cutoff:
            ev.resolved_at = now
            resolved += 1

    # Watermark — first run baselines to ``now`` and exits without
    # firing on history.
    if rule.last_scanned_audit_at is None:
        rule.last_scanned_audit_at = now
        return opened, resolved, delivered_syslog, delivered_webhook, delivered_smtp

    watermark = rule.last_scanned_audit_at

    audit_rows = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.timestamp > watermark)
                .where(AuditLog.action.in_(actions))
                .where(AuditLog.resource_type.in_(_COMPLIANCE_RESOURCE_TYPES))
                .where(AuditLog.result == "success")
                .order_by(AuditLog.timestamp)
                .limit(_COMPLIANCE_CHANGE_SCAN_LIMIT)
            )
        )
        .scalars()
        .all()
    )

    if not audit_rows:
        return opened, resolved, delivered_syslog, delivered_webhook, delivered_smtp

    label = _CLASSIFICATION_LABEL.get(classification, classification)

    # Index existing events for this rule keyed by audit row UUID so
    # repeated passes don't double-fire. Compliance events use the
    # audit row's UUID as the subject_id, so the open-event index is
    # also the dedup index.
    existing_event_subjects = {
        ev.subject_id
        for ev in (await db.execute(select(AlertEvent).where(AlertEvent.rule_id == rule.id)))
        .scalars()
        .all()
    }

    last_seen_ts = watermark
    for row in audit_rows:
        last_seen_ts = row.timestamp

        if str(row.id) in existing_event_subjects:
            continue

        subnet = await _resolve_compliance_subnet(
            db,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            old_value=row.old_value if isinstance(row.old_value, dict) else None,
        )
        if subnet is None:
            continue
        if not getattr(subnet, classification, False):
            continue

        actor = row.user_display_name or "<system>"
        changed = (
            ", ".join(row.changed_fields)
            if isinstance(row.changed_fields, list) and row.changed_fields
            else ""
        )
        descriptor = f"{row.action}"
        if changed:
            descriptor = f"{row.action} ({changed})"

        display = f"{row.resource_type} {row.resource_display}"[:500]
        subnet_label = f"{subnet.network}"
        if subnet.name:
            subnet_label += f" ({subnet.name})"
        message = (
            f"{label}-scoped {row.resource_type} {row.resource_display} "
            f"in subnet {subnet_label} — {descriptor} by {actor}"
        )

        event = AlertEvent(
            rule_id=rule.id,
            subject_type=f"audit:{row.resource_type}",
            subject_id=str(row.id),
            subject_display=display,
            severity=rule.severity,
            message=message,
            fired_at=now,
            last_observed_value={
                "audit_id": str(row.id),
                "audit_timestamp": row.timestamp.isoformat(),
                "subnet_id": str(subnet.id),
                "classification": classification,
                "action": row.action,
                "actor": actor,
                "changed_fields": (
                    row.changed_fields if isinstance(row.changed_fields, list) else None
                ),
            },
        )
        db.add(event)
        await db.flush()
        ds, dw, dm = await _deliver(rule, event, targets)
        event.delivered_syslog = ds
        event.delivered_webhook = dw
        event.delivered_smtp = dm
        opened += 1
        if ds:
            delivered_syslog += 1
        if dw:
            delivered_webhook += 1
        if dm:
            delivered_smtp += 1

    # Advance watermark past the last row we examined regardless of
    # whether it matched — we don't want to re-scan the same window
    # next pass.
    rule.last_scanned_audit_at = last_seen_ts

    return opened, resolved, delivered_syslog, delivered_webhook, delivered_smtp


# Built-in compliance_change rules seeded on first start. Disabled by
# default — the operator opts in by flipping ``enabled`` on the row
# after wiring the audit-forward targets they want the alerts to fan
# out to. We deliberately avoid auto-creating these only when at
# least one classification flag is set, because that would create a
# chicken-and-egg problem where flipping the first PCI flag wouldn't
# also fire the rule on its own create event.
_COMPLIANCE_RULE_SEEDS: list[dict[str, Any]] = [
    {
        "name": "PCI scope changes",
        "description": (
            "Fires whenever a PCI-scoped subnet (or an IP / DHCP scope inside "
            "one) is created, updated, or deleted. Toggle on after configuring "
            "an audit-forward target to receive the events."
        ),
        "rule_type": RULE_TYPE_COMPLIANCE_CHANGE,
        "classification": "pci_scope",
        "change_scope": "any_change",
        "severity": "warning",
    },
    {
        "name": "HIPAA scope changes",
        "description": (
            "Fires whenever a HIPAA-scoped subnet (or an IP / DHCP scope inside "
            "one) is created, updated, or deleted."
        ),
        "rule_type": RULE_TYPE_COMPLIANCE_CHANGE,
        "classification": "hipaa_scope",
        "change_scope": "any_change",
        "severity": "warning",
    },
    {
        "name": "Internet-facing scope changes",
        "description": (
            "Fires whenever an internet-facing subnet (or an IP / DHCP scope "
            "inside one) is created, updated, or deleted."
        ),
        "rule_type": RULE_TYPE_COMPLIANCE_CHANGE,
        "classification": "internet_facing",
        "change_scope": "any_change",
        "severity": "warning",
    },
]


_AUDIT_CHAIN_RULE_NAME = "audit-chain-broken"


async def seed_audit_chain_alert_rule() -> None:
    """Seed the singleton ``audit-chain-broken`` rule (issue #73).

    Enabled by default — tampering is one of the few signals every
    deployment wants to know about; opt-out is for the rare operator
    who genuinely doesn't want it. Keyed on ``name`` since there's
    only one rule per platform.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _AUDIT_CHAIN_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_AUDIT_CHAIN_RULE_NAME,
                description=(
                    "Fires when the nightly audit-log chain verifier finds a "
                    "row whose hash doesn't match its predecessor — strong "
                    "evidence of tampering with the audit trail. Critical "
                    "severity by default; auto-resolves on the next pass "
                    "that finds the chain back in sync."
                ),
                rule_type=RULE_TYPE_AUDIT_CHAIN_BROKEN,
                severity="critical",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=True,
            )
        )
        await session.commit()


_SCHEMA_BEHIND_HEAD_RULE_NAME = "schema-behind-head"


async def seed_schema_behind_head_alert_rule() -> None:
    """Seed the singleton ``schema-behind-head`` rule (issue #565).

    Enabled by default — a worker running against a DB behind the
    bundled migrations is a real "code deployed before migrate ran"
    footgun that every deployment wants surfaced loudly instead of a
    silent background retry loop. Keyed on ``name`` (one rule per
    platform); an operator who disables / renames it is never
    overridden by a later boot.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _SCHEMA_BEHIND_HEAD_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_SCHEMA_BEHIND_HEAD_RULE_NAME,
                description=(
                    "Fires when the Celery worker/beat finds the database schema "
                    "behind the Alembic head bundled in the running image — i.e. "
                    "the app was deployed before 'alembic upgrade head' ran, so "
                    "background tasks fail against missing tables/columns. "
                    "Auto-resolves on the next check that finds the schema back "
                    "at head. Set STRICT_SCHEMA_CHECK=true to also refuse to "
                    "process tasks while behind."
                ),
                rule_type=RULE_TYPE_SCHEMA_BEHIND_HEAD,
                severity="critical",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=True,
            )
        )
        await session.commit()


async def seed_firewall_apply_stalled_alert_rule() -> None:
    """Seed the singleton ``firewall.apply_stalled`` rule (issue #285 Phase 2d).

    DISABLED by default — it's only meaningful once an operator has enabled
    server-side firewall render (``firewall_enabled``); seeding it on signals
    its existence in the Alerts UI without firing on installs that never opt
    in. Keyed on ``name`` (one rule per platform); an operator who enables /
    renames it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _FIREWALL_APPLY_STALLED_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_FIREWALL_APPLY_STALLED_RULE_NAME,
                description=(
                    "Fires when an appliance's control-plane-rendered firewall "
                    "ruleset hasn't been applied by the host runner past a short "
                    "grace window, while the node's last apply was a clean 'ok' "
                    "(i.e. a genuine stall, not an apply error or a deliberate "
                    "auto-revert). Distinct from agent-offline — the message says "
                    "whether the supervisor itself is stale or just the host "
                    "firewall runner. Auto-resolves once the node applies the "
                    "rendered ruleset. Enable once server-side firewall render is on."
                ),
                rule_type=RULE_TYPE_FIREWALL_APPLY_STALLED,
                severity="warning",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


_AGENT_CONFIG_REJECTED_RULE_NAME = "Agent config apply rejected"


async def seed_node_pressure_alert_rule() -> None:
    """Seed the #983 Phase 2 PSI rule, ENABLED by default.

    Safe to enable everywhere despite being new and uncalibrated, because it
    cannot fire where the reading does not exist: a kubelet below 1.36
    reports no PSI at all, and the matcher treats that as "no match" rather
    than as zero. So on upgrade day it is silent until the node is actually
    running 1.36, and silent after that until something stalls.

    The default threshold is deliberately conservative. #983 asked for
    "warning at sustained cpu.some / memory.some" without a number, and the
    honest position is that nobody has watched PSI on a loaded appliance yet
    — so it is set where the reading is unambiguous rather than where it is
    sensitive. 50% means half of every five-minute window had something
    blocked; a node doing that is not merely busy. Tune it DOWN once there
    are field numbers to tune against; starting low would page on day one
    and teach operators to ignore it, which costs more than a late alarm.

    Keyed on ``name``; an operator who disables or renames it is never
    overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _NODE_PRESSURE_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_NODE_PRESSURE_RULE_NAME,
                description=(
                    "Fires when a cluster node reports sustained resource stalling "
                    "through PSI (Pressure Stall Information, Kubernetes 1.36+). "
                    "Utilisation cannot see this: a node at 70% CPU with a run "
                    "queue behind one core and a node at 70% without one look "
                    "identical, and only the first one drops traffic. Warning when "
                    "CPU or memory 'some' stalling holds above the threshold across "
                    "a 5-minute window; critical when memory 'full' stalling — every "
                    "runnable task blocked — holds above 1% of that window. Silent "
                    "on nodes whose kubelet does not report PSI. Auto-resolves when "
                    "the pressure clears."
                ),
                rule_type=RULE_TYPE_NODE_PRESSURE,
                severity="warning",
                enabled=True,
                threshold_percent=50,
            )
        )
        await session.commit()


async def seed_cluster_dns_alert_rule() -> None:
    """Seed the #985 rule, ENABLED by default.

    Safe on by default for the same reason as ``agent_config_rejected``: it
    needs no configuration, reads a signal that is either present or
    explicitly unknown, and the failure it catches is invisible on every
    other panel. It is also inert off the appliance — the matcher returns
    immediately when ``appliance_mode`` is off, and an unknown reading raises
    rather than fires.

    Severity is decided by the matcher per finding, not by the rule: a thin
    or co-located deployment is a warning (DNS answers, it just will not
    survive a node loss), while nothing ready or a failed resolve probe is
    critical. So the rule's own severity is only the floor.

    Keyed on ``name``; an operator who disables or renames it is never
    overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _CLUSTER_DNS_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_CLUSTER_DNS_RULE_NAME,
                description=(
                    "Fires when the k3s cluster's DNS (CoreDNS) is down, thinner "
                    "than the appliance targets, co-located on one node, or not "
                    "answering a test lookup. Every pod resolves "
                    "*.svc.cluster.local through it — the api reaches Postgres and "
                    "Redis that way — so a failure here surfaces later as unrelated "
                    "components failing to start. Warning when replicas are missing "
                    "or share a node; critical when none are ready or the resolve "
                    "probe fails. Silent where cluster DNS state cannot be read. "
                    "Auto-resolves when cluster DNS recovers."
                ),
                rule_type=RULE_TYPE_CLUSTER_DNS_DEGRADED,
                severity="warning",
                enabled=True,
            )
        )
        await session.commit()


async def seed_appliance_storage_alert_rule() -> None:
    """Seed the #999 Part A rule, ENABLED by default.

    Safe on everywhere for the same reason as ``cluster_dns_degraded``:
    it needs no configuration and cannot fire where the reading does not
    exist. A supervisor too old to collect storage state ships no
    ``storage`` key and is skipped; an ordinary single-disk appliance
    reports an empty snapshot and is skipped. So enabling it on upgrade
    day is silent until somebody actually builds an array — which is the
    point, because the day they do is the day the silence starts costing
    them.

    Severity is decided by the matcher per finding, not by the rule, so
    the rule's own severity is only the floor. Keyed on ``name``; an
    operator who disables or renames it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _APPLIANCE_STORAGE_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_APPLIANCE_STORAGE_RULE_NAME,
                description=(
                    "Fires when an appliance's software RAID array or multipath "
                    "map loses redundancy. A mirror nobody watches silently "
                    "becomes a single disk: the array drops a member, the box "
                    "keeps serving perfectly, and the operator finds out when "
                    "the survivor dies. Critical when an array is running on the "
                    "last members it needs or a LUN is down to one path; warning "
                    "when redundancy is reduced but a further failure is still "
                    "survivable, or when an assembled array will not report its "
                    "member count. A routine scrub or resync on an intact array "
                    "is shown on the dashboards with its progress and is "
                    "deliberately NOT an event — a monthly checkarray cron would "
                    "otherwise notify every operator with an array, every month, "
                    "about their array working correctly. Silent on appliances "
                    "with no arrays and on supervisors too old to report storage "
                    "state. Auto-resolves when redundancy is restored."
                ),
                rule_type=RULE_TYPE_APPLIANCE_STORAGE_DEGRADED,
                severity="warning",
                enabled=True,
            )
        )
        await session.commit()


async def seed_agent_config_rejected_alert_rule() -> None:
    """Seed the #882 rule, ENABLED by default.

    Unlike the firewall-stalled and DNS-anomaly rules — which are seeded off
    because they only make sense once an optional subsystem is switched on —
    this one applies to every install that runs an agent, needs no
    configuration, and cannot false-fire: it reads a verdict the agent itself
    reported about its own apply. The failure it catches (a saved config that
    silently never went live) is invisible on every other signal, so leaving
    the alarm off by default would mean the operator has to already suspect
    the problem in order to find out about it.

    Keyed on ``name``; an operator who disables or renames it is never
    overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _AGENT_CONFIG_REJECTED_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_AGENT_CONFIG_REJECTED_RULE_NAME,
                description=(
                    "Fires when a DNS, DHCP or Looking Glass agent reports that it "
                    "could not apply the configuration the control plane sent it. "
                    "The agent reverts to its last-known-good config and keeps "
                    "serving, so the server stays reachable and healthy while NOT "
                    "running what is saved here — a divergence no reachability or "
                    "health check can see. Severity follows the agent's verdict: a "
                    "rollback is a warning; a failed rollback, or a failure with no "
                    "previous config to fall back to, is critical. Auto-resolves "
                    "when the agent reports a successful apply."
                ),
                rule_type=RULE_TYPE_AGENT_CONFIG_REJECTED,
                severity="warning",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


_DHCP_SCOPE_UNCOORDINATED_RULE_NAME = "DHCP scope served uncoordinated"


async def seed_dhcp_scope_uncoordinated_alert_rule() -> None:
    """Seed the #1110 rule, ENABLED by default.

    Silent on every install without a Windows DHCP server, and on one with a
    single Windows server per group; it only speaks when two servers already
    hand out the same addresses. That is the outage, not an early warning,
    and nothing else says it: both servers report the scope healthy. Keyed on
    ``name``; an operator who disables or renames it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _DHCP_SCOPE_UNCOORDINATED_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_DHCP_SCOPE_UNCOORDINATED_RULE_NAME,
                description=(
                    "Fires for each DHCP scope that two or more servers serve without "
                    "coordinating: Windows DHCP servers holding it with no failover "
                    "relationship covering it, over overlapping ranges, or a Windows "
                    "server holding a scope a Kea server in the same group also serves. "
                    "Each server can hand the same address to a different client, while "
                    "both report the scope healthy. Resolves when the scope is put in a "
                    "failover relationship or left on one server only."
                ),
                rule_type=RULE_TYPE_DHCP_SCOPE_UNCOORDINATED,
                severity="critical",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


_DHCP_PACKETS_DROPPED_RULE_NAME = "DHCP packets dropped"


async def seed_dhcp_packets_dropped_alert_rule() -> None:
    """Seed the #980 rule, ENABLED by default.

    On by default for the same reason as ``agent_config_rejected``, and not
    for the reason the DNS-anomaly rules are seeded off. Those are off
    because they need an optional subsystem (agent-based BIND9) before they
    can say anything; this one reads a counter every Kea agent reports
    unconditionally, needs no configuration, and cannot false-fire — a
    non-zero ``socket_drop`` is not an inference from a threshold, it is the
    kernel saying it threw a packet away.

    "Cannot false-fire" is only true because the evaluator reads
    ``socket_drop`` alone. Counting ``receive_drop`` as well would make a
    default-on rule fire permanently on any install using the DHCP MAC
    blocklist, since Kea counts a ``DROP``-class match there — the kind of
    alarm that trains operators to ignore the feed.

    It also cannot be found by an operator who does not already suspect it.
    A server dropping packets in its socket buffer is reachable, heartbeats
    normally, passes its health check, has free addresses, and answers 100 %
    of what it reads; the only symptom is clients taking multiple retransmit
    rounds to get an address, which looks like a client-side or network
    problem from here. Seeding this off would mean the alarm arrives only
    after somebody has already diagnosed the thing it exists to diagnose.

    Servers whose agent cannot report the counters are skipped by the
    evaluator, not alarmed on — see
    :func:`_matching_dhcp_packets_dropped_subjects`.

    Keyed on ``name``; an operator who disables or renames it is never
    overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.name == _DHCP_PACKETS_DROPPED_RULE_NAME)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name=_DHCP_PACKETS_DROPPED_RULE_NAME,
                description=(
                    "Fires when the kernel discarded DHCP packets before the server "
                    "could read them — its receive buffer filled, usually because the "
                    "node is short of CPU. Invisible to every other signal: the server "
                    "stays reachable and healthy and answers 100% of what reaches it, "
                    "while clients wait out retransmit rounds. Does NOT fire on packets "
                    "Kea read and discarded, because that figure also counts deliberate "
                    "drops (a blocklisted MAC, an HA standby declining an out-of-scope "
                    "query); those are reported alongside but are not faults. "
                    "Auto-resolves once a window passes with no loss. Set the rule's "
                    "minimum-count threshold to alert only past a number of packets."
                ),
                rule_type=RULE_TYPE_DHCP_PACKETS_DROPPED,
                severity="warning",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


_DNS_NXDOMAIN_SPIKE_RULE_NAME = "DNS NXDOMAIN spike"
_DNS_QUERY_RATE_SPIKE_RULE_NAME = "DNS query-rate spike"


async def seed_dns_query_anomaly_alert_rules() -> None:
    """Seed the two DNS query-anomaly rules (issue #371), DISABLED by default.

    Like the firewall-stalled rule, these are seeded off so their existence is
    discoverable in the Alerts UI without firing on installs that don't run
    agent-based BIND9 (and therefore have no ``dns_metric_sample`` data). Keyed
    on ``rule_type`` so an operator who enables / renames either is never
    overridden by a later boot.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    seeds = [
        {
            "name": _DNS_NXDOMAIN_SPIKE_RULE_NAME,
            "rule_type": RULE_TYPE_DNS_NXDOMAIN_SPIKE,
            "description": (
                "Fires when a DNS server's NXDOMAIN responses reach "
                f"threshold_percent% of total queries (default "
                f"{_DNS_NXDOMAIN_RATIO_DEFAULT}%) AND the absolute NXDOMAIN "
                f"count clears min_free_addresses (default "
                f"{_DNS_NXDOMAIN_MIN_COUNT_DEFAULT}, the low-traffic guard) "
                "over a 15-minute window. Catches DGA malware beacons, broken "
                "clients, and mistyped-search-domain storms. Auto-resolves when "
                "the ratio falls back under threshold."
            ),
            "threshold_percent": _DNS_NXDOMAIN_RATIO_DEFAULT,
            "min_free_addresses": _DNS_NXDOMAIN_MIN_COUNT_DEFAULT,
        },
        {
            "name": _DNS_QUERY_RATE_SPIKE_RULE_NAME,
            "rule_type": RULE_TYPE_DNS_QUERY_RATE_SPIKE,
            "description": (
                "Fires when a DNS server's query total over the last 15 minutes "
                "exceeds the prior 15-minute window by threshold_percent% "
                f"(default {_DNS_QUERY_RATE_SPIKE_PCT_DEFAULT}% = ×3) AND clears "
                f"the min_free_addresses absolute floor (default "
                f"{_DNS_QUERY_RATE_MIN_DEFAULT}, so tiny servers don't page on a "
                "3→9 'spike'). Auto-resolves when the rate settles."
            ),
            "threshold_percent": _DNS_QUERY_RATE_SPIKE_PCT_DEFAULT,
            "min_free_addresses": _DNS_QUERY_RATE_MIN_DEFAULT,
        },
        {
            "name": "DNS rate limiting actively dropping",
            "rule_type": RULE_TYPE_DNS_RATE_LIMIT_DROPPING,
            "description": (
                "Fires when a BIND9 server's Response Rate Limiting drops more "
                "than min_free_addresses responses (default "
                f"{_DNS_RATE_LIMIT_DROP_MIN_DEFAULT}) over a 15-minute window — "
                "the server is actively shedding a query flood, i.e. likely "
                "under a DNS amplification attempt. Needs RRL enabled on the "
                "server group (issue #146 Phase 1). Auto-resolves when the flood "
                "subsides. threshold_percent is unused."
            ),
            "threshold_percent": None,
            "min_free_addresses": _DNS_RATE_LIMIT_DROP_MIN_DEFAULT,
        },
    ]
    async with AsyncSessionLocal() as session:
        for seed in seeds:
            existing = await session.scalar(
                select(AlertRule).where(AlertRule.rule_type == seed["rule_type"])
            )
            if existing is not None:
                continue
            session.add(
                AlertRule(
                    name=seed["name"],
                    description=seed["description"],
                    rule_type=seed["rule_type"],
                    threshold_percent=seed["threshold_percent"],
                    min_free_addresses=seed["min_free_addresses"],
                    severity="warning",
                    enabled=False,
                    notify_syslog=True,
                    notify_webhook=True,
                    notify_smtp=False,
                )
            )
        await session.commit()


async def seed_ip_hygiene_alert_rules() -> None:
    """Seed the three IP-reconciliation hygiene rules (issue #369), DISABLED by
    default so installs that don't run discovery aren't suddenly paged. Keyed on
    ``rule_type`` — an operator who enables / renames one is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    seeds = [
        {
            "name": "IP free but responding",
            "rule_type": RULE_TYPE_IP_FREE_BUT_RESPONDING,
            "description": (
                "Fires on an IP marked 'available' that answered on the wire "
                f"within threshold_days (default {_FREE_RESPONDING_RECENCY_DAYS}) "
                "— IPAM thinks it's free but a host is using it. Reclaim it or "
                "investigate. Needs subnet discovery (ping/ARP sweep or SNMP)."
            ),
            "threshold_days": _FREE_RESPONDING_RECENCY_DAYS,
            "severity": "warning",
        },
        {
            "name": "Stale reservation",
            "rule_type": RULE_TYPE_STALE_RESERVATION,
            "description": (
                "Fires on a reserved / static_dhcp IP not seen on the wire for "
                f"more than threshold_days (default {_STALE_RESERVATION_DAYS}). "
                "The reservation-aware companion to the stale-IP alert (which is "
                "allocated-only). Verify the host or release the reservation."
            ),
            "threshold_days": _STALE_RESERVATION_DAYS,
            "severity": "info",
        },
        {
            "name": "Unknown MAC in static range",
            "rule_type": RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE,
            "description": (
                "Fires when a reserved / static_dhcp IP is answered by a MAC that "
                "differs from the one recorded on the row, observed within "
                f"threshold_days (default {_SQUAT_RECENCY_DAYS}) — a squatter or a "
                "device that moved. Needs subnet discovery (ping/ARP or SNMP)."
            ),
            "threshold_days": _SQUAT_RECENCY_DAYS,
            "severity": "warning",
        },
    ]
    async with AsyncSessionLocal() as session:
        for seed in seeds:
            existing = await session.scalar(
                select(AlertRule).where(AlertRule.rule_type == seed["rule_type"])
            )
            if existing is not None:
                continue
            session.add(
                AlertRule(
                    name=seed["name"],
                    description=seed["description"],
                    rule_type=seed["rule_type"],
                    threshold_days=seed["threshold_days"],
                    severity=seed["severity"],
                    enabled=False,
                    notify_syslog=True,
                    notify_webhook=True,
                    notify_smtp=False,
                )
            )
        await session.commit()


async def seed_rogue_dhcp_alert_rule() -> None:
    """Seed the singleton ``rogue_dhcp`` rule (issue #370), DISABLED by default.

    Meaningful only once an operator turns on the agent's active DHCP probe
    (``DHCP_ROGUE_PROBE_ENABLED=1``); seeding it off makes it discoverable in
    the Alerts UI without firing on installs that never opt in. Keyed on
    ``rule_type`` — an operator who enables / renames it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_ROGUE_DHCP)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="Rogue DHCP server",
                description=(
                    "Fires when the DHCP agent's active probe sees an OFFER from "
                    "a DHCP server that isn't a known group member and isn't on "
                    "the responder allowlist — a rogue or misconfigured DHCP "
                    "server on the segment. Auto-resolves when the responder "
                    "stops appearing or is acknowledged. Enable once the probe "
                    "(DHCP_ROGUE_PROBE_ENABLED) is on."
                ),
                rule_type=RULE_TYPE_ROGUE_DHCP,
                threshold_days=_ROGUE_DHCP_RECENCY_DAYS,
                severity="warning",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_wol_wake_failed_alert_rule() -> None:
    """Seed the singleton ``wol_wake_failed`` rule (issue #596), DISABLED by default.

    Meaningful only once an operator arms post-wake verify on a schedule
    (``verify_enabled``); seeding it off makes it discoverable in the Alerts UI
    without paging anyone on installs that never opt in. Keyed on ``rule_type`` —
    an operator who enables / renames it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_WOL_WAKE_FAILED)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="Wake-on-LAN verify failed",
                description=(
                    "Fires when a Wake-on-LAN schedule's latest verified run left "
                    "hosts that never came up, and they are still not visible on "
                    "the network. One event per schedule (not per run), carrying "
                    "the blast-radius rollup. Auto-resolves once the stragglers "
                    "are seen, or after a clean run. Requires post-wake verify on "
                    "the schedule; mute a noisy one with its "
                    "'alert on wake failure' toggle."
                ),
                rule_type=RULE_TYPE_WOL_WAKE_FAILED,
                threshold_days=_WOL_WAKE_FAILED_RECENCY_DAYS,
                severity="warning",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_rogue_ra_alert_rule() -> None:
    """Seed the singleton ``rogue_ra`` rule (issue #524), DISABLED by default.

    Meaningful only once an operator turns on the agent's passive RA sniffer
    (``DHCP_RA_SNIFFER_ENABLED=1``); seeding it off makes it discoverable in
    the Alerts UI without firing on installs that never opt in. Keyed on
    ``rule_type`` — an operator who enables / renames it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_ROGUE_RA)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="Rogue IPv6 router (RA)",
                description=(
                    "Fires when the DHCP agent's passive RA sniffer sees a Router "
                    "Advertisement from an IPv6 router that isn't on the RA "
                    "allowlist — a rogue or misconfigured router on the segment. "
                    "Auto-resolves when the router stops appearing or is "
                    "acknowledged. Enable once the sniffer "
                    "(DHCP_RA_SNIFFER_ENABLED) is on."
                ),
                rule_type=RULE_TYPE_ROGUE_RA,
                threshold_days=_ROGUE_RA_RECENCY_DAYS,
                severity="warning",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_new_mac_seen_alert_rule() -> None:
    """Seed the singleton ``new_mac_seen`` rule (issue #459), DISABLED by default.

    The companion to the ``security.new_device_watch`` feature module: noisy
    until the operator runs a baseline import to mark the existing fleet as
    ``known``, so it seeds off and discoverable in the Alerts UI. Keyed on
    ``rule_type`` — an operator who enables / renames it is never overridden.
    Excludes locally-administered (randomised) MACs by default (``classification``
    left NULL; set to ``"all"`` to include them).
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_NEW_MAC_SEEN)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="New device on the network",
                description=(
                    "Fires when a MAC address never seen before appears on the "
                    "network (via a DHCP lease, SNMP ARP/FDB, the ping/ARP sweep, "
                    "or the opt-in L2 sniffer) and is not allowlisted or part of "
                    "the allocated fleet. Auto-resolves when the MAC is "
                    "acknowledged, allowlisted, or ages out of the window. "
                    "Enable once new-device watch (security.new_device_watch) is "
                    "on and you've run a baseline import. Randomised (privacy) "
                    "MACs are skipped by default."
                ),
                rule_type=RULE_TYPE_NEW_MAC_SEEN,
                threshold_days=_NEW_MAC_SEEN_RECENCY_DAYS,
                severity="info",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_bgp_hijack_alert_rules() -> None:
    """Seed the two ``bgp_prefix_hijack`` / ``bgp_more_specific_announced``
    rules (issue #527), DISABLED by default.

    External-signal rules over the global routing table are noisy until
    the operator has curated the tracked-prefix + allowlist set, so they
    seed off (matching the ``rogue_dhcp`` / ``rogue_ra`` precedent) —
    discoverable in the Alerts UI without firing on installs that never
    turn on BGP monitoring (``PlatformSettings.bgp_monitoring_enabled``).
    Keyed on ``rule_type``; an operator who enables / renames one is
    never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    seeds = (
        (
            RULE_TYPE_BGP_PREFIX_HIJACK,
            "BGP prefix hijack",
            (
                "Fires when an unexpected origin AS is observed announcing one "
                "of your tracked prefixes on the public routing table (RIPEstat "
                "poll, or the optional RIS Live feed). Severity escalates to "
                "critical when RPKI says the announcement is invalid, warning "
                "when RPKI coverage is unknown. Auto-resolves when the "
                "announcement delists or is acknowledged. Enable once BGP "
                "monitoring (Settings → bgp_monitoring_enabled) is on."
            ),
        ),
        (
            RULE_TYPE_BGP_MORE_SPECIFIC,
            "BGP more-specific announced",
            (
                "Fires when an unexpected origin AS announces a MORE-SPECIFIC "
                "sub-prefix of one of your tracked prefixes — the classic "
                "sub-prefix hijack that wins BGP best-path by longest match. "
                "Severity escalates on RPKI-invalid. Auto-resolves when the "
                "sub-prefix delists or is acknowledged. Enable once BGP "
                "monitoring is on."
            ),
        ),
    )

    async with AsyncSessionLocal() as session:
        for rule_type, name, description in seeds:
            existing = await session.scalar(
                select(AlertRule).where(AlertRule.rule_type == rule_type)
            )
            if existing is not None:
                continue
            session.add(
                AlertRule(
                    name=name,
                    description=description,
                    rule_type=rule_type,
                    severity="warning",
                    enabled=False,
                    notify_syslog=True,
                    notify_webhook=True,
                    notify_smtp=False,
                )
            )
        await session.commit()


async def seed_bgp_lg_alert_rules() -> None:
    """Seed the six ``bgp_lg_*`` rules (issue #566 Phase 5), DISABLED by
    default — the Looking Glass collector needs an operator-configured
    peer (and, for unexpected_origin/more_specific, at least one
    BGPTrackedPrefix owned-prefix row from the #527 UI) before any of
    these mean anything. Discoverable-but-off, matching the
    bgp_prefix_hijack / bgp_more_specific_announced precedent
    (``seed_bgp_hijack_alert_rules`` above). Keyed on ``rule_type``; an
    operator who enables/renames one is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    seeds: tuple[tuple[str, str, str, int | None], ...] = (
        (
            RULE_TYPE_BGP_LG_SESSION_DOWN,
            "BGP Looking Glass session down",
            (
                "Fires when a configured Looking Glass peer session drops out of "
                "Established for longer than a short grace window. Shows the last "
                "known prefix count and cross-references the owning collector's "
                "own health. Auto-resolves the moment the session re-establishes. "
                "Enable once you've configured at least one peer under "
                "Network → BGP Looking Glass."
            ),
            None,
        ),
        (
            RULE_TYPE_BGP_LG_RPKI_INVALID_ROUTE,
            "BGP Looking Glass RPKI-invalid route",
            (
                "Fires when a route in YOUR live routing table (not the public "
                "table — see the separate BGP prefix hijack rule for that) has an "
                "RPKI status of invalid: a ROA covers the prefix but does not "
                "authorise the observed origin/length. Always critical severity. "
                "Auto-resolves when the route withdraws or its RPKI status "
                "changes. The strongest in-network leak/misconfig signal."
            ),
            None,
        ),
        (
            RULE_TYPE_BGP_LG_UNEXPECTED_ORIGIN,
            "BGP Looking Glass unexpected origin",
            (
                "Fires when one of your tracked/owned prefixes (configured under "
                "an ASN's Tracked Prefixes — the same list the BGP prefix hijack "
                "rule reads) is learned in your OWN live table with an origin ASN "
                "outside the expected/allowlisted set. Catches internal leaks and "
                "fat-fingered redistribution before they reach the public table. "
                "Requires at least one enabled tracked prefix to ever fire."
            ),
            None,
        ),
        (
            RULE_TYPE_BGP_LG_MORE_SPECIFIC,
            "BGP Looking Glass more-specific announced",
            (
                "Fires when a route strictly more-specific than one of your "
                "tracked/owned aggregates is learned in your live table with an "
                "unexpected origin ASN — the classic internal sub-prefix leak "
                "that wins best-path over your aggregate via longest-match. "
                "Requires at least one enabled tracked prefix to ever fire."
            ),
            None,
        ),
        (
            RULE_TYPE_BGP_LG_ROUTE_FLAP,
            "BGP Looking Glass route flap",
            (
                "Fires when a learned route's flap count (announce/withdraw "
                "churn) crosses the configured threshold (Threshold %, reused "
                "here as a raw flap-count floor — default 5) with the most "
                "recent flap inside the trailing ~10 minutes. Auto-resolves once "
                "the route stops flapping for that window."
            ),
            _BGP_LG_FLAP_COUNT_DEFAULT,
        ),
        (
            RULE_TYPE_BGP_LG_MISSING_ADVERTISEMENT,
            "BGP Looking Glass missing advertisement",
            (
                "Fires when a subnet flagged 'should advertise via BGP' "
                "(Subnet.bgp_should_advertise) has no active learned route "
                "covering it across any configured peer — catches 'why is this "
                "network unreachable' before the tickets come in. Requires "
                "flagging at least one subnet as bgp_should_advertise=true to "
                "ever fire."
            ),
            None,
        ),
    )

    async with AsyncSessionLocal() as session:
        for rule_type, name, description, default_threshold in seeds:
            existing = await session.scalar(
                select(AlertRule).where(AlertRule.rule_type == rule_type)
            )
            if existing is not None:
                continue
            session.add(
                AlertRule(
                    name=name,
                    description=description,
                    rule_type=rule_type,
                    severity="warning",
                    enabled=False,
                    notify_syslog=True,
                    notify_webhook=True,
                    notify_smtp=False,
                    threshold_percent=default_threshold,
                )
            )
        await session.commit()


async def seed_builtin_compliance_alert_rules() -> None:
    """Insert the three disabled compliance-change rules on first
    boot. Idempotent — only inserts a row when no rule with the same
    ``(rule_type, classification)`` pair already exists.

    Operators who toggle / rename / re-author one of these are never
    overridden, because the seed key is the ``classification`` value
    rather than ``name``. Renaming "PCI scope changes" → "PCI v4
    cardholder data audit hook" still suppresses the seed.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415 — late import to dodge cycles

    async with AsyncSessionLocal() as session:
        for seed in _COMPLIANCE_RULE_SEEDS:
            existing = await session.scalar(
                select(AlertRule).where(
                    AlertRule.rule_type == seed["rule_type"],
                    AlertRule.classification == seed["classification"],
                )
            )
            if existing is not None:
                continue
            session.add(
                AlertRule(
                    name=seed["name"],
                    description=seed["description"],
                    rule_type=seed["rule_type"],
                    classification=seed["classification"],
                    change_scope=seed["change_scope"],
                    severity=seed["severity"],
                    enabled=False,
                    notify_syslog=True,
                    notify_webhook=True,
                    notify_smtp=False,
                )
            )
        await session.commit()


# ── Delivery ───────────────────────────────────────────────────────────────


def _severity_to_syslog(severity: str) -> int:
    """Map alert severity → RFC 5424 severity (mirrors audit_forward)."""
    if severity == "critical":
        return 2  # crit
    if severity == "warning":
        return 4  # warning
    return 6  # info


async def _deliver(
    rule: AlertRule,
    event: AlertEvent,
    targets: list[dict[str, Any]],
) -> tuple[bool, bool, bool]:
    """Fan an event out to every audit-forward target whose ``kind``
    matches an enabled rule channel. Returns
    ``(delivered_syslog, delivered_webhook, delivered_smtp)`` as
    booleans suitable for stamping onto the event row.

    Per-target ``min_severity`` / ``resource_types`` filters still
    apply via ``_deliver_to_target``. A dead target isolates to its
    own row; the others still see the event.
    """
    delivered_syslog = False
    delivered_webhook = False
    delivered_smtp = False

    payload: dict[str, Any] = {
        "kind": "alert",
        "rule_id": str(rule.id),
        "rule_name": rule.name,
        "rule_type": rule.rule_type,
        "severity": event.severity,
        "fired_at": event.fired_at.isoformat(),
        "subject_type": event.subject_type,
        "subject_id": event.subject_id,
        "subject_display": event.subject_display,
        "message": event.message,
    }

    for target in targets:
        kind = target.get("kind")
        if kind == "syslog" and not rule.notify_syslog:
            continue
        if kind == "webhook" and not rule.notify_webhook:
            continue
        if kind == "smtp" and not rule.notify_smtp:
            continue
        try:
            await audit_forward._deliver_to_target(target, payload)  # noqa: SLF001
            if kind == "syslog":
                delivered_syslog = True
            elif kind == "webhook":
                delivered_webhook = True
            elif kind == "smtp":
                delivered_smtp = True
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "alert_deliver_failed",
                rule=str(rule.id),
                event=str(event.id),
                target=target.get("name"),
                kind=kind,
                error=str(exc),
            )

    return delivered_syslog, delivered_webhook, delivered_smtp


# ── Main entry point ───────────────────────────────────────────────────────


_TLS_CERT_RULE_SEEDS: list[dict[str, object]] = [
    {
        "name": "TLS cert expiring",
        "rule_type": RULE_TYPE_TLS_CERT_EXPIRING,
        "severity": "warning",
        "threshold_days": 30,
        "description": (
            "Fires when a monitored TLS endpoint's served certificate is "
            "within threshold_days of expiry. Severity escalates info → "
            "warning → critical as the expiry nears. Auto-resolves on renewal."
        ),
    },
    {
        "name": "TLS cert chain invalid",
        "rule_type": RULE_TYPE_TLS_CERT_CHAIN_INVALID,
        "severity": "critical",
        "threshold_days": None,
        "description": (
            "Fires when a monitored endpoint's certificate is reachable and "
            "unexpired but not usable: an untrusted chain (self-signed / wrong "
            "CA / broken chain) or a trusted cert served for the wrong hostname "
            "(SAN/CN mismatch). Expiry is covered by the expiring rule. "
            "Auto-resolves once the cert validates and matches the hostname."
        ),
    },
    {
        "name": "TLS cert unreachable",
        "rule_type": RULE_TYPE_TLS_CERT_UNREACHABLE,
        "severity": "warning",
        "threshold_days": None,
        "description": (
            "Fires when a monitored endpoint can't be probed (TCP refused / "
            "TLS handshake failed / DNS) for a couple of consecutive cycles. "
            "Auto-resolves on the next successful probe."
        ),
    },
    {
        "name": "TLS cert changed",
        "rule_type": RULE_TYPE_TLS_CERT_CHANGED,
        "severity": "info",
        "threshold_days": None,
        "description": (
            "Fires once when a monitored endpoint's certificate fingerprint "
            "changes unexpectedly (legitimate on renewal, suspicious "
            "otherwise). Auto-resolves after the transition window."
        ),
    },
    {
        "name": "TLS cert issuer changed",
        "rule_type": RULE_TYPE_TLS_CERT_ISSUER_CHANGED,
        "severity": "warning",
        "threshold_days": None,
        "description": (
            "Fires once when a monitored endpoint's certificate comes back "
            "from a DIFFERENT issuing CA — cert-rotation deviation (e.g. a "
            "normally-Let's-Encrypt cert suddenly issued by another CA), a "
            "higher-signal subset of 'cert changed'. Auto-resolves after the "
            "transition window."
        ),
    },
]


async def seed_tls_cert_alert_rules() -> None:
    """Seed the four ``tls_cert_*`` rules (issue #118), DISABLED by default.

    Opt-in like the other monitoring signals — seeding them surfaces their
    existence in the Alerts UI without firing on installs that never add a
    probe target. Keyed on ``rule_type`` (one per type); an operator who
    enables / renames one is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        for seed in _TLS_CERT_RULE_SEEDS:
            existing = await session.scalar(
                select(AlertRule).where(AlertRule.rule_type == seed["rule_type"])
            )
            if existing is not None:
                continue
            session.add(
                AlertRule(
                    name=seed["name"],
                    description=seed["description"],
                    rule_type=seed["rule_type"],
                    severity=seed["severity"],
                    threshold_days=seed["threshold_days"],
                    enabled=False,
                    notify_syslog=True,
                    notify_webhook=True,
                    notify_smtp=False,
                )
            )
        await session.commit()


async def _matching_ip_blocklisted_subjects(
    db: AsyncSession, rule: AlertRule
) -> list[tuple[str, str, str]]:
    """Public-facing IPs currently listed on ≥1 enabled DNSBL (#528).

    Recurring-condition rule — one subject per listed IP. The shared
    open/resolve loop opens an event on first listing and auto-resolves it
    when the IP drops out of this set (the sweep flips ``listed=False``).
    ``subject_id`` is the IP so the latch survives list churn: the IP stays
    a subject as long as ANY enabled list has it.
    """
    from app.models.dnsbl import DNSBLList, DNSBLListing  # noqa: PLC0415

    rows = (
        await db.execute(
            select(DNSBLListing, DNSBLList.name)
            .join(DNSBLList, DNSBLList.id == DNSBLListing.list_id)
            .where(DNSBLListing.listed.is_(True), DNSBLList.enabled.is_(True))
        )
    ).all()
    by_ip: dict[str, list[str]] = {}
    for listing, list_name in rows:
        by_ip.setdefault(str(listing.ip), []).append(list_name)

    out: list[tuple[str, str, str]] = []
    for ip, list_names in sorted(by_ip.items()):
        names = ", ".join(sorted(list_names))
        msg = (
            f"IP {ip} is listed on {len(list_names)} DNS blocklist(s): {names}. "
            "Mail deliverability / reputation may be affected."
        )
        out.append((ip, ip, msg))
    return out


async def seed_ip_blocklisted_alert_rule() -> None:
    """Seed the ``ip_blocklisted`` rule (#528), DISABLED by default.

    Opt-in like the other monitoring signals — surfaces the rule in the
    Alerts UI without firing on installs that never enable the DNSBL sweep.
    Keyed on ``rule_type``; an operator who enables / renames it is never
    overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_IP_BLOCKLISTED)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="IP on DNS blocklist",
                description=(
                    "Fires when a public-facing IP (public IPAM address, "
                    "internet-facing subnet, NAT/PAT egress, or operator-pinned) "
                    "is found on one or more enabled DNS blocklists (Spamhaus, "
                    "Barracuda, SpamCop, SORBS, …). Auto-resolves when the daily "
                    "sweep finds the IP delisted. Requires the DNSBL sweep enabled."
                ),
                rule_type=RULE_TYPE_IP_BLOCKLISTED,
                severity="warning",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_restore_drill_failed_alert_rule() -> None:
    """Seed the ``restore_drill_failed`` rule (#702), ENABLED by default.

    The odd one out among the seeds: enabled rather than opt-in. The
    matcher only considers enabled targets with drills scheduled, so
    the rule is silent on every install that doesn't use the feature —
    and an operator who went to the trouble of scheduling drills wants
    to hear the answer. Keyed on ``rule_type``; an operator who disables
    or renames it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_RESTORE_DRILL_FAILED)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="Backup restore drill failed",
                description=(
                    "Fires when a restore-verification drill replays a backup "
                    "target's newest archive into a scratch database and an "
                    "assertion does not hold — the archive is not restorable. "
                    "Drills that could not run at all (destination unreachable) "
                    "are NOT covered; those are infrastructure faults, not "
                    "findings about the backup. Auto-resolves when the target's "
                    "next drill passes."
                ),
                rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
                severity="critical",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_dns_tunneling_alert_rule() -> None:
    """Seed the ``dns_tunneling_suspected`` rule (#699), ENABLED.

    Enabled is safe here despite the severity: the matcher reads
    ``dns_client_window``, which only has rows when the default-off
    ``security.dns_threat`` module is on AND a DNS group has query
    logging enabled. On an install that hasn't opted into either, the
    rule matches nothing and costs one indexed query per tick. An
    operator who turned both on wants to hear the answer.

    Keyed on ``rule_type``; an operator who disables, renames or
    re-thresholds it is never overridden.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_DNS_TUNNELING)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="DNS tunneling suspected",
                description=(
                    "Fires when a client's DNS behaviour scores above the tunneling "
                    "threshold — long high-entropy labels, many unique subdomains "
                    "under one parent domain, and payload-bearing qtypes, sustained "
                    "over an hour. This is the shape of iodine / dnscat2-style "
                    "exfiltration, which firewalls do not inspect. Subject is the "
                    "client IP; auto-resolves when recent windows fall back below "
                    "the threshold. Requires the security.dns_threat module and "
                    "query logging on a DNS server group."
                ),
                rule_type=RULE_TYPE_DNS_TUNNELING,
                severity="critical",
                enabled=True,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_dns_beaconing_alert_rule() -> None:
    """Seed ``dns_beaconing_suspected`` (#699), DISABLED by default.

    The opposite call from the tunneling rule, and deliberately so. A
    health check every 30 s is beaconing by any timing measure and
    scores ~100, so on a typical network this fires on the operator's
    own monitoring the moment it is armed. It becomes genuinely useful
    once they have muted their known pollers — which is what the mute
    workflow is for — but shipping it pre-armed would train people to
    ignore it, and an ignored detector is worse than none.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_DNS_BEACONING)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="DNS beaconing suspected",
                description=(
                    "Fires when a client queries one name on a metronomic "
                    "cadence — the rhythm of a C2 callback. Disabled by "
                    "default: legitimate pollers (monitoring agents, health "
                    "checks, update checkers) are indistinguishable from a "
                    "beacon by timing alone and score just as high. Enable "
                    "after muting your known pollers from the DNS Threat tab. "
                    "Requires the security.dns_threat module and query logging."
                ),
                rule_type=RULE_TYPE_DNS_BEACONING,
                severity="warning",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


async def seed_dns_dga_alert_rule() -> None:
    """Seed ``dns_dga_suspected`` (#699), DISABLED by default.

    Disabled for a reason specific to this detection rather than
    beaconing's. The issue specified scoring NXDOMAIN-heavy clients;
    the BIND9 query log carries no rcode, so the score rests on name
    plausibility alone. That is a weaker basis than tunneling's four
    independent signals, and hashed-CDN buckets, shortlink services and
    any brand that bought a consonant cluster all share the shape. It
    wants an operator who has looked at their own baseline on the DNS
    Threat tab first — which is exactly what leaving it disarmed
    encourages.
    """
    from app.db import AsyncSessionLocal  # noqa: PLC0415
    from app.models.alerts import AlertRule  # noqa: PLC0415

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(
            select(AlertRule).where(AlertRule.rule_type == RULE_TYPE_DNS_DGA)
        )
        if existing is not None:
            return
        session.add(
            AlertRule(
                name="DNS DGA suspected",
                description=(
                    "Fires when a client queries a crop of "
                    "algorithmically-generated domain names — how malware "
                    "finds its command-and-control server. Disabled by "
                    "default: scoring is on name plausibility alone (the "
                    "BIND9 query log carries no rcode, so there is no "
                    "NXDOMAIN prior), and hashed-CDN and shortlink traffic "
                    "shares the shape. Review your baseline on the DNS "
                    "Threat tab before enabling. Requires the "
                    "security.dns_threat module and query logging."
                ),
                rule_type=RULE_TYPE_DNS_DGA,
                severity="warning",
                enabled=False,
                notify_syslog=True,
                notify_webhook=True,
                notify_smtp=False,
            )
        )
        await session.commit()


# #1068 — rules that are meaningless without their subsystem. Checked once
# per pass in ``evaluate_all`` rather than inside 50 evaluators.
#
# Mostly this saves work rather than changing outcomes: disabling
# ``core.dhcp`` is refused while any DHCP server or scope exists, so by the
# time the module is off these evaluators have no rows to match anyway.
# Making it explicit keeps a disabled subsystem from running queries on
# every 60 s tick, and says in one place which rules belong to what.
#
# ``rogue_dhcp`` is deliberately NOT listed either, and it is the one
# entry where that needed arguing. Its subject rows keep arriving —
# ``/dhcp/agents/dhcp-offers`` is on the ungated agent router — and the
# rule matters MOST to an install that does not run DHCP, where any
# server answering DHCP is by definition unauthorised. The drill-down
# page does 404 with the module off, which is the cost; an alert whose
# message names the offending IP and MAC is still far better than
# silence. Revisit if the responders surface is ever lifted out of the
# gated router.
#
# Deliberately NOT listed: ``cluster_dns_degraded`` (CoreDNS inside k3s,
# nothing to do with the DNS subsystem SpatiumDDI serves),
# ``server_unreachable`` (one rule spanning dns_server, dhcp_server AND
# looking_glass_collector, so no single module owns it), and the
# ``domain_*`` registrar rules (a Domain is a registrar/RDAP record that
# outlives any zone we serve). The three ``dns_*_suspected`` rules and
# ``rogue_ra`` are keyed to their own modules, which in turn require the
# core module — so they resolve off either way.
_RULE_TYPE_MODULE: dict[str, str] = {
    RULE_TYPE_DHCP_POOL_EXHAUSTION: "core.dhcp",
    RULE_TYPE_DHCP_PACKETS_DROPPED: "core.dhcp",
    RULE_TYPE_DHCP_SCOPE_UNCOORDINATED: "core.dhcp",
    RULE_TYPE_VOICE_LEASE_COUNT_BELOW: "core.dhcp",
    RULE_TYPE_STALE_RESERVATION: "core.dhcp",
    RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE: "core.dhcp",
    RULE_TYPE_ROGUE_RA: "ipv6.router_advertisements",
    RULE_TYPE_DNS_NXDOMAIN_SPIKE: "core.dns",
    RULE_TYPE_DNS_QUERY_RATE_SPIKE: "core.dns",
    RULE_TYPE_DNS_RATE_LIMIT_DROPPING: "core.dns",
    RULE_TYPE_DNS_TUNNELING: "security.dns_threat",
    RULE_TYPE_DNS_BEACONING: "security.dns_threat",
    RULE_TYPE_DNS_DGA: "security.dns_threat",
}


async def evaluate_all(db: AsyncSession) -> dict[str, int]:
    """Evaluate every enabled rule; open / resolve events as needed.

    Returns a summary dict for the scheduled-task audit row: opened,
    resolved, delivered_syslog, delivered_webhook. Per-rule failures are
    logged but don't abort the pass — one broken rule shouldn't silence
    the rest.
    """
    settings = await db.get(PlatformSettings, 1)
    targets = await audit_forward._load_targets()  # noqa: SLF001

    # Alerts have their own enabled toggle per rule; we still rely on
    # audit-forward's target table for actual delivery. With no targets
    # configured the event is recorded but goes nowhere — still visible
    # in the /alerts UI.
    now = datetime.now(UTC)

    opened = 0
    resolved = 0
    delivered_syslog = 0
    delivered_webhook = 0
    delivered_smtp = 0

    res = await db.execute(select(AlertRule).where(AlertRule.enabled.is_(True)))
    rules = list(res.scalars().all())
    # #1068 — resolved once per pass, not per rule (it is a cached read, but
    # the loop can be long and the answer cannot change mid-pass).
    enabled_modules = await feature_modules.get_enabled_modules(db)
    for rule in rules:
        try:
            # Each match tuple is (subject_id, display, message,
            # severity_override). Threshold-style rules pass
            # severity_override=None so the rule's own severity
            # applies; ``domain_expiring`` overrides per-row based on
            # how close the actual expiry is.
            matches: list[tuple[str, str, str, str | None]] = []
            subject_type = ""

            required = _RULE_TYPE_MODULE.get(rule.rule_type)
            module_off = required is not None and required not in enabled_modules

            if module_off:
                # #1068 — deliberately NOT ``continue``. Falling through with
                # an empty match set lets the common open/resolve logic below
                # close whatever this rule still has open. A ``continue`` here
                # skips that too, so a DHCP pool-exhaustion event that was
                # firing when the operator switched DHCP off would stay open
                # forever, with no evaluator left that could ever close it —
                # a permanently red dashboard for a subsystem that is gone.
                # ``subject_type`` stays unused: it is only read inside the
                # match loop, which does not run.
                pass
            elif rule.rule_type == RULE_TYPE_SUBNET_UTILIZATION:
                base = await _matching_subnet_subjects(db, rule, settings)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "subnet"
            elif rule.rule_type == RULE_TYPE_VOICE_LEASE_COUNT_BELOW:
                base = await _matching_voice_lease_count_below_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "subnet"
            elif rule.rule_type == RULE_TYPE_STALE_IP_COUNT:
                base = await _matching_stale_ip_count_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "subnet"
            elif rule.rule_type == RULE_TYPE_DHCP_POOL_EXHAUSTION:
                base = await _matching_dhcp_pool_exhaustion_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dhcp_pool"
            elif rule.rule_type == RULE_TYPE_DNS_NXDOMAIN_SPIKE:
                base = await _matching_dns_nxdomain_spike_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dns_server"
            elif rule.rule_type == RULE_TYPE_DNS_QUERY_RATE_SPIKE:
                base = await _matching_dns_query_rate_spike_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dns_server"
            elif rule.rule_type == RULE_TYPE_DHCP_PACKETS_DROPPED:
                base = await _matching_dhcp_packets_dropped_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dhcp_server"
            elif rule.rule_type == RULE_TYPE_DNS_RATE_LIMIT_DROPPING:
                base = await _matching_dns_rate_limit_dropping_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dns_server"
            elif rule.rule_type == RULE_TYPE_IP_FREE_BUT_RESPONDING:
                base = await _matching_ip_free_but_responding_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "ip_address"
            elif rule.rule_type == RULE_TYPE_STALE_RESERVATION:
                base = await _matching_stale_reservation_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "ip_address"
            elif rule.rule_type == RULE_TYPE_UNKNOWN_MAC_IN_STATIC_RANGE:
                base = await _matching_unknown_mac_in_static_range_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "ip_address"
            elif rule.rule_type == RULE_TYPE_ROGUE_DHCP:
                base = await _matching_rogue_dhcp_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dhcp_responder"
            elif rule.rule_type == RULE_TYPE_ROGUE_RA:
                base = await _matching_rogue_ra_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "ra_router"
            elif rule.rule_type == RULE_TYPE_WOL_WAKE_FAILED:
                base = await _matching_wol_wake_failed_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "wol_schedule"
            elif rule.rule_type == RULE_TYPE_RESTORE_DRILL_FAILED:
                base = await _matching_restore_drill_failed_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "backup_target"
            elif rule.rule_type == RULE_TYPE_DNS_TUNNELING:
                base = await _matching_dns_tunneling_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dns_client"
            elif rule.rule_type == RULE_TYPE_DNS_BEACONING:
                base = await _matching_dns_beaconing_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dns_client"
            elif rule.rule_type == RULE_TYPE_DNS_DGA:
                base = await _matching_dns_dga_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "dns_client"
            elif rule.rule_type == RULE_TYPE_NEW_MAC_SEEN:
                base = await _matching_new_mac_seen_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "ip_mac_observation"
            elif rule.rule_type == RULE_TYPE_SERVER_UNREACHABLE:
                base = await _matching_server_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "server"
            elif rule.rule_type == RULE_TYPE_ASN_HOLDER_DRIFT:
                matches = await _matching_asn_drift_subjects(db, rule)
                subject_type = "asn"
            elif rule.rule_type == RULE_TYPE_ASN_WHOIS_UNREACHABLE:
                matches = await _matching_asn_unreachable_subjects(db, rule)
                subject_type = "asn"
            elif rule.rule_type == RULE_TYPE_RPKI_ROA_EXPIRING:
                matches = await _matching_rpki_roa_expiring_subjects(db, rule)
                subject_type = "rpki_roa"
            elif rule.rule_type == RULE_TYPE_RPKI_ROA_EXPIRED:
                matches = await _matching_rpki_roa_expired_subjects(db, rule)
                subject_type = "rpki_roa"
            elif rule.rule_type == RULE_TYPE_BGP_PREFIX_HIJACK:
                matches = await _matching_bgp_hijack_subjects(db, rule, "prefix_hijack")
                subject_type = "bgp_hijack"
            elif rule.rule_type == RULE_TYPE_BGP_MORE_SPECIFIC:
                matches = await _matching_bgp_hijack_subjects(db, rule, "more_specific")
                subject_type = "bgp_hijack"
            elif rule.rule_type == RULE_TYPE_BGP_LG_SESSION_DOWN:
                base = await _matching_bgp_lg_session_down_subjects(db, rule, now)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "bgp_lg_peer"
            elif rule.rule_type == RULE_TYPE_BGP_LG_RPKI_INVALID_ROUTE:
                matches = await _matching_bgp_lg_rpki_invalid_route_subjects(db, rule)
                subject_type = "bgp_lg_route"
            elif rule.rule_type == RULE_TYPE_BGP_LG_UNEXPECTED_ORIGIN:
                base = await _matching_bgp_lg_unexpected_origin_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "bgp_lg_route"
            elif rule.rule_type == RULE_TYPE_BGP_LG_MORE_SPECIFIC:
                base = await _matching_bgp_lg_more_specific_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "bgp_lg_route"
            elif rule.rule_type == RULE_TYPE_BGP_LG_ROUTE_FLAP:
                base = await _matching_bgp_lg_route_flap_subjects(db, rule, now)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "bgp_lg_route"
            elif rule.rule_type == RULE_TYPE_BGP_LG_MISSING_ADVERTISEMENT:
                base = await _matching_bgp_lg_missing_advertisement_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in base]
                subject_type = "subnet"
            elif rule.rule_type == RULE_TYPE_DOMAIN_EXPIRING:
                expiring = await _matching_domain_expiring_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in expiring]
                subject_type = "domain"
            elif rule.rule_type == RULE_TYPE_DOMAIN_NS_DRIFT:
                drift = await _matching_domain_drift_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in drift]
                subject_type = "domain"
            elif rule.rule_type == RULE_TYPE_CIRCUIT_TERM_EXPIRING:
                expiring = await _matching_circuit_term_expiring_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in expiring]
                subject_type = "circuit"
            elif rule.rule_type == RULE_TYPE_K3S_API_CERT_EXPIRING:
                expiring = await _matching_k3s_api_cert_expiring_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in expiring]
                subject_type = "appliance"
            elif rule.rule_type == RULE_TYPE_SECRET_EXPIRING:
                expiring = await _matching_secret_expiring_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in expiring]
                subject_type = "secret"
            elif rule.rule_type == RULE_TYPE_NODE_PRESSURE:
                pressured = await _matching_node_pressure_subjects(db, rule)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in pressured]
                # Subject is the Kubernetes node NAME — cluster nodes have no
                # row in this database, and the name is what every other
                # surface (Cluster screen, kubectl, the Fleet drilldown)
                # identifies them by.
                subject_type = "node"
            elif rule.rule_type == RULE_TYPE_CLUSTER_DNS_DEGRADED:
                degraded = await _matching_cluster_dns_subjects(db, rule)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in degraded]
                # Subject is the cluster itself. CoreDNS is cluster-scoped —
                # there is no row and no single node it belongs to, and which
                # node a replica sits on is already in the message.
                subject_type = "cluster"
            elif rule.rule_type == RULE_TYPE_DHCP_SCOPE_UNCOORDINATED:
                uncoordinated = await _matching_dhcp_scope_uncoordinated_subjects(db, rule)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in uncoordinated]
                # A scope held on Windows need not have a SpatiumDDI row, so the
                # subject is "<group id>:<cidr>", not a dhcp_scope id.
                subject_type = "dhcp_scope"
            elif rule.rule_type == RULE_TYPE_AGENT_CONFIG_REJECTED:
                rejected = await _matching_agent_config_rejected_subjects(db, rule)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in rejected]
                # One rule spans three tables, so the subject_type is the
                # generic "agent" and the subject_id carries the source —
                # same shape ``secret_expiring`` uses for its two credential
                # tables. Without the prefix a dns_server and a dhcp_server
                # sharing a UUID would collide into one event.
                subject_type = "agent"
            elif rule.rule_type == RULE_TYPE_APPLIANCE_STORAGE_DEGRADED:
                storage_hits = await _matching_appliance_storage_subjects(db, rule)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in storage_hits]
                subject_type = "appliance"
            elif rule.rule_type == RULE_TYPE_FIREWALL_APPLY_STALLED:
                stalled = await _matching_firewall_apply_stalled_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in stalled]
                subject_type = "appliance"
            elif rule.rule_type == RULE_TYPE_SERVICE_TERM_EXPIRING:
                expiring = await _matching_service_term_expiring_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in expiring]
                subject_type = "network_service"
            elif rule.rule_type == RULE_TYPE_DECOM_EXPIRING:
                expiring = await _matching_decom_expiring_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in expiring]
                subject_type = "subnet"
            elif rule.rule_type == RULE_TYPE_TLS_CERT_EXPIRING:
                expiring = await _matching_tls_cert_expiring_subjects(db, rule, now)
                matches = [(sid, disp, msg, sev) for sid, disp, msg, sev in expiring]
                subject_type = "tls_cert"
            elif rule.rule_type == RULE_TYPE_TLS_CERT_CHAIN_INVALID:
                invalid = await _matching_tls_cert_chain_invalid_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in invalid]
                subject_type = "tls_cert"
            elif rule.rule_type == RULE_TYPE_TLS_CERT_UNREACHABLE:
                down = await _matching_tls_cert_unreachable_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in down]
                subject_type = "tls_cert"
            elif rule.rule_type == RULE_TYPE_TLS_CERT_CHANGED:
                # Transition-once — latches the fingerprint pair + auto-resolves.
                op_, res_, dsy, dwh, dsm = await _evaluate_tls_cert_transition_rule(
                    db, rule, now, value_attr="fingerprint_sha256", what="fingerprint"
                )
                opened += op_
                resolved += res_
                delivered_syslog += dsy
                delivered_webhook += dwh
                delivered_smtp += dsm
                continue
            elif rule.rule_type == RULE_TYPE_TLS_CERT_ISSUER_CHANGED:
                # Transition-once on the issuing CA — cert-rotation deviation.
                op_, res_, dsy, dwh, dsm = await _evaluate_tls_cert_transition_rule(
                    db, rule, now, value_attr="issuer_cn", what="issuer"
                )
                opened += op_
                resolved += res_
                delivered_syslog += dsy
                delivered_webhook += dwh
                delivered_smtp += dsm
                continue
            elif rule.rule_type == RULE_TYPE_IP_BLOCKLISTED:
                listed_ips = await _matching_ip_blocklisted_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in listed_ips]
                subject_type = "ip_blocklist"
            elif rule.rule_type == RULE_TYPE_SERVICE_RESOURCE_ORPHANED:
                orphans = await _matching_service_resource_orphaned_subjects(db, rule)
                matches = [(sid, disp, msg, None) for sid, disp, msg in orphans]
                subject_type = "network_service_resource"
            elif rule.rule_type == RULE_TYPE_CIRCUIT_STATUS_CHANGED:
                # Transition-style rule with its own evaluator that
                # latches ``(from, to, changed_at)`` snapshots and
                # auto-resolves after ``_TRANSITION_AUTO_RESOLVE_DAYS``.
                op_, res_, dsy, dwh, dsm = await _evaluate_circuit_status_changed_rule(
                    db, rule, now
                )
                opened += op_
                resolved += res_
                delivered_syslog += dsy
                delivered_webhook += dwh
                delivered_smtp += dsm
                continue
            elif rule.rule_type == RULE_TYPE_COMPLIANCE_CHANGE:
                # Audit-log-driven; opens one event per matching audit
                # row with its own auto-resolve window. Watermark stored
                # on the rule itself.
                op_, res_, dsy, dwh, dsm = await _evaluate_compliance_change_rule(db, rule, now)
                opened += op_
                resolved += res_
                delivered_syslog += dsy
                delivered_webhook += dwh
                delivered_smtp += dsm
                continue
            elif rule.rule_type in (
                RULE_TYPE_DOMAIN_REGISTRAR_CHANGED,
                RULE_TYPE_DOMAIN_DNSSEC_CHANGED,
            ):
                # Transition-once rules don't fit the open/resolve
                # symmetry — they have their own evaluator that
                # latches snapshots into AlertEvent.last_observed_value
                # and auto-resolves after _TRANSITION_AUTO_RESOLVE_DAYS.
                field_name, label = (
                    ("registrar", "registrar")
                    if rule.rule_type == RULE_TYPE_DOMAIN_REGISTRAR_CHANGED
                    else ("dnssec_signed", "DNSSEC status")
                )
                op_, res_, dsy, dwh, dsm = await _evaluate_domain_transition_rule(
                    db,
                    rule,
                    field_name=field_name,
                    rule_label=label,
                    now=now,
                )
                opened += op_
                resolved += res_
                delivered_syslog += dsy
                delivered_webhook += dwh
                delivered_smtp += dsm
                continue
            elif rule.rule_type == RULE_TYPE_AUDIT_CHAIN_BROKEN:
                # Externally driven — the dedicated
                # ``app.tasks.audit_chain_verify.verify_audit_chain``
                # Celery task creates / resolves AlertEvent rows for
                # this rule on its own schedule (nightly + on-demand).
                # The general evaluator just silently passes; without
                # this branch the warning loop spammed once per
                # 60s tick.
                continue
            else:
                logger.warning("alert_unknown_rule_type", rule=str(rule.id), type=rule.rule_type)
                continue

            # Index current open events by subject_id for this rule.
            open_res = await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id,
                    AlertEvent.resolved_at.is_(None),
                )
            )
            open_events = list(open_res.scalars().all())
            open_by_subject = {ev.subject_id: ev for ev in open_events}

            match_ids = {sid for sid, _, _, _ in matches}

            # Open new events for unseen matches; escalate existing ones.
            for subject_id, display, message, severity_override in matches:
                existing = open_by_subject.get(subject_id)
                if existing is not None:
                    # Subject is already open. For the *_expiring rule
                    # family the matcher recomputes a per-row severity
                    # every tick that climbs info → warning → critical as
                    # the expiry date nears (issue #46). Bump the open
                    # event and re-deliver when that severity is *higher*
                    # than what's already recorded — never downgrade and
                    # never re-deliver on an unchanged severity (avoids
                    # 60 s notification spam). Non-escalating rules pass a
                    # stable severity, so the rank compare never trips and
                    # they're left untouched.
                    new_severity = severity_override or rule.severity
                    if _severity_rank(new_severity) > _severity_rank(existing.severity):
                        existing.severity = new_severity
                        existing.message = message
                        ds, dw, dm = await _deliver(rule, existing, targets)
                        # OR-in: a channel that delivered on open should
                        # stay flagged even if a later escalation skips it.
                        existing.delivered_syslog = existing.delivered_syslog or ds
                        existing.delivered_webhook = existing.delivered_webhook or dw
                        existing.delivered_smtp = existing.delivered_smtp or dm
                        if ds:
                            delivered_syslog += 1
                        if dw:
                            delivered_webhook += 1
                        if dm:
                            delivered_smtp += 1
                    continue
                event = AlertEvent(
                    rule_id=rule.id,
                    subject_type=subject_type,
                    subject_id=subject_id,
                    subject_display=display,
                    severity=severity_override or rule.severity,
                    message=message,
                    fired_at=now,
                )
                db.add(event)
                await db.flush()  # populate event.id for delivery payload
                ds, dw, dm = await _deliver(rule, event, targets)
                event.delivered_syslog = ds
                event.delivered_webhook = dw
                event.delivered_smtp = dm
                opened += 1
                if ds:
                    delivered_syslog += 1
                if dw:
                    delivered_webhook += 1
                if dm:
                    delivered_smtp += 1

            # Resolve open events whose subject no longer matches.
            for subject_id, event in open_by_subject.items():
                if subject_id in match_ids:
                    continue
                event.resolved_at = now
                resolved += 1
        except AlertDataUnavailable as exc:
            # Not a failure worth a traceback, and deliberately not treated as
            # "no matches": open events stay open, nothing new opens, and the
            # next tick with real data decides. Logged at info because during
            # a genuine outage this fires every 60 s.
            logger.info(
                "alert_rule_eval_skipped_no_data",
                rule=str(rule.id),
                rule_type=rule.rule_type,
                reason=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "alert_rule_eval_failed",
                rule=str(rule.id),
                rule_type=rule.rule_type,
                error=str(exc),
            )

    await db.commit()
    return {
        "opened": opened,
        "resolved": resolved,
        "delivered_syslog": delivered_syslog,
        "delivered_webhook": delivered_webhook,
        "delivered_smtp": delivered_smtp,
    }
