"""Backup-section catalog (issue #117 Phase 2a).

Maps every table in the schema to a logical section. Used by:

* The backup endpoint — operators tick which sections to include
  in a partial / "diagnostic" backup (Phase 2b).
* The restore endpoint — operators tick which sections to apply,
  leaving the rest untouched (selective restore — Phase 2b).
* Future factory-reset feature — the same catalog drives "wipe
  this section back to defaults".

The catalog is the single source of truth for these three flows.
Adding a new table that needs to be backed up means adding it to
the right :class:`Section` here. Forgetting to do so means the
table is silently excluded from selective backups + restores —
:func:`assert_catalog_covers_models` reports this, from the api's startup
hook and from the test suite (see its docstring).

Membership is not the whole story for restore, though: a selective
restore TRUNCATEs CASCADE, which reaches every table holding a foreign
key into a selected one whether or not it is catalogued. That set is
computed from the FK graph by :func:`cascade_closure`, and restored
alongside the selection so the difference isn't silently deleted (#781).

Design notes:

* Sections are intentionally coarse (8–10 sections, not per-table).
  Operators want to think in terms of "DNS" / "DHCP" / "IPAM",
  not 70 individual tables. Internal grouping inside a section
  doesn't matter — the catalog just declares membership.
* ``volatile = True`` sections are excluded from a default backup
  but can be opted into for a "diagnostic" snapshot. These are
  things like DHCP leases (re-syncs on next agent poll), the
  query/activity logs (short retention), nmap scan history
  (regenerable), and metric samples.
* ``alembic_version``, ``oui_vendor`` and ``tld_registry_snapshot`` are
  platform-housekeeping tables — they live in their own
  ``platform_internal`` section.
  ``alembic_version`` is technically not user data; restoring
  from an older snapshot re-pins the schema head and the
  upgrade-on-restore path (Phase 2b) walks it forward.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Section:
    key: str
    label: str
    description: str
    tables: tuple[str, ...]
    #: True when this section's data is regenerable / short-lived
    #: and can be safely excluded from a backup or restore. The
    #: default backup excludes volatile sections; operators tick
    #: them on for a diagnostic snapshot.
    volatile: bool = False
    #: Whether the section is selectable independently of the
    #: rest. Some sections (``platform_internal`` — alembic head,
    #: OUI cache) only make sense as part of a full restore so we
    #: render the checkbox disabled.
    selectable: bool = True


SECTIONS: tuple[Section, ...] = (
    Section(
        key="auth",
        label="Authentication",
        description=(
            "Users, groups, roles, sessions, API tokens, external "
            "auth providers + group mappings, MFA. Restoring this "
            "without the related resources leaves owner_id columns "
            "pointing at users that don't exist in the destination."
        ),
        tables=(
            "user",
            "group",
            "role",
            "user_group",
            "group_role",
            "user_session",
            "api_token",
            "auth_provider",
            "auth_group_mapping",
        ),
    ),
    Section(
        key="audit",
        label="Audit & forwarding",
        description=(
            "Append-only audit log + the syslog / webhook / chat "
            "forwarding-target rows that fan it out. Restoring "
            "audit also restores the tamper-evidence chain "
            "(seq + row_hash + prev_hash) from the source install."
        ),
        tables=("audit_log", "audit_forward_target"),
    ),
    Section(
        key="settings",
        label="Platform settings & RBAC scaffolding",
        description=(
            "Platform-wide settings, branding assets, custom field "
            "definitions, IPAM templates, feature-module toggles, alert "
            "rules + events, conformity policies + results, platform-wide "
            "tags, event subscriptions + outbox, InfluxDB export targets."
        ),
        tables=(
            "platform_settings",
            # The operator-uploaded logo (#886). Belongs with settings
            # rather than in its own section: it is branding config that
            # happens to be bytes, and restoring the banner text without
            # the logo it sits beside would be a half-restore.
            "branding_asset",
            "custom_field_definition",
            "feature_module",
            "ipam_template",
            "alert_rule",
            "alert_event",
            "conformity_policy",
            "conformity_result",
            "event_subscription",
            "event_outbox",
            # #889. Configuration, not sample data — so it belongs here
            # and NOT in the volatile ``metrics`` section, which is
            # excluded from the default backup. A target whose Fernet
            # columns survive a cross-install restore but whose row does
            # not is the same silent failure from the other direction.
            "influxdb_target",
        ),
    ),
    Section(
        key="ownership",
        label="Customers / Sites / Providers",
        description=(
            "Logical-ownership entities cross-referenced from "
            "IPAM / DNS / DHCP / Network rows. Restoring the rest "
            "without these would leave customer_id / site_id / "
            "provider_id columns dangling."
        ),
        tables=("customer", "site", "provider"),
    ),
    Section(
        key="network_modeling",
        label="Network modeling (ASN / VRF / circuits / overlays)",
        description=(
            "ASNs (with their RPKI ROAs + BGP peerings + "
            "communities), VRFs, WAN circuits, overlay networks + "
            "sites + routing policies, the SaaS application "
            "catalog, network services + their resource bindings, "
            "domain registrations + DNS-zone↔domain links."
        ),
        tables=(
            "asn",
            "asn_rpki_roa",
            "bgp_community",
            "bgp_peering",
            "vrf",
            "circuit",
            "network_service",
            "network_service_resource",
            "overlay_network",
            "overlay_site",
            "routing_policy",
            "application_category",
            "domain",
            "subnet_domain",
        ),
    ),
    Section(
        key="ipam",
        label="IPAM (spaces / blocks / subnets / IPs / VLANs)",
        description=(
            "The core IPAM hierarchy plus VLAN catalog, NAT "
            "mappings, IP↔MAC history, and the subnet-planner "
            "scratch table. References Auth (owner / modified-by), "
            "Ownership, Network-modeling (ASN / VRF), DNS (primary "
            "zone)."
        ),
        tables=(
            "ip_space",
            "ip_block",
            "subnet",
            "ip_address",
            "vlan",
            "vlan_mapping",
            "nat_mapping",
            "ip_mac_history",
            "subnet_plan",
        ),
    ),
    Section(
        key="verticals",
        label="Vertical network awareness (multicast / AV / BACnet / OT / DICOM / E911)",
        description=(
            "The multicast stream registry (groups + PIM domains + "
            "ports + memberships) and the vertical descriptors layered "
            "on it: AV-over-IP flow profiles + reserved ranges "
            "(Dante / AES67 / SMPTE 2110), BACnet/IP devices with "
            "their internetwork-unique device instance numbers and "
            "BBMD tables, industrial-OT devices + Purdue zoning, and "
            "the DICOM AE Title registry with its configured "
            "peer-association map, and the E911 Emergency Response "
            "Locations + their network bindings. "
            "References IPAM (space / subnet / address) and VLANs. "
            "NOTE: E911 bindings reference network_interface / subnet / "
            "vlan / ip_address / site with ON DELETE CASCADE, so a "
            "selective restore that rewinds IPAM or ownership without "
            "this section leaves the dispatchable locations gone — which "
            "is why they are catalogued here rather than left "
            "unclassified."
        ),
        tables=(
            "multicast_domain",
            "multicast_group",
            "multicast_group_port",
            "multicast_membership",
            "av_flow_profile",
            "av_reserved_range",
            "bacnet_device",
            "ot_device",
            "ot_zone",
            "dicom_ae",
            "dicom_peer",
            "emergency_response_location",
            "erl_binding",
            "e911_resolution_log",
        ),
    ),
    Section(
        key="dns",
        label="DNS (groups / servers / zones / records / pools)",
        description=(
            "DNS server groups + server members, zones, records, "
            "views, ACLs, blocklists + entries + exceptions, DNS "
            "GSLB pools + members, TSIG keys, trust anchors, "
            "per-server zone-state + runtime state, server "
            "options, record-ops queue. NOTE for PowerDNS-driver "
            "groups: DNSSEC signing keys live in the agent's LMDB "
            "store on its persistent volume — they are NOT inside "
            "this archive. Restoring DNSSEC-enabled PowerDNS zones "
            "to a fresh agent regenerates the keys and produces "
            "new DS records, which must be re-published to the "
            "parent registrar. The restore endpoint surfaces this "
            "as a warning when applicable."
        ),
        tables=(
            "dns_server_group",
            "dns_server",
            "dns_server_options",
            "dns_server_runtime_state",
            "dns_server_zone_state",
            # #1111 — the per-server stored config bundle (bytes + the dirty
            # watermark it was rendered at); cascades from dns_server, so it
            # restores and truncates with the server it belongs to.
            "dns_agent_bundle",
            "dns_zone",
            "dns_record",
            "dns_view",
            "dns_acl",
            "dns_acl_entry",
            "dns_blocklist",
            "dns_blocklist_entry",
            "dns_blocklist_exception",
            "dns_blocklist_group_assoc",
            "dns_blocklist_view_assoc",
            "dns_pool",
            "dns_pool_member",
            "dns_tsig_key",
            "dns_trust_anchor",
            "dns_record_op",
        ),
    ),
    Section(
        key="dhcp",
        label="DHCP (groups / servers / scopes / statics / classes)",
        description=(
            "DHCP server groups + server members, scopes + pools "
            "+ static assignments + client classes, option "
            "templates, MAC blocklists, PXE profiles + arch "
            "matches, phone profiles + scope bindings, "
            "fingerprint catalog, config-ops queue."
        ),
        tables=(
            "dhcp_server_group",
            "dhcp_server",
            "dhcp_scope",
            "dhcp_pool",
            "dhcp_static_assignment",
            "dhcp_client_class",
            "dhcp_option_template",
            "dhcp_mac_block",
            "dhcp_pxe_profile",
            "dhcp_pxe_arch_match",
            "dhcp_phone_profile",
            "dhcp_phone_profile_scope",
            # #700 — FKs into dhcp_server_group, so a selective restore of
            # this section TRUNCATE-CASCADEs it. Absent from the list, it
            # would be emptied and never repopulated.
            "dhcp_device_policy",
            "dhcp_fingerprint",
            "dhcp_config_op",
        ),
    ),
    Section(
        key="migration",
        label="Migration (Windows cutover plans)",
        description=(
            "Windows → SpatiumDDI cutover plans, their per-zone / "
            "per-scope items (parity + shadow reports, pre-flight TTL "
            "snapshots, lease-handover results), the decommission "
            "checklist, and the plan timeline. Its own section rather "
            "than a DNS or DHCP one because a single plan spans both. "
            "The zones, scopes and reservations a plan points at are "
            "owned by the DNS / DHCP sections — this is the "
            "bookkeeping around them, and the pre-flight TTL snapshot "
            "is the only copy of the pre-migration TTLs, so a restore "
            "without it loses the ability to roll a cutover back."
        ),
        tables=(
            "cutover_plan",
            "cutover_item",
            "cutover_checklist_item",
            "cutover_event",
        ),
    ),
    Section(
        key="integrations",
        label="Integrations + network discovery",
        description=(
            "K8s / Docker / Proxmox / Tailscale / UniFi mirrors, "
            "SNMP-discovered network devices + interfaces + "
            "ARP / FDB / neighbour caches, routers + their zone "
            "links, ACME accounts."
        ),
        tables=(
            "kubernetes_cluster",
            "docker_host",
            "proxmox_node",
            "tailscale_tenant",
            "unifi_controller",
            "network_device",
            "network_interface",
            "network_arp_entry",
            "network_fdb_entry",
            "network_neighbour",
            "router",
            "router_zone",
            "acme_account",
        ),
    ),
    Section(
        key="ai",
        label="Operator Copilot (providers / sessions / prompts)",
        description=(
            "AI providers, chat sessions + messages, saved " "prompts, write-operation proposals."
        ),
        tables=(
            "ai_provider",
            "ai_chat_session",
            "ai_chat_message",
            "ai_prompt",
            "ai_operation_proposal",
        ),
    ),
    Section(
        key="backup_self",
        label="Backup (self-reference)",
        description=(
            "Backup-target rows themselves. Restoring this "
            "section onto a different install carries over the "
            "scheduled-destination configs — make sure those "
            "secrets are re-applicable on the destination."
        ),
        tables=("backup_target",),
    ),
    Section(
        key="diagnostics",
        label="Diagnostics (captured exceptions)",
        description=(
            "Captured uncaught Python exceptions (issue #123). "
            "Self-managed via daily prune; safe to skip on a "
            "diagnostic-snapshot backup."
        ),
        tables=("internal_error",),
        volatile=True,
    ),
    Section(
        key="logs",
        label="Logs (DNS query / DHCP activity)",
        description=(
            "Short-retention diagnostic logs — DNS query log + "
            "DHCP Kea activity log. Volatile by design (24 h "
            "retention via prune sweep). Excluded from default "
            "backup; tick to include for a diagnostic snapshot."
        ),
        tables=("dns_query_log_entry", "dhcp_log_entry"),
        volatile=True,
    ),
    Section(
        key="dns_threat",
        label="DNS threat analytics",
        description=(
            "Per-client DNS tunneling rollups (issue #699). NOT "
            "volatile despite deriving from the 24 h query log: the "
            "whole point of the rollup is that the summary outlives "
            "the raw lines, so a restore that dropped it would lose "
            "the only record that a host looked like an exfil tunnel "
            "last week. Includes the per-client mutes — losing those on "
            "restore would start paging about hosts an operator already "
            "reviewed and cleared."
        ),
        tables=("dns_client_window", "dns_threat_mute", "dns_rpz_hit"),
    ),
    Section(
        key="metrics",
        label="Metric samples",
        description=(
            "Per-server timeseries used by the dashboard charts. "
            "Volatile (7 d retention). Excluded from default "
            "backup; restoring this only matters when you need "
            "historical chart data after a disaster recovery."
        ),
        tables=("dns_metric_sample", "dhcp_metric_sample"),
        volatile=True,
    ),
    Section(
        key="leases",
        label="DHCP leases + history",
        description=(
            "Live lease table + lease-history audit. Volatile — "
            "Kea + Windows DHCP agents re-populate on next poll, "
            "so excluding this gives you a smaller archive without "
            "losing real state."
        ),
        tables=("dhcp_lease", "dhcp_lease_history"),
        volatile=True,
    ),
    Section(
        key="nmap_history",
        label="nmap scan history",
        description=(
            "Stored nmap scan results. Often huge on installs that "
            "schedule periodic sweeps; regenerable on demand. "
            "Excluded by default."
        ),
        tables=("nmap_scan",),
        volatile=True,
    ),
    Section(
        key="platform_internal",
        label="Platform internals (alembic head / reference caches)",
        description=(
            "Schema-version pin (``alembic_version``), the IEEE OUI "
            "vendor cache, and the refreshed IANA TLD list. These ride "
            "along with every restore — selective restore can't deselect "
            "them."
        ),
        # tld_registry_snapshot (#986) sits here for the same reason as
        # oui_vendor: it is an operator-refreshed copy of public reference
        # data, not their configuration. Losing it costs one click of
        # Refresh, and the list bundled with the release keeps working in
        # the meantime — but it is still restored rather than dropped, or
        # a restore would silently roll an install back to the bundled
        # list and relabel any zone on a recently-delegated TLD.
        tables=("alembic_version", "oui_vendor", "tld_registry_snapshot"),
        selectable=False,
    ),
)


SECTIONS_BY_KEY: dict[str, Section] = {s.key: s for s in SECTIONS}


def section_for_table(tablename: str) -> Section | None:
    """Return the section that owns ``tablename``, or ``None`` if
    no section claims it. ``None`` is the "this table is missing
    from the catalog" signal — the startup verifier raises on
    that.
    """
    for section in SECTIONS:
        if tablename in section.tables:
            return section
    return None


def all_section_tables() -> set[str]:
    return {table for section in SECTIONS for table in section.tables}


def tables_for_sections(keys: list[str]) -> list[str]:
    """Return the deduped union of every table claimed by any of
    ``keys``. Caller filters / orders before passing to pg_restore.
    """
    out: list[str] = []
    seen: set[str] = set()
    for key in keys:
        section = SECTIONS_BY_KEY.get(key)
        if section is None:
            continue
        for table in section.tables:
            if table not in seen:
                seen.add(table)
                out.append(table)
    return out


def cascade_closure(tables: Iterable[str]) -> set[str]:
    """Every table a ``TRUNCATE … CASCADE`` of ``tables`` would also empty.

    Postgres cascades a TRUNCATE to any table holding a foreign key into a
    truncated one, transitively. Selective restore truncates the selected
    sections' tables CASCADE and then repopulates **only those tables**, so
    without this the difference is silently deleted: measured on the shipped
    catalog, restoring ``auth`` alone cascades into 130 tables and refills
    11 (#781).

    Returned set INCLUDES the input, so callers can hand it straight to the
    truncate + ``pg_restore --table=`` pair and get a database consistent
    with the archive for everything the operation touched.

    Derived from mapped metadata rather than a hand-maintained list — the
    FK graph is the thing Postgres actually walks, and any hand-copy of it
    is one migration away from being wrong.
    """
    from app.models.base import Base  # noqa: PLC0415

    # parent table -> tables that FK into it (the ones CASCADE reaches).
    dependents: dict[str, set[str]] = {}
    for name, table in Base.metadata.tables.items():
        for fk in table.foreign_keys:
            parent = fk.column.table.name
            if parent != name:
                dependents.setdefault(parent, set()).add(name)

    out = set(tables)
    stack = list(out)
    while stack:
        for child in dependents.get(stack.pop(), ()):
            if child not in out:
                out.add(child)
                stack.append(child)
    return out


def assert_catalog_covers_models(known_tables: set[str]) -> list[str]:
    """Compare the catalog against the set of tables actually
    declared by the SQLAlchemy models. Returns a list of tables
    the catalog is missing — empty list = catalog is complete.

    Two callers, deliberately different in kind:

    * ``app.main._log_backup_section_catalog_gap`` logs the gap at api
      startup, so an operator can see it without running the test suite.
    * ``tests/test_rewrap_coverage.py`` pins today's gap against a frozen
      baseline, so a newly added table has to be classified or explicitly
      accepted rather than slipping in unnoticed.

    See #781 for why the currently-unclassified tables are a baseline
    rather than a fix.
    """
    catalog = all_section_tables()
    missing = sorted(known_tables - catalog)
    return missing


def default_backup_section_keys() -> list[str]:
    """Section keys included by default when no explicit selection
    is supplied. Skips ``volatile=True`` sections.
    """
    return [s.key for s in SECTIONS if not s.volatile]
