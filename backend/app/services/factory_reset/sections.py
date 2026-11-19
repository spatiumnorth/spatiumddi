"""Factory-reset section catalog (issue #116).

12 user-facing sections, mapped from the issue body. Each section
has:

* a stable ``key`` operators reference in the API + UI
* a human-readable ``label``
* a confirmation ``phrase`` the operator must re-type to commit
* a ``kind`` describing how the wipe runs:
  - ``truncate`` — wipes the declared tables. Never
    ``TRUNCATE … CASCADE`` (#1835): see :mod:`.fk_graph` — a table
    nothing outside the wipe references is truncated, the rest are
    ``DELETE``d so ``ON DELETE SET NULL`` keys null instead of
    emptying the referencing table. The bulk of sections.
  - ``auth_rbac`` — partial wipe that preserves the calling user's
    row, group memberships, role assignments, and the platform
    builtin roles.
  - ``settings_reset`` — UPDATE the singleton ``platform_settings``
    row to its defaults. Doesn't touch any other table.
* a ``tables`` list (for ``truncate`` kind) — what gets wiped.
* ``cascade_dependents`` — tables OUTSIDE ``tables`` whose rows a
  ``DELETE`` of ``tables`` removes through ``ON DELETE CASCADE`` keys
  (a row that cannot exist without its parent). The preview names
  them with counts; ``tests/test_factory_reset_fk_cascade.py`` fails
  when this list and the schema's foreign keys disagree, so a new
  CASCADE key cannot widen a reset without somebody declaring it.

Sections deliberately overlap in some places — e.g. DNS query log
is in both DNS and Observability logs. That's intentional: an
operator wiping DNS expects the query log to go too; an operator
wiping observability expects DNS data to stay. The wipe is
idempotent so the overlap is safe.

Tables NOT mentioned in any section are intentionally untouchable
by factory reset:

* ``alembic_version`` / ``oui_vendor`` — schema head + IEEE OUI
  cache. Wiping these would render the install unusable.
* ``backup_target`` — the backup-destination configs are the
  safety net. Wiping them mid-reset removes the restore path.
* ``feature_module`` — module enable/disable flags persist across
  resets so operators don't have to re-enable everything.
* ``event_outbox`` — in-flight webhook deliveries, not user data.
* ``internal_error`` — captured exception traces are diagnostic
  state, not configuration.
* ``audit_forward_target`` — keep operating the syslog / webhook /
  chat audit forwarders even when audit_log itself is wiped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# The "Everything" target is implemented as a synthetic section that
# expands to every other section's tables — see ALL_SECTION_KEY.
ALL_SECTION_KEY = "all"


@dataclass(frozen=True)
class FactorySection:
    key: str
    label: str
    description: str
    phrase: str
    kind: Literal["truncate", "auth_rbac", "settings_reset", "everything"]
    tables: tuple[str, ...] = field(default_factory=tuple)
    cascade_dependents: tuple[str, ...] = field(default_factory=tuple)


# Tables the ``auth_rbac`` section deletes from (partial deletes —
# see ``_execute_auth_rbac``) and the ones it removes through CASCADE.
AUTH_RBAC_TABLES: tuple[str, ...] = (
    "user_session",
    "api_token",
    "auth_group_mapping",
    "auth_provider",
    "group_role",
    "user_group",
    "group",
    "role",
    "user",
)
AUTH_RBAC_CASCADE_DEPENDENTS: tuple[str, ...] = (
    "ai_chat_message",
    "ai_chat_session",
    "ai_operation_proposal",
    "saved_view",
    "time_bound_grant",
)

# Sections in the order they'll render on the UI page. Sequence
# follows the issue body exactly.
FACTORY_SECTIONS: tuple[FactorySection, ...] = (
    FactorySection(
        key="ipam",
        label="IPAM",
        description=(
            "IP spaces, blocks, subnets, IP addresses, NAT mappings, "
            "VLANs, VRFs, ASNs, IPAM templates, custom-field "
            "definitions. DNS records and DHCP statics that point at "
            "an IP address are KEPT and their IP link cleared; "
            "but a DHCP scope cannot exist without its subnet, so "
            "the scopes, pools and static assignments of every "
            "subnet are removed with it (as are vertical-registry "
            "rows keyed on an address or subnet). The preview "
            "lists them. Refused while an integration, a network "
            "device or a multicast group still points at an IP "
            "space — reset Integrations / Vertical network awareness "
            "first, or run them together."
        ),
        phrase="DESTROY-IPAM",
        kind="truncate",
        tables=(
            "ip_address",
            "subnet_plan",
            "subnet",
            "ip_block",
            "ip_space",
            "nat_mapping",
            "vlan_mapping",
            "vlan",
            "vrf",
            "asn_rpki_roa",
            "bgp_peering",
            "bgp_community",
            "asn",
            "ipam_template",
            "custom_field_definition",
            "ip_mac_history",
        ),
        cascade_dependents=(
            "address_set",
            "av_reserved_range",
            "bacnet_device",
            "bgp_hijack_detection",
            "bgp_tracked_prefix",
            "dhcp_phone_profile_scope",
            "dhcp_pool",
            "dhcp_scope",
            "dhcp_static_assignment",
            "erl_binding",
            "multicast_membership",
            "ot_device",
            "ot_zone",
            "subnet_domain",
            "subnet_utilization_history",
        ),
    ),
    FactorySection(
        key="dns",
        label="DNS",
        description=(
            "DNS server groups, servers, zones, records, blocking "
            "lists, GSLB pools, TSIG keys, ACLs, DNS query log, "
            "trust anchors. The dns_record_op queue is also flushed. "
            "Zone-owned ACME accounts, DNSSEC keys and update ACLs "
            "go with their zones; IP addresses are kept."
        ),
        phrase="DESTROY-DNS",
        kind="truncate",
        tables=(
            "dns_record",
            "dns_record_op",
            "dns_pool_member",
            "dns_pool",
            "dns_blocklist_view_assoc",
            "dns_blocklist_group_assoc",
            "dns_blocklist_exception",
            "dns_blocklist_entry",
            "dns_blocklist",
            "dns_view",
            "dns_acl_entry",
            "dns_acl",
            "dns_zone",
            "dns_server_options",
            "dns_server_zone_state",
            "dns_ingest_snapshot",
            "dns_server_runtime_state",
            "dns_server",
            "dns_server_group",
            "dns_tsig_key",
            "dns_trust_anchor",
            "dns_query_log_entry",
            "dns_client_window",
            "dns_rpz_hit",
            "dns_threat_mute",
            "dns_metric_sample",
            "subnet_domain",
            "domain",
        ),
        cascade_dependents=(
            "acme_account",
            "dns_agent_bundle",
            "dns_zone_update_acl",
            "dnssec_key",
        ),
    ),
    FactorySection(
        key="dhcp",
        label="DHCP",
        description=(
            "DHCP server groups, servers, scopes, pools, static "
            "assignments, client classes, option templates, MAC "
            "blocks, PXE profiles, leases + lease history, the "
            "config-ops queue. Failover relationships, observed-"
            "responder rows and device policies hang off a server "
            "group and go with it; IP addresses and subnets are "
            "kept."
        ),
        phrase="DESTROY-DHCP",
        kind="truncate",
        tables=(
            "dhcp_lease_history",
            "dhcp_lease",
            "dhcp_static_assignment",
            "dhcp_pool",
            "dhcp_scope",
            "dhcp_phone_profile_scope",
            "dhcp_phone_profile",
            "dhcp_pxe_arch_match",
            "dhcp_pxe_profile",
            "dhcp_mac_block",
            "dhcp_option_template",
            "dhcp_client_class",
            "dhcp_server",
            "dhcp_server_group",
            "dhcp_log_entry",
            "dhcp_metric_sample",
            "dhcp_config_op",
            "dhcp_fingerprint",
        ),
        cascade_dependents=(
            "dhcp_device_policy",
            "dhcp_failover_relationship",
            "dhcp_observed_responder",
            "dhcp_responder_allowlist",
            "dhcp_server_scope_state",
            "ra_observed_router",
            "ra_router_allowlist",
        ),
    ),
    FactorySection(
        key="migration",
        label="Migration plans",
        description=(
            "Windows → SpatiumDDI cutover plans and everything hanging "
            "off them: per-zone / per-scope items with their parity and "
            "shadow reports, pre-flight TTL snapshots, lease-handover "
            "results, the decommission checklist, and the plan timeline. "
            "The zones, scopes and reservations the plans point at are "
            "NOT touched — only the migration bookkeeping is destroyed. "
            "Note that a plan's TTL snapshot is the only record of the "
            "pre-migration TTLs, so destroying an in-flight plan gives up "
            "the ability to roll its cutover back."
        ),
        phrase="DESTROY-MIGRATION-PLANS",
        kind="truncate",
        tables=(
            "cutover_event",
            "cutover_checklist_item",
            "cutover_item",
            "cutover_plan",
        ),
    ),
    FactorySection(
        key="network_modeling",
        label="Network modeling",
        description=(
            "Customers, sites, providers, services, circuits, "
            "overlays, routing policies, application catalog, "
            "network-service ↔ resource bindings."
        ),
        phrase="DESTROY-NETWORK-MODELING",
        kind="truncate",
        tables=(
            "network_service_resource",
            "network_service",
            "routing_policy",
            "overlay_site",
            "overlay_network",
            "circuit",
            "site",
            "customer",
            "provider",
            "application_category",
        ),
        cascade_dependents=("erl_binding",),
    ),
    FactorySection(
        key="integrations",
        label="Integrations",
        description=(
            "Kubernetes / Docker / Proxmox / Tailscale / UniFi "
            "endpoints + their mirrored network discovery rows "
            "(ARP, FDB, neighbours, interfaces, routers, ACME "
            "accounts). IPAM rows (blocks, subnets, addresses, "
            "zones, records) owned by an integration are removed "
            "with it; everything else in IPAM / DNS is kept."
        ),
        phrase="DESTROY-INTEGRATIONS",
        kind="truncate",
        tables=(
            "kubernetes_cluster",
            "docker_host",
            "proxmox_node",
            "tailscale_tenant",
            "unifi_controller",
            "cloud_endpoint",
            "fortinet_firewall",
            "meraki_org",
            "netbird_instance",
            "opnsense_router",
            "panos_firewall",
            "network_arp_entry",
            "network_fdb_entry",
            "network_neighbour",
            "network_interface",
            "network_device",
            "router_zone",
            "router",
            "acme_account",
        ),
        cascade_dependents=(
            "address_set",
            "bacnet_device",
            "dhcp_phone_profile_scope",
            "dhcp_pool",
            "dhcp_scope",
            "dhcp_static_assignment",
            "dns_pool",
            "dns_pool_member",
            "dns_ingest_snapshot",
            "dns_record",
            "dns_server_zone_state",
            "dns_zone",
            "dns_zone_update_acl",
            "dnssec_key",
            "erl_binding",
            "firewall_endpoint_object",
            "ip_address",
            "ip_block",
            "ip_mac_history",
            "multicast_membership",
            "nat_mapping",
            "ot_device",
            "ot_zone",
            "subnet",
            "subnet_domain",
            "subnet_utilization_history",
            "vlan",
        ),
    ),
    FactorySection(
        key="ai",
        label="AI / Copilot",
        description=(
            "AI providers, custom prompts, chat sessions + " "messages, AI operation proposals."
        ),
        phrase="DESTROY-AI",
        kind="truncate",
        tables=(
            "ai_chat_message",
            "ai_chat_session",
            "ai_operation_proposal",
            "ai_prompt",
            "ai_provider",
        ),
    ),
    FactorySection(
        key="compliance",
        label="Compliance",
        description=(
            "Conformity policies, conformity results, alert rules, "
            "alert events. Resets compliance reporting back to a "
            "clean slate; built-in conformity policies re-seed at "
            "next startup."
        ),
        phrase="DESTROY-COMPLIANCE",
        kind="truncate",
        tables=(
            "conformity_result",
            "conformity_policy",
            "alert_event",
            "alert_rule",
        ),
    ),
    FactorySection(
        key="verticals",
        label="Vertical network awareness",
        description=(
            "The multicast stream registry (groups, PIM domains, "
            "ports, memberships) and the vertical descriptors layered "
            "on it — AV-over-IP flow profiles + reserved ranges, "
            "BACnet/IP devices + BBMD tables, industrial-OT devices + "
            "Purdue zoning, and the DICOM AE Title registry + peer "
            "map. The underlying IPAM addresses and subnets "
            "are untouched; only the vertical metadata is destroyed."
        ),
        phrase="DESTROY-VERTICALS",
        kind="truncate",
        tables=(
            "av_flow_profile",
            "av_reserved_range",
            "bacnet_device",
            "dicom_peer",
            "dicom_ae",
            "ot_device",
            "ot_zone",
            "multicast_membership",
            "multicast_group_port",
            "multicast_group",
            "multicast_domain",
        ),
    ),
    FactorySection(
        key="tools",
        label="Tools",
        description=(
            "nmap scan history. IP addresses keep their last-"
            "profiled timestamp; only the link to the deleted scan "
            "is cleared. The DHCP-fingerprint catalog (separate "
            "from device profiles) lives under DHCP."
        ),
        phrase="DESTROY-TOOLS",
        kind="truncate",
        tables=("nmap_scan",),
    ),
    FactorySection(
        key="observability_logs",
        label="Observability logs",
        description=(
            "Audit log + DNS query log + DHCP activity log. "
            "Separate from audit-forward targets so operators can "
            "wipe the diagnostic logs while keeping the syslog / "
            "webhook forwarders intact. A synthetic "
            "factory_reset_performed audit row is written AFTER "
            "the wipe so the trail of evidence survives."
        ),
        phrase="DESTROY-OBSERVABILITY-LOGS",
        kind="truncate",
        tables=(
            "audit_log",
            "dns_query_log_entry",
            # Query-derived behavioural data about clients, plus the
            # operator triage decisions on it (client IPs, reasons,
            # operator names) — someone wiping an appliance before
            # handing it on reasonably expects all of this gone (#699).
            "dns_client_window",
            "dns_rpz_hit",
            "dns_threat_mute",
            "dhcp_log_entry",
            "internal_error",
        ),
    ),
    FactorySection(
        key="auth_rbac",
        label="Auth + RBAC",
        description=(
            "All non-admin users, all custom groups, all "
            "non-builtin roles, all API tokens, all auth providers. "
            "The calling superadmin and built-in roles "
            "(Superadmin / Viewer / IPAM/DNS/DHCP Editor / Auditor / "
            "Compliance Editor) are preserved automatically."
        ),
        phrase="DESTROY-AUTH-RBAC",
        kind="auth_rbac",
    ),
    FactorySection(
        key="settings_branding",
        label="Settings + branding",
        description=(
            "Reverts platform_settings to defaults. Keeps the "
            "encryption key intact (SECRET_KEY lives in env, not "
            "the DB). Audit-forward targets, event subscriptions, "
            "and feature-module toggles are not touched."
        ),
        phrase="DESTROY-SETTINGS",
        kind="settings_reset",
    ),
    FactorySection(
        key=ALL_SECTION_KEY,
        label="Everything",
        description=(
            "Run every section above sequentially. The calling "
            "superadmin, built-in roles, alembic head, OUI cache, "
            "configured backup destinations, and audit-forward "
            "targets are still preserved. Use this as the "
            "fresh-install button."
        ),
        phrase="FACTORY-RESET-ALL",
        kind="everything",
    ),
)


FACTORY_SECTIONS_BY_KEY: dict[str, FactorySection] = {s.key: s for s in FACTORY_SECTIONS}


def expand_everything() -> list[FactorySection]:
    """Return the ordered list of non-``everything`` sections that
    the ``all`` target expands to. Excludes the ``ALL_SECTION_KEY``
    pseudo-section itself.
    """
    return [s for s in FACTORY_SECTIONS if s.key != ALL_SECTION_KEY]
