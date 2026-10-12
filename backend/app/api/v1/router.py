from fastapi import APIRouter, Depends

from app.api.token_path_scope import enforce_path_token_scope
from app.api.v1.acme import router as acme_router
from app.api.v1.address_sets import router as address_sets_router
from app.api.v1.admin.agent_keys import router as agent_keys_router
from app.api.v1.admin.containers import router as containers_router
from app.api.v1.admin.feature_modules import router as feature_modules_router
from app.api.v1.admin.postgres import router as postgres_router
from app.api.v1.admin.redis import router as redis_admin_router
from app.api.v1.admin.trash import router as trash_router
from app.api.v1.ai import router as ai_router
from app.api.v1.alerts.router import router as alerts_router
from app.api.v1.ansible import router as ansible_router
from app.api.v1.api_tokens.router import router as api_tokens_router
from app.api.v1.appliance import router as appliance_router
from app.api.v1.appliance.firewall import router as firewall_policy_router
from app.api.v1.applications import router as applications_router
from app.api.v1.asns import router as asns_router
from app.api.v1.audit.router import router as audit_router
from app.api.v1.auth.router import router as auth_router
from app.api.v1.auth_providers.router import router as auth_providers_router
from app.api.v1.av import router as av_router
from app.api.v1.backup import router as backup_router
from app.api.v1.bacnet import router as bacnet_router
from app.api.v1.bgp import router as bgp_router
from app.api.v1.block_sync import router as block_sync_router
from app.api.v1.change_requests import router as change_requests_router
from app.api.v1.circuits import router as circuits_router
from app.api.v1.cloud import router as cloud_router
from app.api.v1.conformity import router as conformity_router
from app.api.v1.custom_fields.router import router as custom_fields_router
from app.api.v1.cutover import router as cutover_router
from app.api.v1.dashboards import router as dashboards_router
from app.api.v1.dhcp import router as dhcp_router
from app.api.v1.dhcp.agents import router as dhcp_agents_router
from app.api.v1.dhcp.ra_routers import router as ra_routers_router
from app.api.v1.dhcp_import.router import router as dhcp_import_router
from app.api.v1.diagnostics import router as diagnostics_router
from app.api.v1.dicom import router as dicom_router
from app.api.v1.dns.agents import router as dns_agents_router
from app.api.v1.dns.blocklist_router import router as dns_blocklist_router
from app.api.v1.dns.pool_router import router as dns_pool_router
from app.api.v1.dns.router import router as dns_router
from app.api.v1.dns_import.router import router as dns_import_router
from app.api.v1.dns_threat.router import router as dns_threat_router
from app.api.v1.dns_tools import router as dns_tools_router
from app.api.v1.dnsbl import router as dnsbl_router
from app.api.v1.docker import router as docker_router
from app.api.v1.domains import router as domains_router
from app.api.v1.e911 import router as e911_router
from app.api.v1.firewall_feeds.router import public_router as firewall_feeds_public_router
from app.api.v1.firewall_feeds.router import router as firewall_feeds_router
from app.api.v1.fortinet.router import router as fortinet_router
from app.api.v1.groups.router import router as groups_router
from app.api.v1.groups.time_bound_grants import router as time_bound_grants_router
from app.api.v1.ipam.router import router as ipam_router
from app.api.v1.kubernetes import router as kubernetes_router
from app.api.v1.logs import logs_router
from app.api.v1.looking_glass.agents import router as looking_glass_agents_router
from app.api.v1.looking_glass.router import router as looking_glass_router
from app.api.v1.meraki.router import router as meraki_router
from app.api.v1.metrics import router as metrics_router
from app.api.v1.multicast import router as multicast_router
from app.api.v1.netbird import router as netbird_router
from app.api.v1.netbox_import.router import router as netbox_import_router
from app.api.v1.network import router as network_router
from app.api.v1.new_devices import router as new_devices_router
from app.api.v1.nmap import router as nmap_router
from app.api.v1.opnsense import router as opnsense_router
from app.api.v1.ot import router as ot_router
from app.api.v1.overlays import router as overlays_router
from app.api.v1.ownership import (
    customers_router,
    providers_router,
    sites_router,
)
from app.api.v1.panos import router as panos_router
from app.api.v1.pcap import router as pcap_router
from app.api.v1.proxmox import router as proxmox_router
from app.api.v1.reports import router as reports_router
from app.api.v1.requests import router as requests_router
from app.api.v1.roles.router import router as roles_router
from app.api.v1.saved_views import router as saved_views_router
from app.api.v1.search.router import router as search_router
from app.api.v1.services import router as services_router
from app.api.v1.sessions.router import router as sessions_router
from app.api.v1.settings.router import router as settings_router
from app.api.v1.system import router as system_router
from app.api.v1.tags import router as tags_router
from app.api.v1.tailscale import router as tailscale_router
from app.api.v1.tls_certs import router as tls_certs_router
from app.api.v1.tools import router as tools_router
from app.api.v1.unifi import router as unifi_router
from app.api.v1.upgrades import router as upgrades_router
from app.api.v1.users.router import router as users_router
from app.api.v1.version import router as version_router
from app.api.v1.vlans.router import router as vlans_router
from app.api.v1.vrfs import router as vrfs_router
from app.api.v1.webhooks import router as webhooks_router
from app.api.v1.wol_schedules import router as wake_scheduler_router
from app.core.agent_wake import wake_publishing
from app.services.feature_modules import require_module

api_v1_router = APIRouter()

# Tags are alphabetised so the ReDoc / Swagger surface lists sections
# A → Z. New entries should be inserted in sort order.
api_v1_router.include_router(acme_router, prefix="/acme", tags=["acme"])
api_v1_router.include_router(
    address_sets_router,
    prefix="/address-sets",
    dependencies=[Depends(require_module("ipam.address_sets"))],
    tags=["address-sets"],
)
api_v1_router.include_router(
    ai_router,
    prefix="/ai",
    tags=["ai"],
    dependencies=[Depends(require_module("ai.copilot"))],
)
api_v1_router.include_router(agent_keys_router, prefix="/admin", tags=["admin-agent-keys"])
api_v1_router.include_router(containers_router, prefix="/admin", tags=["admin-containers"])
api_v1_router.include_router(
    feature_modules_router, prefix="/admin", tags=["admin-feature-modules"]
)
api_v1_router.include_router(postgres_router, prefix="/admin", tags=["admin-postgres"])
api_v1_router.include_router(redis_admin_router, prefix="/admin", tags=["admin-redis"])
api_v1_router.include_router(trash_router, prefix="/admin", tags=["admin-trash"])
api_v1_router.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
api_v1_router.include_router(ansible_router, prefix="/ansible", tags=["ansible"])
api_v1_router.include_router(api_tokens_router, prefix="/api-tokens", tags=["api-tokens"])
api_v1_router.include_router(appliance_router, prefix="/appliance", tags=["appliance"])
# #285 Phase 3c — firewall policy CRUD. Separate include (NOT folded into
# appliance_router) so the require_module gate applies to /appliance/firewall
# ONLY — the /appliance hub itself stays always-visible (docker/k8s control
# planes with appliance agents must reach Fleet). This router-level gate is
# the real #14 enforcement (404 when the module is off).
api_v1_router.include_router(
    firewall_policy_router,
    prefix="/appliance/firewall",
    tags=["appliance-firewall"],
    dependencies=[Depends(require_module("appliance.firewall"))],
)
api_v1_router.include_router(applications_router, prefix="/applications", tags=["applications"])
api_v1_router.include_router(
    asns_router,
    prefix="/asns",
    tags=["asns"],
    dependencies=[Depends(require_module("network.asn"))],
)
api_v1_router.include_router(audit_router, prefix="/audit", tags=["audit"])
api_v1_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_v1_router.include_router(
    auth_providers_router, prefix="/auth-providers", tags=["auth-providers"]
)
# Vertical-awareness surfaces (#543): AV (#540), BACnet (#541), OT (#542).
# NO wake_publishing on any of the three — they enrich multicast / IPAM rows
# and touch neither the DNS nor the DHCP ConfigBundle, so there is no parked
# agent long-poll to wake (same reasoning as the netbox_import include below).
api_v1_router.include_router(
    av_router,
    prefix="/av",
    tags=["av"],
    dependencies=[Depends(require_module("network.av"))],
)
api_v1_router.include_router(backup_router, prefix="/backup", tags=["backup"])
api_v1_router.include_router(
    bacnet_router,
    prefix="/bacnet",
    tags=["bacnet"],
    dependencies=[Depends(require_module("network.bacnet"))],
)
api_v1_router.include_router(
    bgp_router,
    prefix="/bgp",
    tags=["bgp"],
    # Folds into the existing ASN feature module (its MCP tools are
    # tagged module="network.asn" and its UI is a tab on the ASN detail
    # page) — gate /bgp by the same module as /asns (non-negotiable #14).
    dependencies=[Depends(require_module("network.asn"))],
)
api_v1_router.include_router(
    change_requests_router,
    prefix="/change-requests",
    tags=["change-requests"],
    dependencies=[Depends(require_module("governance.approvals"))],
)
api_v1_router.include_router(
    requests_router,
    prefix="/requests",
    tags=["requests"],
    dependencies=[Depends(require_module("governance.requests"))],
)
api_v1_router.include_router(
    circuits_router,
    prefix="/circuits",
    tags=["circuits"],
    dependencies=[Depends(require_module("network.circuit"))],
)
api_v1_router.include_router(
    cloud_router,
    prefix="/cloud",
    tags=["cloud"],
    dependencies=[Depends(require_module("integrations.cloud"))],
)
api_v1_router.include_router(
    conformity_router,
    prefix="/conformity",
    tags=["conformity"],
    dependencies=[Depends(require_module("compliance.conformity"))],
)
api_v1_router.include_router(custom_fields_router, prefix="/custom-fields", tags=["custom-fields"])
api_v1_router.include_router(dashboards_router, prefix="/dashboards", tags=["dashboards"])
api_v1_router.include_router(
    customers_router,
    prefix="/customers",
    tags=["customers"],
    dependencies=[Depends(require_module("network.customer"))],
)
api_v1_router.include_router(
    dhcp_router,
    prefix="/dhcp",
    tags=["dhcp"],
    # #358 — DHCP CRUD shifts the rebuilt-bundle ETag; publish a wake on
    # commit so parked Kea agents re-poll immediately.
    #
    # #1068 — the whole operator-facing DHCP surface hangs off core.dhcp
    # so a DNS-only or IPAM-only install can put it away. The agent
    # router used to live INSIDE this one and was lifted out (next
    # include) because this gate answers 404, which is exactly what makes
    # an agent re-bootstrap from its PSK.
    dependencies=[Depends(require_module("core.dhcp")), Depends(wake_publishing)],
)
# DHCP agent bootstrap / config long-poll / lease + log ingest. Same
# ``/dhcp`` prefix as above so the wire path is unchanged, but mounted
# here rather than inside ``dhcp_router`` so it does NOT carry the
# core.dhcp gate: turning DHCP off must stop the operator surface, never
# the fleet, and require_module answers 404 — the status that makes an
# agent discard its JWT and re-bootstrap from its PSK.
#
# It DOES keep wake_publishing, unlike the DNS agent include below. The
# DNS agent router really is a pure consumer, but ``/dhcp/agents/
# lease-events`` runs subnet-level DDNS (``apply_ddns_for_lease`` →
# ``_sync_dns_record`` → ``enqueue_record_op``), which calls
# ``collect_wake`` — and collect_wake is a silent no-op when no collector
# is installed. Dropping it here would not error; lease-driven DNS
# updates would simply stop waking DNS agents and converge on the 12 s
# safety tick instead.
api_v1_router.include_router(
    dhcp_agents_router,
    prefix="/dhcp",
    tags=["dhcp-agents"],
    dependencies=[Depends(wake_publishing)],
)
api_v1_router.include_router(
    dhcp_import_router,
    prefix="/dhcp/import",
    tags=["dhcp-import"],
    dependencies=[Depends(require_module("dhcp.import")), Depends(wake_publishing)],
)
# IPv6 Router Advertisement management + rogue-RA detection (#524). Gated by
# the ipv6.router_advertisements module. wake_publishing so an allowlist /
# ack change that could shift agent state re-polls parked agents.
api_v1_router.include_router(
    ra_routers_router,
    prefix="/dhcp/ra",
    tags=["dhcp"],
    dependencies=[
        Depends(require_module("ipv6.router_advertisements")),
        Depends(wake_publishing),
    ],
)
api_v1_router.include_router(diagnostics_router, prefix="/diagnostics", tags=["diagnostics"])
# DICOM AE registry (#723) — the healthcare member of the #543 vertical
# family. No wake_publishing: it enriches IPAM rows and touches neither
# the DNS nor the DHCP ConfigBundle, so there is no parked agent
# long-poll to wake (same reasoning as the /av include above).
api_v1_router.include_router(
    dicom_router,
    prefix="/dicom",
    tags=["dicom"],
    dependencies=[Depends(require_module("network.dicom"))],
)
api_v1_router.include_router(
    e911_router,
    prefix="/e911",
    tags=["e911"],
    dependencies=[Depends(require_module("network.e911"))],
)
api_v1_router.include_router(
    dns_router,
    prefix="/dns",
    tags=["dns"],
    # #358 — publish a Redis wake after any record-mutating handler
    # commits so parked agent long-polls re-poll immediately. The
    # agent router (next line) is deliberately NOT wrapped — it holds
    # the long-poll and never enqueues record ops, and since #1068 that
    # separation is also what keeps the fleet reachable when core.dns is
    # off (the gate answers 404, which re-bootstraps agents).
    # GHSA-46mq-mpwf-xxwv: a zone-scoped token is held to its zones on
    # every route keyed on {zone_id}, before any handler runs.
    dependencies=[
        Depends(require_module("core.dns")),
        Depends(wake_publishing),
        Depends(enforce_path_token_scope),
    ],
)
api_v1_router.include_router(dns_agents_router, prefix="/dns", tags=["dns-agents"])
api_v1_router.include_router(
    dns_blocklist_router,
    prefix="/dns",
    tags=["dns-blocklists"],
    # #358 — RPZ blocklist edits shift the structural ETag; publish on commit.
    dependencies=[Depends(require_module("core.dns")), Depends(wake_publishing)],
)
api_v1_router.include_router(
    dns_import_router,
    prefix="/dns/import",
    tags=["dns-import"],
    dependencies=[Depends(require_module("dns.import")), Depends(wake_publishing)],
)
api_v1_router.include_router(
    dns_pool_router,
    prefix="/dns",
    tags=["dns-pools"],
    # #358 — GSLB pool reconcile calls enqueue_record_op; publish on commit.
    dependencies=[
        Depends(require_module("core.dns")),
        Depends(wake_publishing),
        Depends(enforce_path_token_scope),
    ],
)
api_v1_router.include_router(
    dns_tools_router,
    prefix="/dns",
    tags=["dns-tools"],
    dependencies=[Depends(require_module("core.dns"))],
)
api_v1_router.include_router(
    dns_threat_router,
    prefix="/dns-threat",
    tags=["dns-threat"],
    dependencies=[Depends(require_module("security.dns_threat"))],
)
api_v1_router.include_router(
    dnsbl_router,
    prefix="/dnsbl",
    tags=["dnsbl"],
    dependencies=[Depends(require_module("security.dnsbl"))],
)
api_v1_router.include_router(
    docker_router,
    prefix="/docker",
    tags=["docker"],
    dependencies=[Depends(require_module("integrations.docker"))],
)
api_v1_router.include_router(domains_router, tags=["domains"])
# Mount the time-bound-grant routes BEFORE the groups router: the groups
# router carries a ``GET /{group_id}`` that would otherwise shadow
# ``/groups/time-bound-grants`` (the literal path would be parsed as a UUID
# path param and 422). Registering the static-prefix router first wins.
api_v1_router.include_router(time_bound_grants_router, prefix="/groups", tags=["time-bound-grants"])
api_v1_router.include_router(groups_router, prefix="/groups", tags=["groups"])
api_v1_router.include_router(
    ipam_router,
    prefix="/ipam",
    tags=["ipam"],
    # #358 — IPAM→DNS auto-sync calls enqueue_record_op; publish on commit.
    # GHSA-46mq-mpwf-xxwv: a subnet-scoped token is held to its subnets on
    # every route keyed on {subnet_id} / {address_id}.
    dependencies=[Depends(wake_publishing), Depends(enforce_path_token_scope)],
)
api_v1_router.include_router(
    kubernetes_router,
    prefix="/kubernetes",
    tags=["kubernetes"],
    dependencies=[Depends(require_module("integrations.kubernetes"))],
)
api_v1_router.include_router(logs_router, prefix="/logs", tags=["logs"])
# BGP Looking Glass (#566). Operator CRUD carries wake_publishing so a peer
# config change wakes the parked collector long-poll; the agent router (which
# holds that long-poll) is included without it, mirroring dns-agents.
api_v1_router.include_router(
    looking_glass_router,
    prefix="/looking-glass",
    tags=["looking-glass"],
    dependencies=[
        Depends(require_module("network.looking_glass")),
        Depends(wake_publishing),
    ],
)
api_v1_router.include_router(
    looking_glass_agents_router,
    prefix="/looking-glass",
    tags=["looking-glass-agents"],
    dependencies=[Depends(require_module("network.looking_glass"))],
)
api_v1_router.include_router(metrics_router, prefix="/metrics", tags=["metrics"])
api_v1_router.include_router(
    multicast_router,
    prefix="/multicast",
    tags=["multicast"],
    dependencies=[Depends(require_module("network.multicast"))],
)
api_v1_router.include_router(
    netbird_router,
    prefix="/netbird",
    tags=["netbird"],
    dependencies=[Depends(require_module("integrations.netbird"))],
)
api_v1_router.include_router(
    cutover_router,
    prefix="/migration/cutover",
    tags=["cutover"],
    # 404 when the module is off. wake_publishing because the cutover DOES
    # touch agent config: the TTL pre-flight rewrites records (shifting the DNS
    # bundle ETag) and the switch flips DHCPScope.is_active — parked agents
    # should re-poll on commit rather than wait out the safety tick.
    dependencies=[Depends(require_module("migration.cutover")), Depends(wake_publishing)],
)
api_v1_router.include_router(
    netbox_import_router,
    prefix="/ipam/import/netbox",
    tags=["netbox-import"],
    # 404 when the module is off. NO wake_publishing — NetBox seeds IPAM
    # rows only and touches no DNS/DHCP agent config bundle, so there's
    # no agent long-poll to wake (contrast dns_import / dhcp_import which
    # DO carry wake_publishing).
    dependencies=[Depends(require_module("ipam.import.netbox"))],
)
api_v1_router.include_router(
    network_router,
    tags=["network"],
    dependencies=[Depends(require_module("network.device"))],
)
api_v1_router.include_router(
    new_devices_router,
    dependencies=[Depends(require_module("security.new_device_watch"))],
)
api_v1_router.include_router(
    block_sync_router,
    dependencies=[Depends(require_module("security.block_sync"))],
)
api_v1_router.include_router(
    nmap_router,
    prefix="/nmap",
    tags=["nmap"],
    dependencies=[Depends(require_module("tools.nmap"))],
)
api_v1_router.include_router(
    pcap_router,
    prefix="/pcap",
    tags=["pcap"],
    dependencies=[Depends(require_module("tools.pcap"))],
)
api_v1_router.include_router(
    opnsense_router,
    prefix="/opnsense",
    tags=["opnsense"],
    dependencies=[Depends(require_module("integrations.opnsense"))],
)
# OT / industrial devices (#542). No wake_publishing — see the /av include.
api_v1_router.include_router(
    ot_router,
    prefix="/ot",
    tags=["ot"],
    dependencies=[Depends(require_module("network.ot"))],
)
api_v1_router.include_router(
    overlays_router,
    prefix="/overlays",
    tags=["overlays"],
    dependencies=[Depends(require_module("network.overlay"))],
)
api_v1_router.include_router(
    panos_router,
    prefix="/paloalto",
    tags=["paloalto"],
    dependencies=[Depends(require_module("integrations.paloalto"))],
)
api_v1_router.include_router(
    fortinet_router,
    prefix="/fortinet",
    tags=["fortinet"],
    dependencies=[Depends(require_module("integrations.fortinet"))],
)
api_v1_router.include_router(
    meraki_router,
    prefix="/meraki",
    tags=["meraki"],
    dependencies=[Depends(require_module("integrations.meraki"))],
)
# Firewall block-list feeds (#606). Admin CRUD is module-gated; the public
# token-authed poll endpoint is included with NO dependency so a polling
# firewall can always reach it (its own token is the auth).
api_v1_router.include_router(
    firewall_feeds_router,
    prefix="/firewall-feeds",
    tags=["firewall-feeds"],
    dependencies=[Depends(require_module("security.firewall_feeds"))],
)
api_v1_router.include_router(
    firewall_feeds_public_router,
    prefix="/firewall-feeds",
    tags=["firewall-feeds"],
)
api_v1_router.include_router(
    providers_router,
    prefix="/providers",
    tags=["providers"],
    dependencies=[Depends(require_module("network.provider"))],
)
api_v1_router.include_router(
    proxmox_router,
    prefix="/proxmox",
    tags=["proxmox"],
    dependencies=[Depends(require_module("integrations.proxmox"))],
)
api_v1_router.include_router(
    reports_router,
    prefix="/reports",
    tags=["reports"],
    dependencies=[Depends(require_module("reports.top_n"))],
)
api_v1_router.include_router(roles_router, prefix="/roles", tags=["roles"])
api_v1_router.include_router(
    saved_views_router,
    prefix="/saved-views",
    tags=["saved-views"],
    dependencies=[Depends(require_module("ui.saved_views"))],
)
api_v1_router.include_router(search_router, prefix="/search", tags=["search"])
api_v1_router.include_router(
    services_router,
    prefix="/services",
    tags=["services"],
    dependencies=[Depends(require_module("network.service"))],
)
api_v1_router.include_router(sessions_router, prefix="/sessions", tags=["sessions"])
api_v1_router.include_router(settings_router, prefix="/settings", tags=["settings"])
api_v1_router.include_router(
    sites_router,
    prefix="/sites",
    tags=["sites"],
    dependencies=[Depends(require_module("network.site"))],
)
api_v1_router.include_router(system_router, prefix="/system", tags=["system"])
api_v1_router.include_router(tags_router, prefix="/tags", tags=["tags"])
api_v1_router.include_router(
    tailscale_router,
    prefix="/tailscale",
    tags=["tailscale"],
    dependencies=[Depends(require_module("integrations.tailscale"))],
)
api_v1_router.include_router(
    tls_certs_router,
    prefix="/tls-certs",
    tags=["tls-certs"],
    dependencies=[Depends(require_module("security.tls_certs"))],
)
api_v1_router.include_router(
    tools_router,
    prefix="/tools",
    tags=["tools"],
    dependencies=[Depends(require_module("tools.network"))],
)
api_v1_router.include_router(
    unifi_router,
    prefix="/unifi",
    tags=["unifi"],
    dependencies=[Depends(require_module("integrations.unifi"))],
)
api_v1_router.include_router(upgrades_router, prefix="/upgrades", tags=["upgrades"])
api_v1_router.include_router(users_router, prefix="/users", tags=["users"])
api_v1_router.include_router(version_router, prefix="/version", tags=["version"])
api_v1_router.include_router(
    vlans_router,
    prefix="/vlans",
    tags=["vlans"],
    dependencies=[Depends(require_module("network.vlan"))],
)
api_v1_router.include_router(
    vrfs_router,
    prefix="/vrfs",
    tags=["vrfs"],
    dependencies=[Depends(require_module("network.vrf"))],
)
# Scheduled Wake-on-LAN (#586). Package is ``wol_schedules`` but the wire
# prefix is ``wake-scheduler`` (the cross-surface contract with the frontend
# api client + MCP tools). NO wake_publishing — a magic packet mutates no
# DNS/DHCP agent ConfigBundle, so there is no parked long-poll to wake.
api_v1_router.include_router(
    wake_scheduler_router,
    prefix="/wake-scheduler",
    tags=["wake-scheduler"],
    dependencies=[Depends(require_module("tools.wake_scheduler"))],
)
api_v1_router.include_router(webhooks_router, prefix="/webhooks", tags=["webhooks"])
