"""Feature-module catalog + cached enabled-set.

The catalog is the source of truth for *which modules exist*. The
``feature_module`` DB table stores per-module operator overrides;
unknown rows in the table are tolerated (forward-compat with
downgrades) but never gate anything.

Default policy (#1069):
    A module ships ENABLED only if it is part of the core IPAM / DNS /
    DHCP workflow, a zero-footprint UI convenience, or a read-only
    diagnostic the operator invokes by hand. Everything else ships
    DISABLED — a domain-specific registry most installs will never
    populate, anything that emits traffic or writes to infrastructure
    once armed, anything that calls off-prem, and the Windows cutover.
    Day-one importers are the deliberate exception to that last clause:
    a fresh install is exactly when an estate gets imported.

    This replaced "default-on so operators discover what exists", which
    had put 37 of 53 modules in a new operator's sidebar — BACnet, DICOM,
    OT zoning, E911 and a BGP looking glass among them. Discovery is
    served by Settings → Features, which lists every module with its
    description whether or not it is on.

    The shipped value of every module is pinned by
    ``tests/test_feature_module_defaults.py``, so changing one is a
    deliberate edit in two places rather than a default nobody noticed.

When a route gate (``require_module``) fails it raises 404, not 403:
    a disabled module is "not present" from the API surface's
    perspective, not "you can't access it". Mirrors how a not-installed
    plugin would behave in NetBox / Grafana.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

import structlog
from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.models.feature_module import FeatureModule

logger = structlog.get_logger(__name__)


# ── Catalog ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ModuleSpec:
    """Static catalog entry for a togglable feature."""

    id: str
    label: str
    group: str
    description: str
    default_enabled: bool = True
    # Parent modules this one is meaningless without (#1068). A module
    # resolves ENABLED only if every ancestor does — see
    # ``get_enabled_modules``. This is a real gate, not a UI hint: a
    # child left independently on when its parent is off would keep a
    # router mounted and a sidebar row visible, pointing at a subsystem
    # the operator has turned off.
    requires: tuple[str, ...] = ()


# Stable dotted-name ids. A new module appends here and does NOT seed a
# row: the catalog's ``default_enabled`` IS the default, and a
# ``feature_module`` row means "an operator changed this" (#1069). The
# historical seeds are why flipping a default here used to do nothing —
# a row always wins over the catalog, and a fresh install ran the same
# seed migrations an upgrade did.
#
# Groups drive UI placement on Settings → Features (11 today:
# Network, AI, Compliance, Tools, DNS, DHCP, IPAM, Integrations, Appliance, Security, UI).
# Keep the list short — the page collapses fine sub-groups into broader
# headings, and a group per feature would defeat that.
MODULES: Final[tuple[ModuleSpec, ...]] = (
    # Network — everything under the sidebar's "Network" section.
    #
    # Of these, only Sites, VLANs, VRFs and Address sets ship ON (#1069):
    # they are the dimensions an ordinary IPAM install uses on day one, and
    # three of the four are referenced straight off a subnet. The rest are
    # service-provider / MSP modelling (Customers, Providers, Services,
    # Circuits, Overlays, ASNs) or a registry that only means something once
    # the operator populates it (Network devices, Multicast, and the four
    # verticals below) — real features that most installs never open, and
    # that cost a sidebar row each until someone asks for them.
    ModuleSpec(
        id="network.customer",
        label="Customers",
        group="Network",
        description="Customer ownership records — operator-facing entity attached to IPAM/DNS/DHCP/Network rows.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.provider",
        label="Providers",
        group="Network",
        description="Carrier/upstream provider records, used as RESTRICT FK on circuits.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.site",
        label="Sites",
        group="Network",
        description="Physical/logical site records attached as ownership FKs.",
    ),
    ModuleSpec(
        id="network.service",
        label="Services",
        group="Network",
        description="Service catalog (MPLS L3VPN, SD-WAN, …) bound to underlying VRFs / subnets / circuits.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.asn",
        label="ASNs",
        group="Network",
        description="Autonomous-system records with RDAP holder + RPKI ROA enrichment.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.circuit",
        label="Circuits",
        group="Network",
        description="WAN circuits — carrier-supplied logical pipes between sites/providers.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.device",
        label="Network devices",
        group="Network",
        description="Routers/switches discovered via SNMP polling and their ARP/FDB/interface tables.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.overlay",
        label="Overlays",
        group="Network",
        description="SD-WAN overlay topology — sites + circuits + routing policies.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.vlan",
        label="VLANs",
        group="Network",
        description="VLAN registry + Router groups.",
    ),
    ModuleSpec(
        id="network.vrf",
        label="VRFs",
        group="Network",
        description="VRF records replacing freeform RD/RT text on IPSpace.",
    ),
    ModuleSpec(
        id="network.multicast",
        label="Multicast groups",
        group="Network",
        description="Multicast group registry — addresses + producer/consumer memberships for SMPTE 2110 / Dante / NDI / market-data deployments. Niche but high-value when operators need it.",
        default_enabled=False,
    ),
    # Vertical-awareness modules (#543 / #723). Registry-only — no probes,
    # no device I/O, no off-prem calls — so nothing here is dangerous ON.
    # They are default-OFF (#1069) for a different reason: each one is a
    # domain-specific registry that a site either runs its whole network
    # around or will never open once. A hospital wants DICOM; nobody else
    # wants five extra sidebar entries. Turning one on costs one click and
    # arms nothing, and each is listed with its description on
    # Settings → Features whether or not it is on.
    ModuleSpec(
        id="network.av",
        label="AV over IP",
        group="Network",
        description="Audio/video-over-IP descriptors on top of the multicast registry — Dante / AES67 / SMPTE ST 2110 / NDI / RAVENNA flow labels, PTP clock domain, and operator-declared reserved ranges so allocations can be checked against the studio address plan. Registry only; no media monitoring, no NMOS connection control.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.bacnet",
        label="BACnet/IP devices",
        group="Network",
        description="Building-automation device registry — internetwork-unique device instance numbers, BACnet network numbers, and per-subnet BBMD designation, each attached to an existing IPAM address. Documents the BACnet topology (including the exactly-one-BBMD-per-subnet rule); never reads or writes device objects.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.e911",
        label="E911 dispatchable location",
        group="Network",
        description=(
            "Location Information Server for E911 — Emergency Response Locations as "
            "RFC 5139 civic addresses, bindings from switch port / subnet / VLAN / "
            "device to an ERL, and a resolver that answers 'which room is this device "
            "in, right now?' from DHCP, FDB and LLDP data already collected for IPAM. "
            "RAY BAUM'S Act §506 puts the dispatchable-location duty on the enterprise. "
            "SpatiumDDI is a location SOURCE only: it does no call routing, no ALI "
            "upload and no PSAP interaction, and it never asserts an address is valid "
            "on its own say-so."
        ),
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.dicom",
        label="DICOM AE registry",
        group="Network",
        description="Medical-imaging Application Entity registry — the institution-wide-unique AE Titles that PS3.15 Annex H specifies a registry for and that in practice live in a spreadsheet, plus the configured AE→AE association map behind 'what breaks if I renumber this host'. Network identity only: no patient data, ever, and no DICOM traffic is read or generated.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="network.ot",
        label="OT / industrial devices",
        group="Network",
        description="Industrial device descriptors and Purdue-level zoning for OT networks — PROFINET / EtherNet-IP / Modbus TCP / OPC UA role + vendor + criticality per address, per-subnet zone records, and CSV import of engineering-tool exports. Read-only identification: no tag reads, no control-protocol writes, ever.",
        default_enabled=False,
    ),
    # BGP Looking Glass (#566) — a receive-only GoBGP collector peers with the
    # operator's routers and mirrors the live Adj-RIB-In, linking every learned
    # prefix / origin ASN / community back into IPAM. Default-OFF (#1069):
    # it is inert until an operator configures a BGP peer, and an install
    # with no routers to peer with will never configure one. Receive-only —
    # never advertises.
    ModuleSpec(
        id="network.looking_glass",
        label="BGP Looking Glass",
        group="Network",
        description="Receive-only BGP collector that peers with your routers and surfaces the live routing table — every learned prefix, origin ASN and community linked back into IPAM / the ASN + community catalogs, RPKI-validated. Never advertises routes to your network. Discovery toggle only; the collector does nothing until you configure a peer.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="ipam.address_sets",
        label="Address sets",
        group="Network",
        description="Named IP ranges within a subnet carrying their own RBAC scope, so edit of a slice (e.g. .50–.99) can be delegated without subnet-wide write.",
    ),
    # IPv6 Router Advertisements — radvd management + rogue-RA detection
    # (issue #524). Default-OFF (#1069): this is the one DHCP-adjacent
    # surface that ends in something being transmitted onto the wire, and a
    # v4-only install — still the common case — has no use for it. Emitting
    # RAs additionally requires opting a scope in (ra_enabled) AND radvd on
    # the agent (RADVD_MANAGED=1); the passive rogue-RA sniffer is separately
    # gated on DHCP_RA_SNIFFER_ENABLED + CAP_NET_RAW.
    ModuleSpec(
        id="ipv6.router_advertisements",
        label="IPv6 Router Advertisements",
        group="Network",
        description="Manage IPv6 Router Advertisements (radvd) per subnet — M/O flags derived from the DHCPv6 mode, RDNSS/DNSSL from DNS settings, prefix + router lifetimes — plus passive rogue-RA detection with an expected-router allowlist and a rogue_ra alert. Discovery toggle only; emitting RAs needs a per-scope opt-in and radvd on the DHCP agent, and the sniffer needs DHCP_RA_SNIFFER_ENABLED.",
        default_enabled=False,
        requires=("core.dhcp",),
    ),
    # AI — operator copilot, gated as a whole.
    ModuleSpec(
        id="ai.copilot",
        label="Operator Copilot",
        group="AI",
        description="Multi-vendor LLM chat + MCP tool surface. Disabling hides the chat drawer and 404s /ai endpoints.",
    ),
    # Compliance / observability extras. Conformity is default-OFF (#1069):
    # it is a rules engine an operator opts into, and its builtin policies
    # seed ``enabled=False``, so the 60 s evaluator finds nothing due and the
    # module being off leaves no background work running invisibly. Top-N
    # reports stay ON — read-only aggregates over data the install already
    # has, with no footprint of their own.
    ModuleSpec(
        id="compliance.conformity",
        label="Conformity evaluations",
        group="Compliance",
        description="Declarative compliance checks + PDF export. Auditor / Compliance Editor builtin roles depend on it.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="reports.top_n",
        label="Top-N Reports",
        group="Compliance",
        description="Fixed Top-N reports (subnet utilization, owner IP counts, most-modified resources, noisiest DNS clients) derived from existing tables.",
    ),
    # Tools. ``tools.network`` (ping / traceroute / dig / port test) stays ON:
    # it is the everyday read-only diagnostic, invoked by hand, and it is the
    # first thing reached for when something is broken. The other three are
    # default-OFF (#1069) because each one puts something on the wire or on
    # disk — a port scan that trips an IDS, a packet capture, a scheduled
    # magic packet — and none is needed to run DNS, DHCP or IPAM.
    ModuleSpec(
        id="tools.nmap",
        label="Nmap scanning",
        group="Tools",
        description="On-demand nmap with live SSE output + history. Subnet/IP scan buttons hide when off.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="tools.network",
        label="Network tools",
        group="Tools",
        description=(
            "Built-in ping/traceroute/MTR/dig/whois/port-test/TLS-cert/"
            "DNS-propagation/MAC-vendor run from the server. "
            "Permission-gated + rate-limited."
        ),
    ),
    ModuleSpec(
        id="tools.pcap",
        label="Packet capture",
        group="Tools",
        description=(
            "On-demand tcpdump capture from the control-plane (or appliance "
            "host) vantage — BPF filter + presets, live progress, downloadable "
            ".pcap, history with auto-retention. Captures raw traffic; high "
            "sensitivity (gated by the manage_packet_capture permission)."
        ),
        default_enabled=False,
    ),
    ModuleSpec(
        id="tools.wake_scheduler",
        label="Scheduled Wake-on-LAN",
        group="Tools",
        description=(
            "Recurring, tag-targeted Wake-on-LAN with a built-in holiday "
            "gate (blackout dates + term range). Cron-scheduled fires from "
            "a server or appliance vantage, run history, and live target "
            "preview. Reuses the manual-wake send path; permission-gated."
        ),
        default_enabled=False,
    ),
    # DNS — the subsystem itself (#1068), then the togglable extras
    # beneath it.
    #
    # ``core.dns`` exists so a DHCP-only or IPAM-only install can put the
    # whole DNS surface away: sidebar anchor, /dns routers, the DNS
    # dashboard panels, the DNS beat tasks and every DNS copilot tool.
    # Default-ON, and it stays that way — this is core workflow under the
    # #1069 criterion, and the module is here to be turned OFF by the
    # minority of installs that do not run DNS, not to be discovered.
    #
    # NOT gated by it: ``/dns/agents/*``. That router is mounted
    # separately at the v1 level precisely so this gate cannot reach it.
    # ``require_module`` answers 404, and 404 is the status that makes an
    # agent throw its JWT away and re-bootstrap from the PSK (see "Agent
    # bootstrap + reconnection" in CLAUDE.md) — so gating the agent path
    # would not disable a fleet, it would put it in a re-bootstrap loop.
    #
    # Turning it off is REFUSED while any dns_server or dns_zone row
    # exists (see the toggle endpoint): a toggle that strands a running
    # fleet behind a 404 is worse than no toggle.
    ModuleSpec(
        id="core.dns",
        label="DNS",
        group="DNS",
        description=(
            "The DNS subsystem as a whole — zones, records, views, server "
            "groups, blocklists and the DNS dashboard panels. Turn it off "
            "on an IPAM-only or DHCP-only install to put the entire DNS "
            "surface away; every DNS feature below depends on it. Agent "
            "registration and config polling are deliberately unaffected, "
            "and disabling is refused while any DNS server or zone exists."
        ),
    ),
    # DNS — togglable extras under the Settings → Import surface and
    # the DNS sidebar group. The importer is one-shot (issue #128) —
    # operators upload BIND9 configs / live-pull from Windows DNS or
    # PowerDNS to seed SpatiumDDI with their existing zones, then the
    # importer's job is done. Kept default-ON by #1069: a fresh install is
    # exactly when an operator has an existing estate to load, so this is
    # day-one workflow rather than clutter. No blast radius from the toggle
    # either (importer endpoints are RBAC-gated separately).
    ModuleSpec(
        id="dns.import",
        label="DNS configuration import",
        group="DNS",
        description="One-shot import from BIND9 / Windows DNS / PowerDNS into SpatiumDDI's native zones + records. Run it from Administration → Import → DNS; each source asks for its own credentials or file upload.",
        requires=("core.dns",),
    ),
    # Dynamic-update (RFC 2136) ACLs on zones (issue #641). Lets an
    # operator authorize third-party DDNS writers (an AD DC, a DHCP
    # server registering A/PTR) to a managed zone by TSIG key or source
    # IP/CIDR. Default-enabled for discovery — the surface exposes no
    # secrets by itself (TSIG keys are referenced by name; the encrypted
    # secret never surfaces), and the endpoints are RBAC-gated + the
    # write path is capability-gated per DNS backend.
    ModuleSpec(
        id="dns.dynamic_update_acl",
        label="Dynamic update ACLs",
        group="DNS",
        description="Operator-configurable RFC 2136 dynamic-update ACLs on DNS zones — authorize external DDNS writers (AD DC, DHCP server) by TSIG key or source IP/CIDR. BIND9 + PowerDNS express it natively; Windows maps coarsely; cloud drivers can't (the write 422s).",
        requires=("core.dns",),
    ),
    # DHCP — the subsystem itself (#1068). Mirror of ``core.dns`` above,
    # including the agent carve-out (``/dhcp/agents/*``, which #1068 had
    # to lift OUT of ``dhcp_router`` to keep it reachable) and the
    # refuse-while-populated rule (dhcp_server / dhcp_scope).
    ModuleSpec(
        id="core.dhcp",
        label="DHCP",
        group="DHCP",
        description=(
            "The DHCP subsystem as a whole — servers, scopes, pools, "
            "reservations, leases, client classes and the DHCP dashboard "
            "panels, plus the DHCP affordances inside IPAM. Turn it off on "
            "a DNS-only or IPAM-only install; every DHCP feature below "
            "depends on it. Agent registration and config polling are "
            "deliberately unaffected, and disabling is refused while any "
            "DHCP server or scope exists."
        ),
    ),
    # DHCP — sister importer to ``dns.import`` (issue #129). One-shot
    # import of scopes / pools / reservations / classes from Kea JSON /
    # Windows DHCP live-pull / ISC dhcpd.conf so operators can seed a
    # sandbox SpatiumDDI from their real DHCP estate. Same default-ON
    # rationale as the DNS importer (#1069): day-one workflow, and no blast
    # radius from the toggle (endpoints are RBAC-gated separately).
    ModuleSpec(
        id="dhcp.import",
        label="DHCP configuration import",
        group="DHCP",
        description="One-shot import from Kea / Windows DHCP / ISC dhcpd.conf into SpatiumDDI's native scopes + pools + reservations + classes. Run it from Administration → Import → DHCP; each source asks for its own credentials or file upload.",
        requires=("core.dhcp",),
    ),
    # IPAM — NetBox read-only one-shot migration importer (issue #36).
    # Sister to ``dns.import`` / ``dhcp.import``: pulls prefixes / IP
    # addresses / VLANs / VRFs / tenants / sites out of a live NetBox
    # install and stamps them into native IPAM rows
    # (``import_source="netbox"``). One-shot migration tooling, NOT a
    # continuous reconciler (contrast the ``integrations.*`` mirrors).
    # Default-ON — same rationale as the DNS / DHCP importers (#1069):
    # day-one migration workflow, and no blast radius from the toggle
    # (endpoints are RBAC-gated + superadmin separately).
    # Windows → SpatiumDDI cutover (issue #756). The one-shot importers get an
    # operator's Windows estate INTO SpatiumDDI; this is the rest of the
    # journey — parity verification, the parallel run, the per-zone/per-scope
    # switch, and the decommission checklist.
    #
    # Group is "Tools", not "DNS" or "DHCP": one plan covers both protocols
    # (a single item list holds zones and scopes), so either protocol group
    # would be a lie about half the surface. "Tools" is where the operator
    # workflows live.
    #
    # Default-OFF (#1069), unlike the three importers it extends. An importer
    # is day-one work — a fresh install is exactly when an estate gets loaded,
    # so hiding it would hide the path on the one day it is wanted. A cutover
    # is the opposite end of the journey: it happens after a parity check and
    # a parallel run, only on installs migrating off Windows, and every step
    # of it is superadmin-only.
    ModuleSpec(
        id="migration.cutover",
        label="Windows cutover",
        group="Tools",
        description="Guided migration from Windows DNS / DHCP onto managed BIND9 / PowerDNS / Kea — parity verification, parallel-run shadow queries, per-zone and per-scope cutover with rollback, and the decommission checklist. Configuration → Import → Windows cutover; superadmin-only.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="ipam.import.netbox",
        label="NetBox import",
        group="IPAM",
        description="One-shot migration import of prefixes / IP addresses / VLANs / VRFs / tenants / sites from a NetBox instance into native IPAM rows. Run it from Administration → Import → NetBox; the connection and token are supplied per import and never stored.",
    ),
    # Integrations — read-only mirrors of external orchestrators.
    # Default-disabled: each one needs operator-supplied credentials
    # before it does anything useful, and the kickoff lives behind
    # the per-integration page anyway. Toggle on here makes the
    # integration's sidebar entry + REST surface appear; the actual
    # poll only starts once the operator configures a target.
    #
    # The matching ``PlatformSettings.integration_*_enabled`` columns
    # are kept in lock-step by the toggle endpoint (Celery beat tasks
    # gate on them and we don't want to fan out the read-feature_module
    # change across every reconciler in one PR).
    ModuleSpec(
        id="integrations.kubernetes",
        label="Kubernetes",
        group="Integrations",
        description="Read-only mirror of Kubernetes pods + services into IPAM. Connect clusters from the Kubernetes page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.docker",
        label="Docker",
        group="Integrations",
        description="Read-only mirror of Docker container IPs into IPAM. Connect hosts from the Docker page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.proxmox",
        label="Proxmox VE",
        group="Integrations",
        description="Read-only mirror of Proxmox guests + bridges + SDN VNets into IPAM. Connect endpoints from the Proxmox page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.tailscale",
        label="Tailscale",
        group="Integrations",
        description="Read-only mirror of tailnet devices into IPAM. Connect tenants from the Tailscale page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.unifi",
        label="UniFi",
        group="Integrations",
        description="Read-only mirror of UniFi networks + clients into IPAM. Supports local + cloud-hosted controllers; connect controllers from the UniFi page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.cloud",
        label="Cloud (AWS / Azure / GCP)",
        group="Integrations",
        description="Read-only mirror of public-cloud infrastructure (VPCs / subnets / instance NICs / public + load-balancer IPs) into IPAM. Connect accounts from the Cloud page once enabled. (Cloud DNS is managed separately via the Add DNS server flow.)",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.opnsense",
        label="OPNsense",
        group="Integrations",
        description="Read-only mirror of OPNsense interfaces + DHCP leases + reservations into IPAM.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.netbird",
        label="NetBird",
        group="Integrations",
        description="Read-only mirror of NetBird mesh peers into IPAM (self-hosted or cloud), with optional synthetic DNS for the mesh domain. Connect instances from the NetBird page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.paloalto",
        label="Palo Alto (PAN-OS / Panorama)",
        group="Integrations",
        description="Read-only mirror of Palo Alto address objects/groups + NAT rules (+ optional zones/interfaces and DHCP leases) into IPAM, with a drift report vs your IPAM subnets. Optional Dynamic Address Group enforcement (commit-free User-ID tag register) is a separate, default-off master switch gated by the Active block sync module. Connect firewalls from the Palo Alto page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.fortinet",
        label="Fortinet (FortiGate)",
        group="Integrations",
        description="Read-only mirror of FortiGate address objects/groups + VIPs (destination NAT) (+ optional interfaces and DHCP leases) into IPAM, with a drift report vs your IPAM subnets. Enforcement is credential-free: point a FortiGate External Threat Feed at a SpatiumDDI-hosted block-list URL (Active block sync module). Connect firewalls from the Fortinet page once enabled.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="integrations.meraki",
        label="Cisco Meraki (MX)",
        group="Integrations",
        description="Read-only mirror of a Meraki organization's appliance VLANs → subnets, DHCP fixed-IP reservations → IPAM, org policy objects/groups → firewall objects, and 1:1 NAT / port-forward → NAT mappings (+ optional network clients). Optional per-client Blocked enforcement (move a client to a restrictive device policy via the Dashboard API — no on-prem deploy) is a separate, default-off master switch gated by the Active block sync module. Connect an org from the Meraki page once enabled.",
        default_enabled=False,
    ),
    # Appliance — the declarative fleet-firewall policy surface (#285
    # Phase 3). One of the few kept ON by #1069, and deliberately: on an
    # appliance a per-role nftables policy is ALREADY filtering traffic
    # (the supervisor renders it from role assignments regardless of this
    # module), so turning the editor off would hide the only window onto a
    # firewall that is running either way. Off-appliance the whole Appliance
    # section is beside the point, not actively misleading.
    # DISCOVERY/STAGING only: turning this module ON exposes the policy
    # editor + preview but applies NOTHING.
    # Enforcement is a SEPARATE master switch (platform_settings.
    # firewall_enabled, default OFF) — flipping the module does not change
    # any node's firewall. The two gates are intentionally distinct so an
    # operator authors + previews policy long before arming enforcement.
    ModuleSpec(
        id="appliance.firewall",
        label="Fleet Firewall",
        group="Appliance",
        description="Declarative per-role, fleet-wide appliance firewall policy compiled to nftables. DISCOVERY/STAGING only — enforcement is a separate master switch (the Enforcement card under Appliance → Firewall → Policies; default OFF). Enabling this module does NOT apply any firewall.",
    ),
    # Security — embedded ACME client for the Web UI TLS cert (#438).
    # Default-ENABLED deliberately: the module is the DISCOVERY toggle so
    # operators see the "Issue via Let's Encrypt" affordance exists.
    # Issuance itself is separately RBAC-gated (admin,appliance) AND
    # gated on the operator's explicit ``platform_settings.acme_enabled``
    # intent, so a default-on module does NOT auto-issue anything.
    ModuleSpec(
        id="security.certificates",
        label="Certificates (ACME / Let's Encrypt)",
        group="Security",
        description="Embedded RFC 8555 ACME client that issues a CA-trusted Web UI TLS cert from Let's Encrypt, solving the DNS-01 challenge through SpatiumDDI's own managed DNS zones. Discovery toggle only — issuance is RBAC-gated and requires an explicit operator opt-in: registering an ACME account, under Appliance → Fleet → Web UI Certificate → Issue via Let's Encrypt.",
    ),
    # Default-OFF (#1069): armed, this reaches out and opens TLS connections
    # to endpoints on a schedule, and its discovery half can mint its own
    # targets from DNS records. Both halves are additionally inert until an
    # operator opts a zone / record in (``auto_tls_probe``) or adds a target
    # by hand, so nothing runs on a fresh install either way — the module is
    # off because a monitor that dials out is a posture, not a default.
    ModuleSpec(
        id="security.tls_certs",
        label="TLS certificate monitoring",
        group="Security",
        description="Watch external TLS endpoints for expiry / chain validity / SAN drift; auto-discover probe targets from DNS A/AAAA records; alert on approaching expiry, broken chains, unreachable endpoints, and unexpected cert changes. Read-only monitoring — distinct from the ACME client that issues the appliance's own cert.",
        default_enabled=False,
    ),
    # Governance — change-gating + approval workflows. Default-off so
    # existing installs see zero behaviour change until opted in (#62).
    ModuleSpec(
        id="governance.approvals",
        label="Approval workflows",
        group="Security",
        description="Two-person approval gating for high-blast-radius operations (deletes, bulk ops, factory reset, large imports). A risky action submitted by one operator is queued as a change request and only executes after a *different* eligible approver accepts it — the operation then runs under the approver's identity with the audit log carrying both user IDs. Default-off: when disabled (or no policy matches) every covered handler executes inline exactly as today.",
        default_enabled=False,
    ),
    ModuleSpec(
        id="governance.requests",
        label="Self-service request portal",
        group="Security",
        description=(
            "Lets low-privilege users request IP addresses, subnets, DNS records and "
            "DHCP reservations they cannot create themselves. A request provisions "
            "nothing on its own: it queues a pending row that a different operator — "
            "who must hold the underlying operation's own permission — reviews with a "
            "live preview and approves, at which point the SAME service-layer call a "
            "manual create would make runs under the approver's identity. Reuses the "
            "#62 approval lifecycle rather than a second state machine, so every "
            "transition is audited and the expiry sweep is shared. Default-off: the "
            "portal is a delegation model, and an operator should opt into delegating."
        ),
        default_enabled=False,
    ),
    # UI — cross-cutting personalisation surfaces. Per-user, never shared.
    ModuleSpec(
        id="ui.saved_views",
        label="Saved views",
        group="UI",
        description='Per-user named filter/sort/column presets on list pages — "All subnets in DC1 over 80% utilization, sorted by name" becomes a one-click view. Personal-only; no cross-user visibility.',
    ),
    # Security — arpwatch-style new-device detection. Default-off: watching is
    # noisy and needs a baseline import before it is useful (#459).
    ModuleSpec(
        id="security.new_device_watch",
        label="New device watch",
        group="Security",
        description="Alert the moment a previously-unseen MAC address appears on the network (arpwatch-style), across DHCP leases, SNMP ARP/FDB, and an opt-in L2 sniffer. Maintain an allowlist of trusted MACs (or OUI prefixes for VMs/containers), acknowledge or block from a review queue, and fire a real-time device.first_seen event. Default-off: enable, run a baseline import to mark the existing fleet as known, then arm.",
        default_enabled=False,
    ),
    # Security — DNS threat analytics (#699). Default-off on privacy
    # grounds, not on noise grounds: scoring reads query *content*
    # (the names clients look up), which is a posture operators should
    # opt into deliberately rather than inherit from an upgrade. It is
    # additionally inert until a DNS group turns on query logging.
    ModuleSpec(
        id="security.dns_threat",
        label="DNS threat analytics",
        group="Security",
        description=(
            "Score DNS clients for tunneling/exfiltration behaviour (iodine / "
            "dnscat2-shaped traffic that walks past a firewall untouched) from "
            "the query log SpatiumDDI already collects — long high-entropy "
            "labels, many unique subdomains under one parent, elevated "
            "TXT/NULL/CNAME ratio. Findings surface as an alert, a Threat tab "
            "on Logs, and a Security dashboard card, and deep-link to the IP so "
            "the device profile is one click away. Default-off: this reads the "
            "names clients look up. Requires query logging enabled on a DNS "
            "server group."
        ),
        default_enabled=False,
        requires=("core.dns",),
    ),
    # Security — active block sync / write-back enforcement (#601). The
    # deliberate, guarded exception to the read-only-mirror stance: pushes
    # SpatiumDDI-owned IP/MAC blocks into OPNsense (firewall table alias)
    # and UniFi (L2 client quarantine). Default-OFF — the whole surface is
    # dark until an operator opts in, AND every push additionally requires
    # a per-target ``block_sync_enabled`` master switch + distinct
    # write-scoped credentials. Turning this module ON exposes the surface
    # but arms nothing.
    ModuleSpec(
        id="security.block_sync",
        label="Active block sync (firewall enforcement)",
        group="Security",
        description="Turn passive rogue-device / new-MAC detection into active enforcement: push a SpatiumDDI-owned block set of IPs / MACs into OPNsense (firewall table-alias membership) and UniFi (L2 client quarantine), so a device that self-assigns a static IP is stopped at the firewall/gateway — not only starved of DHCP. Default-off and heavily guarded: each target has its own default-off enforcement master switch + distinct write-scoped credentials, every push is previewable + audited + RBAC-gated (manage_block_sync) + eligible for two-person approval. Discovery toggle only — enabling this arms nothing on its own.",
        default_enabled=False,
    ),
    # Security — SpatiumDDI-hosted firewall block-list feeds (#606, the "feed
    # inversion"). Default-OFF (#1069): it is an enforcement surface, and it
    # pairs with Active block sync, which has always been off. No feed serves
    # anything until an operator creates one (each is token-scoped). This
    # is the credential-free enforcement path — a FortiGate External Threat
    # Feed / Cisco Security-Intelligence feed polls a SpatiumDDI URL instead of
    # SpatiumDDI holding write creds on the firewall.
    ModuleSpec(
        id="security.firewall_feeds",
        label="Firewall block-list feeds",
        group="Security",
        description="Serve the SpatiumDDI block set (the same IP/MAC intent the Active block sync module pushes) as token-scoped block-list URLs that feed-polling firewalls subscribe to — FortiGate External Threat Feed, Cisco Security Intelligence, Check Point IOC — so the firewall enforces with NO write credentials held by SpatiumDDI. Discovery toggle only: enabling this exposes the feeds page but serves nothing until you create a feed.",
        default_enabled=False,
    ),
    # Security — DNSBL / RBL reputation monitoring (#528). Default-OFF
    # (#1069): armed, it queries public blocklist operators about the
    # operator's own address space, which is an off-prem call they should
    # choose. It additionally makes ZERO queries until the master
    # ``dnsbl_monitoring_enabled`` sweep switch is on AND at least one
    # blocklist is enabled, so the module toggle is the outer of two gates.
    ModuleSpec(
        id="security.dnsbl",
        label="DNSBL / RBL reputation monitoring",
        group="Security",
        description="Check every public-facing IP SpatiumDDI knows (public IPAM addresses, internet-facing subnets, NAT/PAT egress addresses, and operator-pinned IPs) against the major DNS blocklists (Spamhaus ZEN, Barracuda, SpamCop, SORBS, …) on a daily reversed-octet sweep — catching mail-deliverability / reputation problems before users report them. Discovery toggle only: no external DNS queries run until you enable the sweep (Administration → DNS Blocklists → Enable daily sweep) and turn on at least one list.",
        default_enabled=False,
        requires=("core.dns",),
    ),
)

# Map a feature_module id to the ``PlatformSettings`` column whose
# ``True``/``False`` value mirrors it. The toggle endpoint writes both
# sides in the same transaction so reconciler tasks (which gate on the
# settings column) see the change without a separate migration. New
# integrations register here in the same PR that adds them.
INTEGRATION_SETTINGS_MIRROR: Final[dict[str, str]] = {
    "integrations.kubernetes": "integration_kubernetes_enabled",
    "integrations.docker": "integration_docker_enabled",
    "integrations.proxmox": "integration_proxmox_enabled",
    "integrations.tailscale": "integration_tailscale_enabled",
    "integrations.unifi": "integration_unifi_enabled",
    "integrations.cloud": "integration_cloud_enabled",
    "integrations.opnsense": "integration_opnsense_enabled",
    "integrations.netbird": "integration_netbird_enabled",
    "integrations.paloalto": "integration_panos_enabled",
}

MODULES_BY_ID: Final[dict[str, ModuleSpec]] = {m.id: m for m in MODULES}


def all_module_ids() -> set[str]:
    return set(MODULES_BY_ID.keys())


def is_known(module_id: str) -> bool:
    return module_id in MODULES_BY_ID


# ── Enabled-set cache ──────────────────────────────────────────────────
#
# Process-local cache — the toggle set is tiny (~14 rows) and changes
# rarely, so we cache it for a short TTL rather than hitting the DB on
# every request. ``invalidate_cache`` is called from the toggle endpoint
# so an admin's flip takes effect immediately for that worker. Other
# workers pick it up at their next TTL expiry (within ``_CACHE_TTL_S``).

_CACHE_TTL_S: Final[float] = 5.0
_cache_loaded_at: float = 0.0
_cached_enabled: set[str] = set()


def invalidate_cache() -> None:
    """Drop the cached enabled-set. Called from the admin toggle so the
    flipping worker sees the change instantly."""
    global _cache_loaded_at
    _cache_loaded_at = 0.0


def _resolve_with_parents(
    module_id: str, own: dict[str, bool], _seen: frozenset[str] = frozenset()
) -> bool:
    """Is ``module_id`` enabled, accounting for ``requires`` (#1068)?

    A module is enabled only when its own state is on AND every ancestor
    resolves enabled. Without this a child could sit on while its parent
    is off — which does not read as "partly on", it reads as a sidebar
    row and a mounted router pointing at a subsystem the operator turned
    off.

    An unknown parent id resolves TRUE, matching ``is_module_enabled``:
    a renamed or removed module must never silently disable its
    children. Cycles resolve FALSE for the repeated id rather than
    recursing forever; ``tests/test_feature_module_defaults.py`` refuses
    a cyclic or dangling ``requires`` at the catalog level, so this is a
    backstop and not the enforcement.
    """
    if module_id in _seen:
        return False
    if module_id not in own:
        return True
    if not own[module_id]:
        return False
    spec = MODULES_BY_ID.get(module_id)
    if spec is None or not spec.requires:
        return True
    seen = _seen | {module_id}
    return all(_resolve_with_parents(parent, own, seen) for parent in spec.requires)


async def get_enabled_modules(db: AsyncSession) -> set[str]:
    """Return the set of currently-enabled module ids.

    Resolved as:
        for each module in the catalog:
            if a DB override exists, honour it
            else honour the catalog's default_enabled
        then drop any module whose ``requires`` chain is not fully
        enabled (#1068).
    """
    global _cache_loaded_at, _cached_enabled
    now = time.monotonic()
    if now - _cache_loaded_at < _CACHE_TTL_S and _cached_enabled:
        return _cached_enabled

    rows = (await db.execute(select(FeatureModule))).scalars().all()
    overrides: dict[str, bool] = {row.id: row.enabled for row in rows}

    own: dict[str, bool] = {
        spec.id: overrides.get(spec.id, spec.default_enabled) for spec in MODULES
    }
    enabled = {mid for mid in own if _resolve_with_parents(mid, own)}

    _cached_enabled = enabled
    _cache_loaded_at = now
    return enabled


async def is_module_enabled(db: AsyncSession, module_id: str) -> bool:
    """Convenience wrapper. Unknown ids resolve to True so a renamed/
    removed module never accidentally hides a route — defensive. The
    catalog itself is the source of truth for what's gateable."""
    if not is_known(module_id):
        return True
    enabled = await get_enabled_modules(db)
    return module_id in enabled


async def set_module_enabled(
    db: AsyncSession,
    module_id: str,
    enabled: bool,
    *,
    user_id,  # type: ignore[no-untyped-def]
) -> FeatureModule:
    """Upsert the override. Caller commits + writes audit + invalidates
    the cache. Raises ``ValueError`` if the id isn't in the catalog."""
    if not is_known(module_id):
        raise ValueError(f"Unknown feature module: {module_id!r}")
    stmt = (
        pg_insert(FeatureModule)
        .values(
            id=module_id,
            enabled=enabled,
            updated_at=datetime.now(UTC),
            updated_by_id=user_id,
        )
        .on_conflict_do_update(
            index_elements=[FeatureModule.id],
            set_=dict(
                enabled=enabled,
                updated_at=datetime.now(UTC),
                updated_by_id=user_id,
            ),
        )
        .returning(FeatureModule)
    )
    row = (await db.execute(stmt)).scalar_one()
    return row


# ── FastAPI dependency ─────────────────────────────────────────────────


def require_module(module_id: str):
    """Build a FastAPI dependency that 404s when ``module_id`` is
    disabled. Apply at the router level::

        api_v1_router.include_router(
            customers_router,
            prefix="/customers",
            dependencies=[Depends(require_module("network.customer"))],
            tags=["customers"],
        )

    404 (not 403) so the API surface mirrors what an air-gapped
    deployment would look like with the module not installed.
    """
    if not is_known(module_id):
        # Catch typos at app-boot so we never deploy a gate against a
        # nonexistent module id.
        raise RuntimeError(f"require_module: unknown module {module_id!r}")

    async def _gate(db: AsyncSession = Depends(get_db)) -> None:
        if not await is_module_enabled(db, module_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Feature '{module_id}' is disabled.",
            )

    return _gate


def filter_to_enabled_tools(
    *,
    enabled_modules: Iterable[str],
    tool_modules: dict[str, str | None],
) -> set[str]:
    """Given a map of ``tool_name -> module_id`` (or None for "always
    enabled"), return the set of tool names that survive the module
    filter. Used by the MCP registry layer to strip tools whose module
    is disabled, regardless of per-tool default_enabled.
    """
    enabled_set = set(enabled_modules)
    return {name for name, mod in tool_modules.items() if mod is None or mod in enabled_set}
