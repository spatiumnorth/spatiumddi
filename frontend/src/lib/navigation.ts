import {
  Activity,
  AlertTriangle,
  AudioLines,
  BarChart3,
  BellRing,
  Binoculars,
  Bird,
  Boxes,
  Briefcase,
  Building2,
  Cable,
  Calculator,
  ClipboardList,
  Cloud,
  Code2,
  Container as ContainerIcon,
  Cpu,
  Database,
  Earth,
  Factory,
  Flame,
  GitPullRequest,
  Globe,
  HardDrive,
  Hash,
  History,
  Inbox,
  KeyRound,
  KeySquare,
  LayoutDashboard,
  LayoutTemplate,
  MapPin,
  Monitor,
  Network,
  Package,
  Power,
  Radio,
  Route as RouteIcon,
  Router as RouterIcon,
  Rss,
  Scan,
  ScrollText,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  ShieldQuestion,
  Shuffle,
  Siren,
  Sparkles,
  Spline,
  Tags,
  ToggleLeft,
  Trash2,
  Truck,
  Upload,
  Users,
  UsersRound,
  Waypoints,
  Webhook,
  Wifi,
  Workflow,
  Wrench,
} from "lucide-react";

/**
 * The sidebar's navigation tree, extracted so more than one surface can
 * read it (issue #879).
 *
 * It lives here rather than inside `Sidebar.tsx` because the Cmd/Ctrl+K
 * command palette also needs it. A second hand-maintained list of pages
 * would drift the first time somebody adds a route and updates only the
 * sidebar — the same argument `lib/shortcuts.ts` makes for keybindings
 * (#737): one definition, several consumers, so retuning it moves
 * everything at once.
 *
 * Module gating is data on the entry, not a branch at the render site, so
 * both consumers apply it identically via {@link navEntryVisible}.
 */
export interface NavEntry {
  label: string;
  icon: React.ElementType;
  to: string;
  /** Feature-module id gating this entry. */
  module?: string;
  /** Visible while ANY of these modules is on (consolidated entries). */
  anyModule?: string[];
  /** react-router `end` matching for the active state. */
  end?: boolean;
}

export interface NavExternalEntry {
  label: string;
  icon: React.ElementType;
  href: string;
}

// Core section. The four canonical anchors (Dashboard / IPAM / DHCP / DNS)
// stay first and prominent; grown-in sub-features group under lightweight
// sub-headings by family below.
export const baseMainNav: NavEntry[] = [
  { label: "Dashboard", icon: LayoutDashboard, to: "/dashboard" },
  { label: "IPAM", icon: Network, to: "/ipam", end: true },
  // #1068 — the two subsystems an install may legitimately not run. Both
  // ship enabled; an IPAM-only or single-subsystem install turns the
  // unused one off under Settings → Features and the anchor goes with it.
  { label: "DHCP", icon: Server, to: "/dhcp", module: "core.dhcp" },
  { label: "DNS", icon: Globe, to: "/dns", end: true, module: "core.dns" },
  // #696 — top-level rather than under Administration on purpose: the
  // audience is ordinary users asking for a resource, and most of them will
  // never see the admin section at all.
  {
    label: "Requests",
    icon: Inbox,
    to: "/requests",
    module: "governance.requests",
  },
];

// IPAM-family children (all route under /ipam/*). Alphabetised, matching the
// Network/Administration sub-group convention.
export const coreIpamNav: NavEntry[] = [
  {
    label: "NAT Mappings",
    icon: Shuffle,
    to: "/ipam/nat",
    module: "ipam.nat",
  },
  { label: "Stale IPs", icon: History, to: "/ipam/stale" },
  { label: "Subnet Planner", icon: Workflow, to: "/ipam/plans" },
];

// DNS-family children. "Domains" keeps its /admin/domains route — it's the
// registrar/expiry/RDAP registry side of a name (linked to dns_zone.domain_id),
// so it belongs beside DNS in the sidebar even though the route lives under
// /admin.
export const dnsSectionNav: NavEntry[] = [
  { label: "DNS Pools", icon: Workflow, to: "/dns/pools", module: "core.dns" },
  {
    label: "DNSSEC Policies",
    icon: KeyRound,
    to: "/dns/dnssec-policies",
    module: "core.dns",
  },
  // Domains is deliberately NOT gated on core.dns (#1068): a Domain is the
  // registrar / expiry / RDAP record for a name, which exists whether or not
  // SpatiumDDI serves a zone for it — an operator tracking renewals on names
  // hosted elsewhere still wants this with DNS off. It has its own module
  // (#2325) because it is the one that makes off-prem RDAP lookups.
  {
    label: "Domains",
    icon: Earth,
    to: "/admin/domains",
    module: "network.domains",
  },
];

// Operations — cross-cutting live telemetry.
export const operationsNav: NavEntry[] = [
  { label: "Logs", icon: ScrollText, to: "/logs" },
];

// Network → Logical: operator-facing ownership / deliverable rows that
// cross-cut every other resource type.
export const networkLogicalNav: NavEntry[] = [
  {
    label: "Customers",
    icon: Briefcase,
    to: "/network/customers",
    module: "network.customer",
  },
  {
    label: "Providers",
    icon: Truck,
    to: "/network/providers",
    module: "network.provider",
  },
  {
    label: "Services",
    icon: Package,
    to: "/network/services",
    module: "network.service",
  },
  {
    label: "Sites",
    icon: MapPin,
    to: "/network/sites",
    module: "network.site",
  },
];

// Network → Infrastructure: the actual network entities. Alphabetised so
// new entries slot in without reshuffling.
export const networkInfrastructureNav: NavEntry[] = [
  { label: "ASNs", icon: Hash, to: "/network/asns", module: "network.asn" },
  {
    label: "AV over IP",
    icon: AudioLines,
    to: "/network/av",
    module: "network.av",
  },
  {
    label: "BACnet Devices",
    icon: Building2,
    to: "/network/bacnet",
    module: "network.bacnet",
  },
  {
    label: "Certificates",
    icon: ShieldCheck,
    to: "/network/certificates",
    module: "security.tls_certs",
  },
  {
    label: "Circuits",
    icon: Waypoints,
    to: "/network/circuits",
    module: "network.circuit",
  },
  {
    label: "DICOM AEs",
    icon: Scan,
    to: "/network/dicom",
    module: "network.dicom",
  },
  {
    label: "E911 locations",
    icon: Siren,
    to: "/network/e911",
    module: "network.e911",
  },
  {
    label: "Devices",
    icon: Cable,
    to: "/network/devices",
    module: "network.device",
  },
  {
    label: "Looking Glass",
    icon: Binoculars,
    to: "/network/looking-glass",
    module: "network.looking_glass",
  },
  {
    label: "Multicast",
    icon: Radio,
    to: "/network/multicast",
    module: "network.multicast",
  },
  {
    label: "OT Devices",
    icon: Factory,
    to: "/network/ot",
    module: "network.ot",
  },
  {
    label: "Overlays",
    icon: Spline,
    to: "/network/overlays",
    module: "network.overlay",
  },
  {
    label: "VLANs",
    icon: RouterIcon,
    to: "/network/vlans",
    module: "network.vlan",
  },
  {
    label: "VRFs",
    icon: RouteIcon,
    to: "/network/vrfs",
    module: "network.vrf",
  },
];

// Keep this list alphabetised by label.
export const toolsNav: NavEntry[] = [
  {
    label: "Block Sync",
    icon: ShieldBan,
    to: "/security/block-sync",
    module: "security.block_sync",
  },
  { label: "CIDR Calculator", icon: Calculator, to: "/tools/cidr" },
  {
    label: "Firewall Feeds",
    icon: Rss,
    to: "/security/firewall-feeds",
    module: "security.firewall_feeds",
  },
  {
    label: "Network Tools",
    icon: Wrench,
    to: "/tools/network",
    module: "tools.network",
  },
  {
    label: "New Devices",
    icon: ShieldQuestion,
    to: "/security/new-devices",
    module: "security.new_device_watch",
  },
  { label: "Nmap", icon: Search, to: "/tools/nmap", module: "tools.nmap" },
  {
    label: "Packet Capture",
    icon: Activity,
    to: "/tools/pcap",
    module: "tools.pcap",
  },
  {
    label: "Wake Schedules",
    icon: Power,
    to: "/tools/wake-schedules",
    module: "tools.wake_scheduler",
  },
];

// Reports section (issue #47) — fixed Top-N rollups derived from existing
// tables. Module-gated so operators who don't want the surface can hide it.
export const reportsNav: NavEntry[] = [
  {
    label: "Top-N Reports",
    icon: BarChart3,
    to: "/reports",
    module: "reports.top_n",
  },
];

// Integrations. Previously assembled inline in the sidebar as a chain of
// `moduleEnabled(...) ? [entry] : []` spreads; the module id is now data on
// the entry like every other group, so the shared filter handles it and the
// palette can read the list without re-implementing the gating.
// Alphabetised by label — adding an integration shouldn't re-shuffle the
// sidebar for operators already using it.
export const integrationsNav: NavEntry[] = [
  { label: "Cloud", icon: Cloud, to: "/cloud", module: "integrations.cloud" },
  {
    label: "Docker",
    icon: ContainerIcon,
    to: "/docker",
    module: "integrations.docker",
  },
  {
    label: "Fortinet",
    icon: Flame,
    to: "/fortinet",
    module: "integrations.fortinet",
  },
  {
    label: "Kubernetes",
    icon: Boxes,
    to: "/kubernetes",
    module: "integrations.kubernetes",
  },
  {
    label: "Meraki",
    icon: Network,
    to: "/meraki",
    module: "integrations.meraki",
  },
  {
    label: "NetBird",
    icon: Bird,
    to: "/netbird",
    module: "integrations.netbird",
  },
  {
    label: "OPNsense",
    icon: ShieldCheck,
    to: "/opnsense",
    module: "integrations.opnsense",
  },
  {
    label: "Palo Alto",
    icon: ShieldAlert,
    to: "/paloalto",
    module: "integrations.paloalto",
  },
  {
    label: "Proxmox",
    icon: HardDrive,
    to: "/proxmox",
    module: "integrations.proxmox",
  },
  {
    label: "Tailscale",
    icon: Waypoints,
    to: "/tailscale",
    module: "integrations.tailscale",
  },
  { label: "UniFi", icon: Wifi, to: "/unifi", module: "integrations.unifi" },
];

export const adminIdentityNav: NavEntry[] = [
  { label: "API Tokens", icon: KeySquare, to: "/admin/api-tokens" },
  { label: "Auth Providers", icon: ShieldCheck, to: "/admin/auth-providers" },
  { label: "Groups", icon: UsersRound, to: "/admin/groups" },
  { label: "Roles", icon: KeyRound, to: "/admin/roles" },
  { label: "Sessions", icon: Monitor, to: "/admin/sessions" },
  { label: "Users", icon: Users, to: "/admin/users" },
];

export const adminConfigurationNav: NavEntry[] = [
  {
    label: "AI Providers",
    icon: Sparkles,
    to: "/admin/ai/providers",
    module: "ai.copilot",
  },
  {
    label: "AI Prompts",
    icon: Sparkles,
    to: "/admin/ai/prompts",
    module: "ai.copilot",
  },
  {
    label: "AI Tool Catalog",
    icon: Sparkles,
    to: "/admin/ai/tools",
    module: "ai.copilot",
  },
  { label: "Custom Fields", icon: Tags, to: "/admin/custom-fields" },
  // Import hub (#36) — the one-shot DHCP (#129) / DNS (#128) / NetBox (#36)
  // importers plus the guided Windows cutover (#756) share a single
  // Configuration entry with a left sub-nav. ``anyModule`` hides the entry
  // only when ALL of those modules are off.
  {
    label: "Import",
    icon: Upload,
    to: "/admin/import",
    anyModule: [
      "dhcp.import",
      "dns.import",
      "ipam.import.netbox",
      "migration.cutover",
    ],
  },
  {
    label: "IPAM Templates",
    icon: LayoutTemplate,
    to: "/admin/ipam/templates",
  },
];

export const adminNotificationsNav: NavEntry[] = [
  { label: "Alerts", icon: BellRing, to: "/admin/alerts" },
  {
    label: "DNS Blocklists",
    icon: ShieldAlert,
    to: "/admin/dns-blocklists",
    module: "security.dnsbl",
  },
  {
    label: "Change Requests",
    icon: GitPullRequest,
    to: "/admin/change-requests",
    module: "governance.approvals",
  },
  { label: "Webhooks", icon: Webhook, to: "/admin/webhooks" },
];

export const adminInsightsNav: NavEntry[] = [
  { label: "Audit Log", icon: ClipboardList, to: "/admin/audit" },
  { label: "Backup", icon: Database, to: "/admin/backup" },
  { label: "Compliance", icon: ShieldCheck, to: "/admin/compliance" },
  {
    label: "Conformity",
    icon: ShieldCheck,
    to: "/admin/conformity",
    module: "compliance.conformity",
  },
  // Diagnostics → Errors (issue #123). Visible to all admins; the backend
  // enforces superadmin on read, so non-superadmins land on a 403 page. We
  // don't gate the nav entry itself so superadmins discover it.
  {
    label: "Diagnostics",
    icon: AlertTriangle,
    to: "/admin/diagnostics/errors",
  },
  { label: "Platform Insights", icon: Cpu, to: "/admin/platform-insights" },
  { label: "Trash", icon: Trash2, to: "/admin/trash" },
];

// External documentation links — opened in a new tab.
export const adminReferenceNav: NavExternalEntry[] = [
  { label: "API Docs", icon: Code2, href: "/api/redoc" },
  { label: "API Docs (interactive)", icon: Code2, href: "/api/docs" },
];

// Footer entries. These render in the sidebar's footer rather than in a
// section — they are ungated, always-visible destinations — but they are
// real pages and belong in the palette. Labels and icons mirror what the
// footer renders so the two read as the same entry.
export const footerNav: NavEntry[] = [
  { label: "Appliance", icon: Wrench, to: "/appliance" },
  { label: "Features & Integrations", icon: ToggleLeft, to: "/admin/features" },
  { label: "Settings", icon: Settings, to: "/settings" },
];

/**
 * Every in-app destination, tagged with the section it appears under.
 *
 * The section name is what the palette shows as context ("Network",
 * "Administration"), so an operator who types "vlan" can tell the VLANs
 * *page* from a VLAN *record*.
 */
export const NAV_SECTIONS: { section: string; items: NavEntry[] }[] = [
  { section: "Core", items: baseMainNav },
  { section: "IPAM", items: coreIpamNav },
  { section: "DNS", items: dnsSectionNav },
  { section: "Operations", items: operationsNav },
  { section: "Network", items: networkLogicalNav },
  { section: "Network", items: networkInfrastructureNav },
  { section: "Tools", items: toolsNav },
  { section: "Reports", items: reportsNav },
  { section: "Integrations", items: integrationsNav },
  { section: "Administration", items: adminIdentityNav },
  { section: "Administration", items: adminConfigurationNav },
  { section: "Administration", items: adminNotificationsNav },
  { section: "Administration", items: adminInsightsNav },
  { section: "System", items: footerNav },
];

export interface NavDestination extends NavEntry {
  section: string;
}

export const ALL_NAV_DESTINATIONS: NavDestination[] = NAV_SECTIONS.flatMap(
  ({ section, items }) => items.map((item) => ({ ...item, section })),
);

/** Shared module-gating predicate for a nav entry. */
export function navEntryVisible(
  entry: Pick<NavEntry, "module" | "anyModule">,
  moduleEnabled: (id: string) => boolean,
): boolean {
  if (entry.module && !moduleEnabled(entry.module)) return false;
  if (entry.anyModule && !entry.anyModule.some((m) => moduleEnabled(m)))
    return false;
  return true;
}

/** Filter a nav list by the enabled feature modules. */
export function filterNav<T extends Pick<NavEntry, "module" | "anyModule">>(
  items: T[],
  moduleEnabled: (id: string) => boolean,
): T[] {
  return items.filter((it) => navEntryVisible(it, moduleEnabled));
}
