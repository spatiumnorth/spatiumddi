import { Children, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueries, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Ban,
  Boxes,
  CalendarClock,
  Check,
  ChevronDown,
  ClipboardCheck,
  Clock,
  Cloud,
  Container as ContainerIcon,
  Cpu,
  FileDown,
  FileText,
  Flame,
  Globe,
  Globe2,
  HardDrive,
  Hash,
  KeyRound,
  Layers,
  Lock,
  Network,
  Plug,
  Radio,
  RefreshCw,
  Route,
  Server,
  Bird,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Waypoints,
  Wifi,
  X,
} from "lucide-react";
import {
  ipamApi,
  dnsApi,
  dhcpApi,
  natApi,
  auditApi,
  settingsApi,
  kubernetesApi,
  dockerApi,
  proxmoxApi,
  opnsenseApi,
  panosApi,
  fortinetApi,
  merakiApi,
  cloudApi,
  netbirdApi,
  tailscaleApi,
  unifiApi,
  platformHealthApi,
  asnsApi,
  vrfsApi,
  domainsApi,
  alertsApi,
  conformityApi,
  dashboardsApi,
  dnsThreatApi,
  tlsCertsApi,
  newDeviceApi,
  lookingGlassApi,
  type IPSpace,
  type Subnet,
  type DNSServer,
  type DHCPServer,
  type DHCPServerGroup,
  type DNSServerGroup,
  type KubernetesCluster,
  type DockerHost,
  type ProxmoxNode,
  type OPNsenseRouter,
  type PANOSFirewall,
  type FortinetFirewall,
  type MerakiOrg,
  type CloudEndpoint,
  type NetbirdInstance,
  type TailscaleTenant,
  type UnifiController,
  type PlatformHealthResponse,
  type PlatformHealthStatus,
  type ASNRead,
  type VRF,
  type Domain,
  type AlertEvent,
  type ConfigApplyStatus,
  type AlertRule,
  type ConformityResult,
  type ConformitySummary,
  type NetworkDashboardSummary,
  type IntegrationsDashboardSummary,
  type IntegrationsDashboardPanel,
  type SecurityDashboardSummary,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { includeInUtilization } from "@/lib/utilization";
import { useSessionState } from "@/lib/useSessionState";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { DHCPTrafficCard, DNSQueryRateCard } from "@/components/MetricsCharts";
import { WidgetErrorBoundary } from "@/components/WidgetErrorBoundary";

/**
 * Dashboard — the home page.
 *
 * Layout:
 *   1. Title row with a live status strip (subnet count + aggregated
 *      health pill) and a "last updated" marker.
 *   2. Six KPI cards — IP Spaces, Subnets, Allocated IPs, Utilization %,
 *      DNS Zones, Servers (DNS + DHCP aggregate).
 *   3. Subnet Utilization Heatmap — every subnet as a colored cell.
 *      The hero element of the page; gives instant at-a-glance signal on
 *      where capacity pressure is.
 *   4. Two-column row — Top Subnets by Utilization (left) + Live
 *      Activity feed (right, audit-log-driven, auto-refreshing).
 *   5. Services panel — all DNS + DHCP servers with status dots.
 *
 * Two time-series cards under the activity row render DNS query rate
 * (BIND9 statistics-channels) and DHCP traffic (Kea statistic-get-all)
 * from the per-server `metric_sample` tables — empty when no agent
 * has reported yet.
 */

// ── Small building blocks ───────────────────────────────────────────────────

type Tone = "default" | "good" | "warn" | "bad" | "info";

const TONE_CLASS: Record<Tone, { value: string; accent: string }> = {
  default: { value: "text-foreground", accent: "bg-muted" },
  good: {
    value: "text-emerald-600 dark:text-emerald-400",
    accent: "bg-emerald-500",
  },
  warn: { value: "text-amber-600 dark:text-amber-400", accent: "bg-amber-500" },
  bad: { value: "text-red-600 dark:text-red-400", accent: "bg-red-500" },
  info: { value: "text-blue-600 dark:text-blue-400", accent: "bg-blue-500" },
};

function KpiCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "default",
  to,
}: {
  label: string;
  value: string | number;
  sub?: React.ReactNode;
  icon: React.ElementType;
  tone?: Tone;
  to?: string;
}) {
  const cls = TONE_CLASS[tone];
  const inner = (
    <div className="group relative rounded-lg border bg-card p-4 transition-colors hover:bg-accent/40">
      {/* Accent stripe */}
      <div
        className={cn(
          "absolute inset-y-0 left-0 w-0.5 rounded-l-lg",
          cls.accent,
        )}
      />
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      <p className={cn("mt-2 text-2xl font-bold tabular-nums", cls.value)}>
        {value}
      </p>
      {sub && <p className="mt-0.5 text-[11px] text-muted-foreground">{sub}</p>}
    </div>
  );
  return to ? <Link to={to}>{inner}</Link> : inner;
}

function UtilColor(percent: number): string {
  if (percent >= 95) return "bg-red-500";
  if (percent >= 85) return "bg-red-400";
  if (percent >= 70) return "bg-amber-400";
  if (percent >= 50) return "bg-emerald-500";
  if (percent >= 25) return "bg-emerald-400";
  if (percent > 0) return "bg-emerald-300";
  return "bg-muted/60 dark:bg-muted/40";
}

/** One entry in the Overview inventory strip (#942) — a value, its unit,
 *  and the same click-through the KPI card it replaced had. */
function InventoryStat({
  value,
  label,
  to,
  title,
  tone,
}: {
  value: string | number;
  label: string;
  to: string;
  title?: string;
  tone?: "warn" | "bad";
}) {
  return (
    <Link
      to={to}
      title={title}
      className="inline-flex items-baseline gap-1.5 rounded px-2 py-0.5 transition-colors hover:bg-accent/60"
    >
      <span
        className={cn(
          "font-semibold tabular-nums",
          tone === "bad"
            ? "text-red-600 dark:text-red-400"
            : tone === "warn"
              ? "text-amber-600 dark:text-amber-400"
              : "text-foreground",
        )}
      >
        {value}
      </span>
      <span className="text-muted-foreground">{label}</span>
    </Link>
  );
}

/** True for an IPv6 prefix, whose capacity numbers are not comparable
 *  to a v4 subnet's and must not be rendered as if they were. */
function isV6(network: string): boolean {
  return network.includes(":");
}

/**
 * Capacity label for one subnet row (#942).
 *
 * A v6 prefix's ``total_ips`` is astronomical: a /64 is 2^64, which
 * crosses `Number.MAX_SAFE_INTEGER` on the way through JSON and renders
 * as "9223372036854776000" — a number that is both wrong and wide
 * enough to wrap the row. The page already refuses to fold v6 into the
 * aggregate totals for exactly this reason (see the reportingV4 /
 * reportingV6 split); rows follow the same rule and show the allocation
 * count alone, which is the only half that means anything.
 */
function capacityLabel(subnet: {
  network: string;
  allocated_ips: number;
  total_ips: number;
}): string {
  if (isV6(subnet.network)) {
    return `${subnet.allocated_ips.toLocaleString()} alloc`;
  }
  return `${subnet.allocated_ips.toLocaleString()} / ${subnet.total_ips.toLocaleString()}`;
}

function UtilizationBar({
  percent,
  network,
}: {
  percent: number;
  /** When this is a v6 prefix the bar renders n/a: "0%" of a /64 is
   *  true, useless, and indistinguishable from an empty v4 subnet. */
  network?: string;
}) {
  if (network && isV6(network)) {
    return (
      <div className="flex items-center gap-2">
        <div className="h-1.5 flex-1 rounded-full bg-muted/40" />
        <span
          className="w-10 text-right text-xs text-muted-foreground/50"
          title="Utilization is not meaningful for an IPv6 prefix"
        >
          n/a
        </span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 flex-1 rounded-full bg-muted overflow-hidden">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            UtilColor(percent),
          )}
          style={{ width: `${Math.min(percent, 100)}%` }}
        />
      </div>
      <span className="w-10 text-right text-xs tabular-nums text-muted-foreground">
        {percent.toFixed(0)}%
      </span>
    </div>
  );
}

/**
 * Utilisation heatmap. Every managed subnet is one cell; the cell color
 * is keyed to its `utilization_percent`. Hover fires a native tooltip
 * (title attr) so no portal machinery is needed. Clicking jumps to the
 * IPAM page — keeps the dashboard as a launcher rather than a dead
 * end. Cells stay square at every breakpoint via aspect-square +
 * grid-cols-autofill.
 */
function SubnetHeatmap({ subnets }: { subnets: Subnet[] }) {
  if (subnets.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <Network className="mx-auto mb-2 h-8 w-8 text-muted-foreground/30" />
        <p className="text-xs text-muted-foreground">
          No subnets yet — create an IP space + subnet to light up the heatmap.
        </p>
      </div>
    );
  }
  const active = subnets.filter((s) => s.total_ips > 0);
  const avg =
    active.length > 0
      ? active.reduce((s, n) => s + n.utilization_percent, 0) / active.length
      : 0;
  const sorted = [...active]
    .map((s) => s.utilization_percent)
    .sort((a, b) => a - b);
  const p95Index = Math.max(0, Math.floor(sorted.length * 0.95) - 1);
  const p95 = sorted.length > 0 ? sorted[p95Index] : 0;
  const hot = active.filter((s) => s.utilization_percent >= 85).length;

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            Subnet Utilization
          </h3>
          <span className="text-[11px] text-muted-foreground">
            / {subnets.length} subnet{subnets.length === 1 ? "" : "s"}
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-[11px]">
          <div className="flex items-center gap-1">
            <span className="inline-block h-2.5 w-2.5 rounded-sm bg-muted/60" />
            <span className="text-muted-foreground">0%</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="inline-block h-2.5 w-2.5 rounded-sm bg-emerald-300" />
            <span className="text-muted-foreground">25</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="inline-block h-2.5 w-2.5 rounded-sm bg-emerald-500" />
            <span className="text-muted-foreground">50</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="inline-block h-2.5 w-2.5 rounded-sm bg-amber-400" />
            <span className="text-muted-foreground">70</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="inline-block h-2.5 w-2.5 rounded-sm bg-red-400" />
            <span className="text-muted-foreground">85</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="inline-block h-2.5 w-2.5 rounded-sm bg-red-500" />
            <span className="text-muted-foreground">100%</span>
          </div>
        </div>
      </div>
      <div className="p-4">
        <div
          className="grid gap-1.5"
          style={{
            gridTemplateColumns: "repeat(auto-fill, minmax(28px, 1fr))",
          }}
        >
          {subnets.map((s) => (
            <Link
              key={s.id}
              to={`/ipam?subnet=${s.id}`}
              title={`${s.network}${s.name ? ` — ${s.name}` : ""}\n${
                isV6(s.network)
                  ? capacityLabel(s)
                  : `${s.utilization_percent.toFixed(1)}% · ${capacityLabel(s)}`
              }`}
              className={cn(
                "aspect-square rounded transition-all hover:scale-110 hover:ring-2 hover:ring-primary/40",
                UtilColor(s.utilization_percent),
              )}
            />
          ))}
        </div>
        {active.length > 0 && (
          <div className="mt-4 flex items-center justify-between border-t pt-3 text-[11px] text-muted-foreground">
            <span>// hover a cell to inspect · click to open</span>
            <div className="flex gap-4 tabular-nums">
              <span>
                <span className="text-muted-foreground/70">AVG</span>{" "}
                <span className="font-semibold text-foreground">
                  {avg.toFixed(1)}%
                </span>
              </span>
              <span>
                <span className="text-muted-foreground/70">P95</span>{" "}
                <span className="font-semibold text-foreground">
                  {p95.toFixed(0)}%
                </span>
              </span>
              <span>
                <span className="text-muted-foreground/70">HOT</span>{" "}
                <span
                  className={cn(
                    "font-semibold",
                    hot > 0 ? "text-red-500" : "text-foreground",
                  )}
                >
                  {hot}
                </span>
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Audit-log-driven live activity feed. One row per audit entry, color-
 * coded by action family (create=green, update=blue, delete=red,
 * denied=amber, failed=red, login/logout=purple). Clickable rows link
 * to the audit log page where the user can filter more.
 */
function ActionBadge({ action, result }: { action: string; result: string }) {
  // Map both action and result to one of a few colour families.
  let tone: Tone = "info";
  let label = action.toUpperCase();
  if (result === "failed") {
    tone = "bad";
    label = "FAIL";
  } else if (result === "denied") {
    tone = "warn";
    label = "DENY";
  } else if (action === "create") tone = "good";
  else if (action === "delete") tone = "bad";
  else if (action === "update") tone = "info";
  else if (action === "login" || action === "logout") tone = "info";

  const cls = TONE_CLASS[tone];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={cn("inline-block h-1.5 w-1.5 rounded-full", cls.accent)}
      />
      <span className={cn("font-semibold tracking-wider", cls.value)}>
        {label}
      </span>
    </span>
  );
}

function humanTime(ts: string): string {
  const d = new Date(ts);
  const now = Date.now();
  const diff = Math.floor((now - d.getTime()) / 1000);
  if (diff < 10) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}

// Future-facing companion to ``humanTime`` — ``humanTime`` is a
// past-only "N ago" formatter that collapses every future timestamp to
// "just now". Use this for expiry dates (e.g. RPKI ROA ``valid_to``)
// that are by definition in the future.
function futureTime(ts: string): string {
  const d = new Date(ts);
  const diff = Math.floor((d.getTime() - Date.now()) / 1000);
  if (diff <= 0) return "expired";
  if (diff < 3600) return `in ${Math.max(1, Math.floor(diff / 60))}m`;
  if (diff < 86400) return `in ${Math.floor(diff / 3600)}h`;
  const days = Math.floor(diff / 86400);
  if (days <= 90) return `in ${days}d`;
  return d.toLocaleDateString();
}

// ── Status chip ─────────────────────────────────────────────────────────────

function StatusChip({
  tone,
  label,
  title,
}: {
  tone: "green" | "amber" | "red" | "gray";
  label: string;
  title?: string;
}) {
  const cls =
    tone === "green"
      ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-400"
      : tone === "amber"
        ? "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-400"
        : tone === "red"
          ? "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400"
          : "bg-muted text-muted-foreground";
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold",
        cls,
        title && "cursor-help",
      )}
    >
      {label}
    </span>
  );
}

/**
 * Agents needing attention (#942).
 *
 * The KPI card above counts these; this names them. A card reading "4
 * agents needing attention" that navigates to a page which does not show
 * those four is the same defect as the old alerts pill, and here no
 * single link can be honest — the set spans DNS and DHCP servers across
 * different groups, and both pages restore their last-visited selection,
 * so a bare `/dns` lands on whatever zone the operator was reading last.
 *
 * Each row therefore deep-links to the group whose server list contains
 * that server: DNSPage restores from ``group`` (defaulting to its servers
 * tab) and DHCPPage from ``group``.
 */
function AttentionAgentsPanel({
  servers,
  dnsGroups,
  dhcpGroups,
}: {
  servers: {
    id: string;
    name: string;
    status: string;
    kind: "dns" | "dhcp";
    group_id?: string;
    server_group_id?: string | null;
    config_apply_status?: ConfigApplyStatus | null;
    config_apply_error?: string | null;
    daemon_status?: string | null;
    daemon_reason?: string | null;
  }[];
  dnsGroups: DNSServerGroup[];
  dhcpGroups: DHCPServerGroup[];
}) {
  function groupFor(s: (typeof servers)[number]): {
    id: string | null;
    name: string;
  } {
    if (s.kind === "dns") {
      const g = dnsGroups.find((x) => x.id === s.group_id);
      return { id: g?.id ?? null, name: g?.name ?? "ungrouped" };
    }
    const g = dhcpGroups.find((x) => x.id === s.server_group_id);
    return { id: g?.id ?? null, name: g?.name ?? "ungrouped" };
  }

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Cpu className="h-3.5 w-3.5 text-red-500" />
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            Agents needing attention ({servers.length})
          </h3>
          <span className="text-[11px] text-muted-foreground">
            paused and maintenance-mode servers excluded
          </span>
        </div>
      </div>
      <div className="overflow-x-auto">
        <div className="min-w-[520px] divide-y">
          {servers.map((s) => {
            const group = groupFor(s);
            const to =
              group.id === null
                ? s.kind === "dns"
                  ? "/dns"
                  : "/dhcp"
                : `/${s.kind}?group=${group.id}`;
            const unreachable =
              s.status === "unreachable" || s.status === "error";
            return (
              <Link
                key={`${s.kind}-${s.id}`}
                to={to}
                className="flex items-center gap-3 px-4 py-2 text-[11px] transition-colors hover:bg-accent/40"
              >
                <span className="inline-block h-1.5 w-1.5 flex-shrink-0 rounded-full bg-red-500" />
                <span
                  className="w-40 flex-shrink-0 truncate font-semibold"
                  title={s.name}
                >
                  {s.name}
                </span>
                <span className="w-12 flex-shrink-0 uppercase text-muted-foreground">
                  {s.kind}
                </span>
                <span
                  className="w-32 flex-shrink-0 truncate text-muted-foreground"
                  title={group.name}
                >
                  {group.name}
                </span>
                <span className="flex flex-1 flex-wrap items-center gap-1.5">
                  {unreachable && (
                    <StatusChip
                      tone="red"
                      label={s.status}
                      title="The health probe cannot reach this server."
                    />
                  )}
                  <ConfigApplyChip
                    status={s.config_apply_status ?? null}
                    error={s.config_apply_error}
                  />
                  <DaemonChip
                    status={s.daemon_status ?? null}
                    reason={s.daemon_reason}
                  />
                </span>
              </Link>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/**
 * Open alerts rollup (#942).
 *
 * The alerts framework fires into `alert_event`, and until now the
 * dashboard surfaced none of it — the header pill did arithmetic of its
 * own and the Compliance tab showed a compliance-filtered slice. So the
 * home page could look calm while the alerting was lit up.
 *
 * Shares its query with the header pill (one key, one fetch); the events
 * arrive newest-first from the API.
 */
function OpenAlertsPanel({
  events,
  failed = false,
  truncated = false,
}: {
  events: AlertEvent[];
  /** The fetch failed. Distinct from "no open alerts" — see below. */
  failed?: boolean;
  /** The response came back at the fetch cap, so the count is a floor. */
  truncated?: boolean;
}) {
  const bySeverity = {
    critical: events.filter((e) => e.severity === "critical").length,
    warning: events.filter((e) => e.severity === "warning").length,
    info: events.filter((e) => e.severity === "info").length,
  };

  // A failed fetch renders as unknown, never as an all-clear. React Query
  // hands back the `[]` default on error, which would otherwise paint the
  // exact green "No open alerts" this panel exists to disprove.
  if (failed) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs text-amber-700 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-400">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
        <span className="font-medium">Could not load alerts</span>
        <span className="text-[11px]">
          This is not an all-clear — the alert state is unknown.
        </span>
        <Link
          to="/admin/alerts"
          className="ml-auto text-[11px] underline hover:no-underline"
        >
          Alerts page →
        </Link>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-lg border bg-card px-4 py-2.5 text-xs">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
        <span className="font-medium">No open alerts</span>
        <Link
          to="/admin/alerts"
          className="ml-auto text-[11px] text-primary hover:underline"
        >
          Alert rules →
        </Link>
      </div>
    );
  }

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            Open alerts ({events.length}
            {truncated ? "+" : ""})
          </h3>
          <span className="flex items-center gap-1.5 text-[11px]">
            {bySeverity.critical > 0 && (
              <StatusChip
                tone="red"
                label={`${bySeverity.critical} critical`}
              />
            )}
            {bySeverity.warning > 0 && (
              <StatusChip
                tone="amber"
                label={`${bySeverity.warning} warning`}
              />
            )}
            {bySeverity.info > 0 && (
              <StatusChip tone="gray" label={`${bySeverity.info} info`} />
            )}
          </span>
        </div>
        <Link
          to="/admin/alerts"
          className="text-[11px] text-primary hover:underline"
        >
          view all →
        </Link>
      </div>
      <div className="divide-y">
        {events.slice(0, 5).map((e) => (
          <Link
            key={e.id}
            to="/admin/alerts"
            className="flex items-center gap-3 px-4 py-2 text-[11px] transition-colors hover:bg-accent/40"
          >
            <span
              className={cn(
                "inline-block h-1.5 w-1.5 flex-shrink-0 rounded-full",
                e.severity === "critical"
                  ? "bg-red-500"
                  : e.severity === "warning"
                    ? "bg-amber-500"
                    : "bg-muted-foreground/40",
              )}
              title={e.severity}
            />
            <span
              className="w-40 flex-shrink-0 truncate font-semibold"
              title={e.subject_display}
            >
              {e.subject_display || e.subject_type}
            </span>
            <span
              className="flex-1 truncate text-muted-foreground"
              title={e.message}
            >
              {e.message}
            </span>
            <span className="w-20 flex-shrink-0 text-right text-muted-foreground">
              {humanTime(e.fired_at)}
            </span>
          </Link>
        ))}
      </div>
      {events.length > 5 && (
        <div className="border-t px-4 py-1.5 text-[11px] text-muted-foreground">
          + {events.length - 5} more
        </div>
      )}
    </div>
  );
}

// ── ASN Summary card ─────────────────────────────────────────────────────────

function AsnSummaryCard() {
  const { enabled, ready } = useFeatureModules();
  // Gate on ``ready`` so the query waits for the real module state (``enabled``
  // is optimistically true while loading → a one-shot 404 on hard load).
  const moduleOn = ready && enabled("network.asn");
  const { data, isLoading, isError } = useQuery({
    queryKey: ["asns-summary"],
    queryFn: () => asnsApi.list({ limit: 200 }),
    staleTime: 30_000,
    enabled: moduleOn,
  });

  // When the ASN module is off the gated endpoint 404s — render
  // nothing (the 4-up grid just collapses) instead of a red error card.
  if (!moduleOn) return null;

  const inner = (() => {
    if (isLoading) {
      return (
        <div className="mt-3 space-y-2">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-4 animate-pulse rounded bg-muted"
              style={{ width: `${60 + i * 10}%` }}
            />
          ))}
        </div>
      );
    }
    if (isError) {
      return (
        <p className="mt-3 text-xs text-red-600 dark:text-red-400">
          Failed to load ASN data.
        </p>
      );
    }
    const asns: ASNRead[] = data?.items ?? [];
    if (asns.length === 0) {
      return (
        <div className="mt-3 flex-1 flex flex-col justify-between">
          <p className="text-xs text-muted-foreground">No ASNs configured.</p>
          <Link
            to="/network/asns"
            className="mt-2 text-[11px] text-primary hover:underline"
          >
            Add one →
          </Link>
        </div>
      );
    }
    const publicCount = asns.filter((a) => a.kind === "public").length;
    const privateCount = asns.filter((a) => a.kind === "private").length;
    const whoisOk = asns.filter((a) => a.whois_state === "ok").length;
    const whoisUnreachable = asns.filter(
      (a) => a.whois_state === "unreachable",
    ).length;

    // RPKI ROAs — the field is optional (may not exist in all deployments)
    const allRoas: { state: string }[] = asns.flatMap(
      (a) =>
        (a as ASNRead & { rpki_roas?: { state: string }[] }).rpki_roas ?? [],
    );
    const roasExpiring = allRoas.filter((r) => r.state === "expiring").length;
    const roasExpired = allRoas.filter((r) => r.state === "expired").length;

    return (
      <div className="mt-3 flex-1 flex flex-col justify-between gap-2">
        <div className="space-y-1.5">
          <p className="text-xs text-muted-foreground">
            <span className="font-medium text-foreground">{publicCount}</span>{" "}
            public,{" "}
            <span className="font-medium text-foreground">{privateCount}</span>{" "}
            private
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {whoisOk > 0 && (
              <span className="flex items-center gap-1 text-[11px]">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <span className="text-emerald-700 dark:text-emerald-400">
                  {whoisOk} ok
                </span>
              </span>
            )}
            {whoisUnreachable > 0 && (
              <span className="flex items-center gap-1 text-[11px]">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-red-500" />
                <span className="text-red-600 dark:text-red-400">
                  {whoisUnreachable} unreachable
                </span>
              </span>
            )}
          </div>
          {(roasExpiring > 0 || roasExpired > 0) && (
            <div className="flex flex-wrap gap-1">
              {roasExpiring > 0 && (
                <StatusChip
                  tone="amber"
                  label={`${roasExpiring} ROA${roasExpiring === 1 ? "" : "s"} expiring`}
                />
              )}
              {roasExpired > 0 && (
                <StatusChip
                  tone="red"
                  label={`${roasExpired} ROA${roasExpired === 1 ? "" : "s"} expired`}
                />
              )}
            </div>
          )}
        </div>
        <Link
          to="/network/asns"
          className="text-[11px] text-muted-foreground hover:text-foreground"
        >
          View all →
        </Link>
      </div>
    );
  })();

  return (
    <div className="rounded-lg border bg-card p-4 flex flex-col">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          ASNs
        </p>
        <Hash className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      {!isLoading && !isError && (data?.items?.length ?? 0) > 0 && (
        <p className="mt-1.5 text-2xl font-bold tabular-nums">
          {data?.total ?? data?.items?.length ?? 0}
        </p>
      )}
      {inner}
    </div>
  );
}

// ── VRF Summary card ─────────────────────────────────────────────────────────

function VrfSummaryCard() {
  const { enabled, ready } = useFeatureModules();
  const moduleOn = ready && enabled("network.vrf");
  const {
    data: vrfs = [],
    isLoading,
    isError,
  } = useQuery<VRF[]>({
    queryKey: ["vrfs-summary"],
    queryFn: () => vrfsApi.list(),
    staleTime: 30_000,
    enabled: moduleOn,
  });

  // When the VRF module is off the gated endpoint 404s — render
  // nothing (the 4-up grid just collapses) instead of a red error card.
  if (!moduleOn) return null;

  const inner = (() => {
    if (isLoading) {
      return (
        <div className="mt-3 space-y-2">
          {[1, 2].map((i) => (
            <div
              key={i}
              className="h-4 animate-pulse rounded bg-muted"
              style={{ width: `${55 + i * 15}%` }}
            />
          ))}
        </div>
      );
    }
    if (isError) {
      return (
        <p className="mt-3 text-xs text-red-600 dark:text-red-400">
          Failed to load VRF data.
        </p>
      );
    }
    if (vrfs.length === 0) {
      return (
        <div className="mt-3 flex-1 flex flex-col justify-between">
          <p className="text-xs text-muted-foreground">No VRFs configured.</p>
          <Link
            to="/network/vrfs"
            className="mt-2 text-[11px] text-primary hover:underline"
          >
            Add one →
          </Link>
        </div>
      );
    }
    const missingRd = vrfs.filter(
      (v) => !v.route_distinguisher || v.route_distinguisher.trim() === "",
    ).length;
    const unlinked = vrfs.filter((v) => v.asn_id === null).length;

    return (
      <div className="mt-3 flex-1 flex flex-col justify-between gap-2">
        <div className="flex flex-wrap gap-1">
          {missingRd > 0 && (
            <StatusChip tone="amber" label={`${missingRd} missing RD`} />
          )}
          {unlinked > 0 && (
            <StatusChip tone="gray" label={`${unlinked} unlinked (no ASN)`} />
          )}
          {missingRd === 0 && unlinked === 0 && (
            <StatusChip tone="green" label="all linked" />
          )}
        </div>
        <Link
          to="/network/vrfs"
          className="text-[11px] text-muted-foreground hover:text-foreground"
        >
          View all →
        </Link>
      </div>
    );
  })();

  return (
    <div className="rounded-lg border bg-card p-4 flex flex-col">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          VRFs
        </p>
        <Route className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      {!isLoading && !isError && vrfs.length > 0 && (
        <p className="mt-1.5 text-2xl font-bold tabular-nums">{vrfs.length}</p>
      )}
      {inner}
    </div>
  );
}

// ── Domains Summary card ──────────────────────────────────────────────────────

function DomainsSummaryCard() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["domains-summary"],
    queryFn: () => domainsApi.list({ page_size: 200 }),
    staleTime: 30_000,
  });

  const inner = (() => {
    if (isLoading) {
      return (
        <div className="mt-3 space-y-2">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-4 animate-pulse rounded bg-muted"
              style={{ width: `${50 + i * 12}%` }}
            />
          ))}
        </div>
      );
    }
    if (isError) {
      return (
        <p className="mt-3 text-xs text-red-600 dark:text-red-400">
          Failed to load domain data.
        </p>
      );
    }
    const domains: Domain[] = data?.items ?? [];
    if (domains.length === 0) {
      return (
        <div className="mt-3 flex-1 flex flex-col justify-between">
          <p className="text-xs text-muted-foreground">
            No domains configured.
          </p>
          <Link
            to="/admin/domains"
            className="mt-2 text-[11px] text-primary hover:underline"
          >
            Add one →
          </Link>
        </div>
      );
    }

    const now = Date.now();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    const expired = domains.filter(
      (d) => d.expires_at && new Date(d.expires_at).getTime() < now,
    ).length;
    const expiringSoon = domains.filter((d) => {
      if (!d.expires_at) return false;
      const exp = new Date(d.expires_at).getTime();
      return exp >= now && exp - now < thirtyDaysMs;
    }).length;
    const healthy = domains.length - expired - expiringSoon;
    const driftCount = domains.filter((d) => d.nameserver_drift).length;

    return (
      <div className="mt-3 flex-1 flex flex-col justify-between gap-2">
        <div className="space-y-1.5">
          <div className="flex flex-wrap gap-1">
            {expired > 0 && (
              <StatusChip tone="red" label={`${expired} expired`} />
            )}
            {expiringSoon > 0 && (
              <StatusChip
                tone="amber"
                label={`${expiringSoon} expiring soon`}
              />
            )}
            {healthy > 0 && (
              <StatusChip tone="green" label={`${healthy} healthy`} />
            )}
          </div>
          {driftCount > 0 && (
            <div>
              <StatusChip
                tone="amber"
                label={`${driftCount} NS drift detected`}
              />
            </div>
          )}
        </div>
        <Link
          to="/admin/domains"
          className="text-[11px] text-muted-foreground hover:text-foreground"
        >
          View all →
        </Link>
      </div>
    );
  })();

  return (
    <div className="rounded-lg border bg-card p-4 flex flex-col">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Domains
        </p>
        <Globe className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      {!isLoading && !isError && (data?.items?.length ?? 0) > 0 && (
        <p className="mt-1.5 text-2xl font-bold tabular-nums">
          {data?.total ?? data?.items?.length ?? 0}
        </p>
      )}
      {inner}
    </div>
  );
}

/**
 * Decom-date awareness (issue #46). Counts subnets whose planned
 * ``decom_date`` is past-due vs. within 30 days, mirroring the
 * DomainsSummaryCard shape. Always-on IPAM widget — self-fetches the
 * subnet list so it works on any dashboard tab that renders it.
 */
function SubnetDecomCard() {
  const { data, isLoading, isError } = useQuery<Subnet[]>({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
    staleTime: 30_000,
  });

  const inner = (() => {
    if (isLoading) {
      return (
        <div className="mt-3 space-y-2">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-4 animate-pulse rounded bg-muted"
              style={{ width: `${50 + i * 12}%` }}
            />
          ))}
        </div>
      );
    }
    if (isError) {
      return (
        <p className="mt-3 text-xs text-red-600 dark:text-red-400">
          Failed to load subnet data.
        </p>
      );
    }
    const subnets: Subnet[] = data ?? [];
    const scheduled = subnets.filter((s) => !!s.decom_date);
    if (scheduled.length === 0) {
      return (
        <div className="mt-3 flex-1 flex flex-col justify-between">
          <p className="text-xs text-muted-foreground">
            No subnets scheduled for decommission.
          </p>
          <Link
            to="/ipam"
            className="mt-2 text-[11px] text-primary hover:underline"
          >
            Manage subnets →
          </Link>
        </div>
      );
    }

    // Compare on the calendar day in local time. decom_date is a plain
    // ISO date (YYYY-MM-DD) with no time component.
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    let pastDue = 0;
    let withinThirty = 0;
    let later = 0;
    for (const s of scheduled) {
      const d = new Date(`${s.decom_date}T00:00:00`).getTime();
      if (Number.isNaN(d)) continue;
      const delta = d - today.getTime();
      if (delta < 0) pastDue += 1;
      else if (delta <= thirtyDaysMs) withinThirty += 1;
      else later += 1;
    }

    return (
      <div className="mt-3 flex-1 flex flex-col justify-between gap-2">
        <div className="flex flex-wrap gap-1">
          {pastDue > 0 && (
            <StatusChip tone="red" label={`${pastDue} past-due`} />
          )}
          {withinThirty > 0 && (
            <StatusChip tone="amber" label={`${withinThirty} within 30 d`} />
          )}
          {pastDue === 0 && withinThirty === 0 && (
            <StatusChip tone="green" label={`${later} scheduled`} />
          )}
        </div>
        <Link
          to="/ipam"
          className="text-[11px] text-muted-foreground hover:text-foreground"
        >
          View all →
        </Link>
      </div>
    );
  })();

  const scheduledCount = (data ?? []).filter((s) => !!s.decom_date).length;

  return (
    <div className="rounded-lg border bg-card p-4 flex flex-col">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Decommissions
        </p>
        <CalendarClock className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      {!isLoading && !isError && scheduledCount > 0 && (
        <p className="mt-1.5 text-2xl font-bold tabular-nums">
          {scheduledCount}
        </p>
      )}
      {inner}
    </div>
  );
}

// ── Looking Glass health card ────────────────────────────────────────────────

function LookingGlassHealthCard() {
  const { enabled, ready } = useFeatureModules();
  const moduleOn = ready && enabled("network.looking_glass");
  const { data, isLoading, isError } = useQuery({
    queryKey: ["lg-dashboard-summary"],
    queryFn: () => lookingGlassApi.getDashboardSummary(),
    staleTime: 30_000,
    refetchInterval: 30_000,
    enabled: moduleOn,
  });

  // When the module is off the gated endpoint 404s — render nothing (the
  // grid just collapses) instead of a red error card, matching the other
  // module-gated summary cards on this tab.
  if (!moduleOn) return null;

  const inner = (() => {
    if (isLoading) {
      return (
        <div className="mt-3 space-y-2">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="h-4 animate-pulse rounded bg-muted"
              style={{ width: `${60 + i * 10}%` }}
            />
          ))}
        </div>
      );
    }
    if (isError) {
      return (
        <p className="mt-3 text-xs text-red-600 dark:text-red-400">
          Failed to load Looking Glass data.
        </p>
      );
    }
    if (!data || data.peers_total === 0) {
      return (
        <div className="mt-3 flex-1 flex flex-col justify-between">
          <p className="text-xs text-muted-foreground">
            No Looking Glass peers configured.
          </p>
          <Link
            to="/network/looking-glass"
            className="mt-2 text-[11px] text-primary hover:underline"
          >
            Configure a peer →
          </Link>
        </div>
      );
    }
    return (
      <div className="mt-3 flex-1 flex flex-col justify-between gap-2">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-1.5">
            {data.peers_established > 0 && (
              <span className="flex items-center gap-1 text-[11px]">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <span className="text-emerald-700 dark:text-emerald-400">
                  {data.peers_established} established
                </span>
              </span>
            )}
            {data.peers_down > 0 && (
              <span className="flex items-center gap-1 text-[11px]">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-red-500" />
                <span className="text-red-600 dark:text-red-400">
                  {data.peers_down} down
                </span>
              </span>
            )}
          </div>
          {(data.routes_rpki_invalid > 0 || data.routes_flapping > 0) && (
            <div className="flex flex-wrap gap-1">
              {data.routes_rpki_invalid > 0 && (
                <StatusChip
                  tone="red"
                  label={`${data.routes_rpki_invalid} RPKI-invalid`}
                />
              )}
              {data.routes_flapping > 0 && (
                <StatusChip
                  tone="amber"
                  label={`${data.routes_flapping} flapping`}
                />
              )}
            </div>
          )}
        </div>
        <Link
          to="/network/looking-glass"
          className="text-[11px] text-muted-foreground hover:text-foreground"
        >
          View all →
        </Link>
      </div>
    );
  })();

  return (
    <div className="rounded-lg border bg-card p-4 flex flex-col">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Looking Glass
        </p>
        <Radio className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      {!isLoading && !isError && data && data.peers_total > 0 && (
        <p className="mt-1.5 text-2xl font-bold tabular-nums">
          {data.peers_total}
        </p>
      )}
      {inner}
    </div>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────

type DashboardTab =
  | "overview"
  | "ipam"
  | "dns"
  | "dhcp"
  | "compliance"
  | "conformity"
  | "network"
  | "integrations"
  | "security";

const _PERSISTED_TABS: ReadonlySet<DashboardTab> = new Set([
  "ipam",
  "dns",
  "dhcp",
  "compliance",
  "conformity",
  "network",
  "integrations",
  "security",
]);

export function DashboardPage() {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();

  // Per-tab feature-module gate — keep in lock-step with the tab-bar
  // array's ``module`` fields below. A tab whose module is off is hidden
  // and must never be the active tab (its panel would 404).
  const _TAB_MODULES: Partial<Record<DashboardTab, string>> = {
    conformity: "compliance.conformity",
    // #1068 — an install that does not run DNS / DHCP hides the tab, and
    // the effect below moves an operator parked on it back to Overview.
    dns: "core.dns",
    dhcp: "core.dhcp",
  };
  const tabVisible = (key: DashboardTab): boolean => {
    const mod = _TAB_MODULES[key];
    return !mod || enabled(mod);
  };

  const [tab, setTab] = useState<DashboardTab>(() => {
    const saved = localStorage.getItem("dashboard-tab");
    if (saved && _PERSISTED_TABS.has(saved as DashboardTab)) {
      return saved as DashboardTab;
    }
    return "overview";
  });
  function selectTab(next: DashboardTab) {
    setTab(next);
    localStorage.setItem("dashboard-tab", next);
  }

  // If the persisted tab points at a now-hidden (module-disabled) tab,
  // fall back to Overview so we don't render a panel against a 404'd
  // endpoint.
  useEffect(() => {
    if (!tabVisible(tab)) {
      setTab("overview");
      localStorage.setItem("dashboard-tab", "overview");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, enabled]);

  // IPAM
  const { data: spaces } = useQuery({
    queryKey: ["spaces"],
    queryFn: ipamApi.listSpaces,
  });
  const { data: subnets } = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
  });

  // NAT mapping count — cheap (single page=1, per_page=1 just for total).
  const { data: natTotal } = useQuery({
    queryKey: ["nat-mappings", "count"],
    queryFn: () => natApi.list({ page: 1, per_page: 1 }).then((r) => r.total),
    staleTime: 60_000,
  });

  // Platform settings drive the utilization filter (excludes /30, /31,
  // /127 etc.) — once loaded, derived stats below use `reportSubnets`
  // instead of the raw list.
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: settingsApi.get,
    staleTime: 60_000,
  });
  const reportSubnets = subnets?.filter((s) =>
    includeInUtilization(s, settings),
  );

  // DNS
  //
  // #1068 — every /dns and /dhcp read below is gated on ``ready &&
  // enabled(...)``. ``enabled`` answers true while the module set is still
  // loading so the sidebar does not blink, so without ``ready`` each of
  // these would fire once on a hard reload and 404 before the real state
  // is known. The dependent per-group queries need no gate of their own:
  // their list comes from a query that stays empty.
  const dnsOn = ready && enabled("core.dns");
  const dhcpOn = ready && enabled("core.dhcp");
  const { data: dnsGroups = [] } = useQuery({
    queryKey: ["dns-groups"],
    queryFn: dnsApi.listGroups,
    staleTime: 30_000,
    enabled: dnsOn,
  });
  const zoneQueries = useQueries({
    queries: dnsGroups.map((g) => ({
      queryKey: ["dns-zones", g.id],
      queryFn: () => dnsApi.listZones(g.id),
      staleTime: 30_000,
    })),
  });
  const totalZones = zoneQueries.reduce(
    (sum, q) => sum + (q.data?.length ?? 0),
    0,
  );
  const serverQueries = useQueries({
    queries: dnsGroups.map((g) => ({
      queryKey: ["dns-servers", g.id],
      queryFn: () => dnsApi.listServers(g.id),
      refetchInterval: 30_000,
    })),
  });
  const allDnsServers: DNSServer[] = serverQueries.flatMap((q) => q.data ?? []);

  // DHCP
  const { data: dhcpServers = [] } = useQuery<DHCPServer[]>({
    queryKey: ["dhcp-servers"],
    queryFn: () => dhcpApi.listServers(),
    refetchInterval: 30_000,
    enabled: dhcpOn,
  });
  // Single groups fetch — drives both the DHCP server-row group-name
  // lookup and the HA panel (groups with >= 2 Kea members).
  const { data: dhcpGroups = [] } = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
    refetchInterval: 30_000,
    enabled: dhcpOn,
  });
  const haGroups = dhcpGroups.filter((g) => g.kea_member_count >= 2);

  // Audit
  const { data: recent } = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: () => auditApi.list({ limit: 15, offset: 0 }),
    staleTime: 10_000,
    refetchInterval: 15_000,
  });

  // Integrations — only fetched when the corresponding toggle is on,
  // so default deployments don't pay for the queries.
  const kubernetesEnabled = settings?.integration_kubernetes_enabled ?? false;
  const dockerEnabled = settings?.integration_docker_enabled ?? false;
  const proxmoxEnabled = settings?.integration_proxmox_enabled ?? false;
  const opnsenseEnabled = settings?.integration_opnsense_enabled ?? false;
  const panosEnabled = settings?.integration_panos_enabled ?? false;
  const fortinetEnabled = settings?.integration_fortinet_enabled ?? false;
  const merakiEnabled = settings?.integration_meraki_enabled ?? false;
  const cloudEnabled = settings?.integration_cloud_enabled ?? false;
  const tailscaleEnabled = settings?.integration_tailscale_enabled ?? false;
  const unifiEnabled = settings?.integration_unifi_enabled ?? false;
  const netbirdEnabled = settings?.integration_netbird_enabled ?? false;
  const { data: k8sClusters = [] } = useQuery<KubernetesCluster[]>({
    queryKey: ["kubernetes-clusters"],
    queryFn: kubernetesApi.listClusters,
    enabled: kubernetesEnabled,
    refetchInterval: 30_000,
  });
  const { data: dockerHosts = [] } = useQuery<DockerHost[]>({
    queryKey: ["docker-hosts"],
    queryFn: dockerApi.listHosts,
    enabled: dockerEnabled,
    refetchInterval: 30_000,
  });
  const { data: tailscaleTenants = [] } = useQuery<TailscaleTenant[]>({
    queryKey: ["tailscale-tenants"],
    queryFn: tailscaleApi.listTenants,
    enabled: tailscaleEnabled,
  });
  const { data: netbirdInstances = [] } = useQuery<NetbirdInstance[]>({
    queryKey: ["netbird-instances"],
    queryFn: netbirdApi.listInstances,
    enabled: netbirdEnabled,
  });

  const { data: proxmoxNodes = [] } = useQuery<ProxmoxNode[]>({
    queryKey: ["proxmox-nodes"],
    queryFn: proxmoxApi.listNodes,
    enabled: proxmoxEnabled,
    refetchInterval: 30_000,
  });

  const { data: opnsenseRouters = [] } = useQuery<OPNsenseRouter[]>({
    queryKey: ["opnsense-routers"],
    queryFn: opnsenseApi.listRouters,
    enabled: opnsenseEnabled,
    refetchInterval: 30_000,
  });

  const { data: panosFirewalls = [] } = useQuery<PANOSFirewall[]>({
    queryKey: ["panos-firewalls"],
    queryFn: panosApi.list,
    enabled: panosEnabled,
    refetchInterval: 30_000,
  });

  const { data: fortinetFirewalls = [] } = useQuery<FortinetFirewall[]>({
    queryKey: ["fortinet-firewalls"],
    queryFn: fortinetApi.list,
    enabled: fortinetEnabled,
    refetchInterval: 30_000,
  });

  const { data: merakiOrgs = [] } = useQuery<MerakiOrg[]>({
    queryKey: ["meraki-orgs"],
    queryFn: merakiApi.list,
    enabled: merakiEnabled,
    refetchInterval: 30_000,
  });

  const { data: cloudEndpoints = [] } = useQuery<CloudEndpoint[]>({
    queryKey: ["cloud-endpoints"],
    queryFn: cloudApi.listEndpoints,
    enabled: cloudEnabled,
    refetchInterval: 30_000,
  });

  const { data: unifiControllers = [] } = useQuery<UnifiController[]>({
    queryKey: ["unifi-controllers"],
    queryFn: unifiApi.listControllers,
    enabled: unifiEnabled,
    refetchInterval: 30_000,
  });

  // Platform health — covers api / postgres / redis / celery workers /
  // celery beat. Unlike DNS/DHCP server health (which is user-managed),
  // these are the pieces *we* ship, so surfacing their liveness makes
  // the dashboard a one-stop check for "is the control plane healthy".
  const { data: platformHealth } = useQuery<PlatformHealthResponse>({
    queryKey: ["platform-health"],
    queryFn: platformHealthApi.get,
    refetchInterval: 30_000,
  });

  // Open alert events (#942). Drives BOTH the header pill and the
  // Overview "Open alerts" panel — one query key, one fetch. The pill
  // used to render `critical + warning + unhealthyServers` computed on
  // this page and link to /ipam: a count the alerts page could not
  // corroborate, pointing at a page unrelated to most of what it
  // counted. Capacity + server health still drive the health LABEL
  // next to the title, which is what they actually describe.
  // ``limit`` is the API's own maximum. It is still a cap, and the count
  // this drives is presented as authoritative — the RPKI misfire this same
  // issue fixed had 928 events open at once, so the ceiling is reachable in
  // practice. When the response comes back exactly full the total is
  // rendered as "N+" rather than as a number we know is wrong.
  const OPEN_ALERT_FETCH_LIMIT = 1000;
  const { data: openAlerts = [], isError: openAlertsFailed } = useQuery({
    queryKey: ["alert-events", { open: true }],
    queryFn: () =>
      alertsApi.listEvents({
        open_only: true,
        limit: OPEN_ALERT_FETCH_LIMIT,
      }),
    refetchInterval: 60_000,
  });
  const openAlertsTruncated = openAlerts.length >= OPEN_ALERT_FETCH_LIMIT;

  // IPAM-tab IP-space filter (issue #115). Multi-select dropdown above
  // the IPAM-tab cards scopes every subnet-derived stat to the chosen
  // spaces. Empty list = "All spaces" (no filter). Persisted per-session
  // so a refresh / drawer toggle keeps the selection.
  const [ipamSpaceFilter, setIpamSpaceFilter] = useSessionState<string[]>(
    "spatium.dashboard.ipam.space_filter",
    [],
  );
  const ipamFilterActive = tab === "ipam" && ipamSpaceFilter.length > 0;
  const filterSpaces = (rows: Subnet[] | undefined) =>
    ipamFilterActive
      ? (rows ?? []).filter((s) => ipamSpaceFilter.includes(s.space_id))
      : (rows ?? []);

  // Derived stats — every utilization-driven counter reads from
  // `reportSubnets` so small PTP / loopback subnets don't skew the
  // dashboard. `subnets` (the unfiltered list) is still used for
  // inventory counts like "N subnets". Both feed through `filterSpaces`
  // so the IPAM-tab filter, when active, scopes every downstream number.
  const reporting = filterSpaces(reportSubnets);
  const subnetsScoped = filterSpaces(subnets);
  // IPv6 subnets (typically /64) carry 2^64 hosts each — counting them in
  // "free addresses" or overall utilization makes the headline numbers
  // meaningless (a single /64 swamps every IPv4 subnet combined). Restrict
  // the top-line counters to IPv4. The heatmap + per-subnet stats keep
  // IPv6 since per-subnet utilization_percent is still meaningful.
  const reportingV4 = reporting.filter((s) => !s.network.includes(":"));
  const reportingV6 = reporting.filter((s) => s.network.includes(":"));
  const totalIPs = reportingV4.reduce((s, n) => s + n.total_ips, 0);
  const allocatedIPs = reportingV4.reduce((s, n) => s + n.allocated_ips, 0);
  const freeIPs = totalIPs - allocatedIPs;
  const overallUtil = totalIPs > 0 ? (allocatedIPs / totalIPs) * 100 : 0;
  // IPv6 allocation count is meaningful per-subnet but the totals don't
  // make sense (a /64 has 2^64 hosts); track subnet count + alloc count
  // separately so the IPv4 vs IPv6 split panel can show both dimensions.
  const v6SubnetCount = reportingV6.length;
  const v6AllocCount = reportingV6.reduce((s, n) => s + n.allocated_ips, 0);
  const v4SubnetCount = reportingV4.length;
  const sortedSubnets = [...reporting]
    .filter((s) => s.total_ips > 0)
    .sort((a, b) => b.utilization_percent - a.utilization_percent);
  const topSubnets = sortedSubnets.slice(0, 6);
  const ipamTopSubnets = sortedSubnets.slice(0, 20);
  const critical = reporting.filter((s) => s.utilization_percent >= 95).length;
  const warning = reporting.filter(
    (s) => s.utilization_percent >= 80 && s.utilization_percent < 95,
  ).length;

  const allServers = [
    ...allDnsServers.map((s) => ({ ...s, kind: "dns" as const })),
    ...dhcpServers.map((s) => ({ ...s, kind: "dhcp" as const })),
  ];
  // A server the operator has deliberately paused or put into
  // maintenance is not a fault, and counting one as unhealthy pins the
  // whole dashboard to "degraded" for as long as it stays parked
  // (#942). Maintenance mode is the load-bearing half: #182 already
  // suppresses the heartbeat-stale ALERT server-side for those, so
  // counting them here contradicted our own alerting. ``is_enabled``
  // is DNS-only — DHCP servers have no pause switch — hence the kind
  // narrowing rather than a bare property read.
  const supervisedServers = allServers.filter(
    (s) => !s.maintenance_mode && (s.kind !== "dns" || s.is_enabled !== false),
  );
  const unhealthyServers = supervisedServers.filter(
    (s) => s.status === "unreachable" || s.status === "error",
  ).length;
  const activeServers = supervisedServers.filter(
    (s) => s.status === "active",
  ).length;
  // #882 — an agent that failed to apply its config keeps serving and
  // keeps heartbeating, so ``status``, the health check and
  // ``last_seen_at`` all read normal while the saved zone or scope is
  // live nowhere. That is exactly the silent failure the dashboard
  // should catch, so a failing verdict degrades the header even when
  // the server is otherwise healthy. NULL is UNKNOWN, never ok — an
  // agent too old to report is where a silent revert would hide, so it
  // is deliberately not counted as a failure either.
  const configFailedServers = supervisedServers.filter(
    (s) => s.config_apply_status != null && s.config_apply_status !== "ok",
  ).length;
  // #1067 — an agent whose daemon is not serving keeps heartbeating too, so
  // ``status`` and the last-seen stamp read normal while it answers nothing
  // (a DNS agent waiting for a bundle that never comes). The agent says so
  // on every heartbeat; that report degrades the header. NULL is UNKNOWN,
  // never ok — and, as for the config verdict, not counted as a failure.
  const daemonDegradedServers = supervisedServers.filter(
    (s) => s.daemon_status != null && s.daemon_status !== "ok",
  ).length;
  // The actual offenders, not just how many. "4 agents needing attention"
  // that navigates to a page which does not name those four is the same
  // defect as the old alerts pill — and here no single link can be
  // honest, because the set spans DNS and DHCP servers across different
  // groups. So the Overview names them and each row deep-links to the
  // group whose server list contains it.
  const attentionServers = supervisedServers.filter(
    (s) =>
      s.status === "unreachable" ||
      s.status === "error" ||
      (s.config_apply_status != null && s.config_apply_status !== "ok") ||
      (s.daemon_status != null && s.daemon_status !== "ok"),
  );

  const degraded =
    unhealthyServers > 0 ||
    configFailedServers > 0 ||
    daemonDegradedServers > 0 ||
    critical > 0;
  const healthTone: Tone = degraded ? "bad" : warning > 0 ? "warn" : "good";
  const healthLabel = degraded
    ? "degraded"
    : warning > 0
      ? "near capacity"
      : "healthy";
  // The label is a rollup of four unrelated things; without this the
  // operator sees "degraded" and has no idea which one to chase.
  const healthDetail =
    [
      critical > 0
        ? `${critical} subnet${critical === 1 ? "" : "s"} ≥95% full`
        : null,
      warning > 0
        ? `${warning} subnet${warning === 1 ? "" : "s"} ≥80% full`
        : null,
      unhealthyServers > 0
        ? `${unhealthyServers} server${unhealthyServers === 1 ? "" : "s"} unreachable`
        : null,
      configFailedServers > 0
        ? `${configFailedServers} agent${configFailedServers === 1 ? "" : "s"} failed to apply config`
        : null,
    ]
      .filter(Boolean)
      .join(" · ") || "No capacity or server-health problems detected";

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-[1400px] space-y-5">
        {/* ── Title + status pill ────────────────────────────────────── */}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
            <p className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
              <span className="font-mono">//</span>
              <span>
                {spaces?.length ?? 0} space{spaces?.length === 1 ? "" : "s"}
              </span>
              <span>·</span>
              <span>
                {subnets?.length ?? 0} subnet{subnets?.length === 1 ? "" : "s"}
              </span>
              <span>·</span>
              <span
                className="inline-flex cursor-help items-center gap-1.5"
                title={healthDetail}
              >
                <span
                  className={cn(
                    "inline-block h-1.5 w-1.5 rounded-full",
                    TONE_CLASS[healthTone].accent,
                  )}
                />
                <span className={TONE_CLASS[healthTone].value}>
                  {healthLabel}
                </span>
              </span>
            </p>
          </div>
          <div className="flex items-center gap-2">
            {tab === "ipam" && (
              <IpamSpaceFilter
                spaces={spaces ?? []}
                selected={ipamSpaceFilter}
                onChange={setIpamSpaceFilter}
              />
            )}
            {openAlerts.length > 0 && (
              <Link
                to="/admin/alerts"
                title={
                  openAlertsTruncated
                    ? `At least ${openAlerts.length} unresolved alert events — more than this page fetches. Open the Alerts page to triage.`
                    : `${openAlerts.length} unresolved alert event${
                        openAlerts.length === 1 ? "" : "s"
                      } — open the Alerts page to triage`
                }
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium",
                  openAlerts.some((e) => e.severity === "critical")
                    ? "border-red-200 bg-red-50 text-red-700 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-950/50"
                    : "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-950/50",
                )}
              >
                <AlertTriangle className="h-3.5 w-3.5" />
                {openAlerts.length}
                {openAlertsTruncated ? "+" : ""} alert
                {openAlerts.length === 1 ? "" : "s"} open
              </Link>
            )}
            {/* Blanket invalidate, deliberately (#942). This used to
                enumerate twelve query keys, which covered the Overview and
                missed every panel on the Network / Integrations /
                Compliance / Conformity / Security tabs plus most of the
                Overview summary cards — pressing Refresh on five of the
                nine tabs did nothing at all. An allowlist on a button whose
                whole contract is "reload everything on this page" can only
                drift as panels are added; the correct scope is the page,
                and React Query only refetches what is mounted. */}
            <button
              type="button"
              onClick={() => void qc.invalidateQueries()}
              title="Reload every panel on the dashboard."
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-accent"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        </div>

        {/* ── Tab bar ─────────────────────────────────────────────────
            Sub-tabs scope the dashboard to one subsystem at a time.
            Overview keeps the headline KPI grid + heatmap + activity
            feed + platform health; the per-subsystem tabs surface the
            subsystem-scoped panels (charts, server lists, integration
            status) without overcrowding the home view. */}
        <div className="border-b overflow-x-auto">
          <div className="flex gap-1 min-w-max whitespace-nowrap">
            {(
              [
                { key: "overview", label: "Overview", Icon: Activity },
                { key: "ipam", label: "IPAM", Icon: Network },
                { key: "dns", label: "DNS", Icon: Globe2, module: "core.dns" },
                {
                  key: "dhcp",
                  label: "DHCP",
                  Icon: Server,
                  module: "core.dhcp",
                },
                { key: "network", label: "Network", Icon: Waypoints },
                { key: "integrations", label: "Integrations", Icon: Plug },
                { key: "compliance", label: "Compliance", Icon: ShieldCheck },
                {
                  key: "conformity",
                  label: "Conformity",
                  Icon: ClipboardCheck,
                  module: "compliance.conformity",
                },
                { key: "security", label: "Security", Icon: Lock },
              ] as const
            )
              .filter((t) => !("module" in t) || enabled(t.module))
              .map(({ key, label, Icon }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => selectTab(key)}
                  className={cn(
                    "inline-flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium -mb-px transition-colors",
                    tab === key
                      ? "border-primary text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground",
                  )}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                </button>
              ))}
          </div>
        </div>

        {/* ── Overview: what needs attention (#942) ──────────────────────
              Overview used to open with the same six inventory counters
              the IPAM / DNS / DHCP tabs repeat verbatim. Space and zone
              counts do not change between visits, so the home page led
              with the least informative thing on it while unhealthy
              agents, capacity pressure and expiring certificates were
              scattered across other tabs or absent. The counters are
              still here — demoted to one line below — and the top of the
              page now answers "what should I look at today". */}
        {tab === "overview" && (
          <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
            <KpiCard
              label="Agents needing attention"
              value={unhealthyServers + configFailedServers}
              sub={
                unhealthyServers + configFailedServers > 0 ? (
                  <span className="text-red-600 dark:text-red-400">
                    {unhealthyServers} unreachable
                    {configFailedServers > 0 &&
                      ` · ${configFailedServers} config failed`}
                  </span>
                ) : (
                  `${activeServers} healthy · paused and maintenance excluded`
                )
              }
              icon={Cpu}
              tone={unhealthyServers + configFailedServers > 0 ? "bad" : "good"}
            />
            <KpiCard
              label="Capacity pressure"
              value={critical + warning}
              sub={
                critical + warning > 0 ? (
                  <span
                    className={
                      critical > 0
                        ? "text-red-600 dark:text-red-400"
                        : "text-amber-600 dark:text-amber-400"
                    }
                  >
                    {critical} at ≥95% · {warning} at ≥80%
                  </span>
                ) : (
                  "no subnet above 80%"
                )
              }
              icon={Network}
              tone={critical > 0 ? "bad" : warning > 0 ? "warn" : "good"}
              to="/ipam"
            />
            <WidgetErrorBoundary title="Certificates expiring">
              <CertsExpiringKpi />
            </WidgetErrorBoundary>
          </div>
        )}

        {/* ── KPI grid (IPAM / DNS / DHCP — same data, different lens.
              Overview gets the compact inventory strip instead, and the
              focused tabs own their own headline KPIs). ─────────────── */}
        {(tab === "ipam" || tab === "dns" || tab === "dhcp") && (
          <div className="grid gap-3 grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
            <KpiCard
              label="IP Spaces"
              value={spaces?.length ?? "—"}
              sub={spaces?.[0]?.name?.toUpperCase()}
              icon={Layers}
              to="/ipam"
            />
            <KpiCard
              label="Subnets"
              value={subnetsScoped.length}
              sub={
                <>
                  <span className="text-emerald-600 dark:text-emerald-400">
                    {subnetsScoped.length - critical - warning} healthy
                  </span>
                  {(critical > 0 || warning > 0) && (
                    <>
                      {" · "}
                      <span className="text-red-600 dark:text-red-400">
                        {critical + warning} alert
                        {critical + warning === 1 ? "" : "s"}
                      </span>
                    </>
                  )}
                </>
              }
              icon={Network}
              tone={critical > 0 ? "bad" : warning > 0 ? "warn" : "good"}
              to="/ipam"
            />
            <KpiCard
              label="Allocated IPs (IPv4)"
              value={allocatedIPs.toLocaleString()}
              sub={`${freeIPs.toLocaleString()} free`}
              icon={Activity}
              to="/ipam"
            />
            <KpiCard
              label="Utilization (IPv4)"
              value={`${overallUtil.toFixed(1)}%`}
              sub={`${allocatedIPs.toLocaleString()} / ${totalIPs.toLocaleString()}`}
              icon={Server}
              tone={
                overallUtil >= 95
                  ? "bad"
                  : overallUtil >= 80
                    ? "warn"
                    : "default"
              }
            />
            {dnsOn && (
              <KpiCard
                label="DNS Zones"
                value={totalZones}
                sub={
                  dnsGroups.length > 0
                    ? `${dnsGroups.length} group${dnsGroups.length === 1 ? "" : "s"}`
                    : "no groups"
                }
                icon={Globe2}
                to="/dns"
              />
            )}
            <KpiCard
              label="Servers"
              value={allServers.length}
              sub={
                unhealthyServers > 0 ? (
                  <span className="text-red-600 dark:text-red-400">
                    {activeServers} active · {unhealthyServers} unhealthy
                  </span>
                ) : allServers.length > 0 ? (
                  `${activeServers} active`
                ) : (
                  "none registered"
                )
              }
              icon={Cpu}
              tone={unhealthyServers > 0 ? "bad" : "default"}
            />
          </div>
        )}

        {tab === "overview" && attentionServers.length > 0 && (
          <WidgetErrorBoundary title="Agents needing attention">
            <AttentionAgentsPanel
              servers={attentionServers}
              dnsGroups={dnsGroups}
              dhcpGroups={dhcpGroups}
            />
          </WidgetErrorBoundary>
        )}

        {tab === "overview" && (
          <WidgetErrorBoundary title="Open alerts">
            <OpenAlertsPanel
              events={openAlerts}
              failed={openAlertsFailed}
              truncated={openAlertsTruncated}
            />
          </WidgetErrorBoundary>
        )}

        {/* ── Platform health (Overview only) ───────────────────────── */}
        {tab === "overview" && platformHealth && (
          <WidgetErrorBoundary title="Platform health">
            <PlatformHealthCard health={platformHealth} />
          </WidgetErrorBoundary>
        )}

        {/* ── Inventory strip (#942) — the demoted six KPI cards. Still
              one click from everything they linked to, in a twelfth of
              the vertical space, because "how many zones do we have" is
              a reference lookup rather than a thing to monitor. ─────── */}
        {tab === "overview" && (
          <div className="flex flex-wrap items-center gap-x-1 gap-y-2 rounded-lg border bg-card px-4 py-2.5 text-xs">
            <InventoryStat
              value={spaces?.length ?? 0}
              label="spaces"
              to="/ipam"
            />
            <InventoryStat
              value={subnetsScoped.length}
              label="subnets"
              to="/ipam"
            />
            <InventoryStat
              value={allocatedIPs.toLocaleString()}
              label="allocated IPv4"
              title={`${freeIPs.toLocaleString()} free of ${totalIPs.toLocaleString()}`}
              to="/ipam"
            />
            <InventoryStat
              value={`${overallUtil.toFixed(1)}%`}
              label="utilization"
              tone={
                overallUtil >= 95
                  ? "bad"
                  : overallUtil >= 80
                    ? "warn"
                    : undefined
              }
              title={`${allocatedIPs.toLocaleString()} / ${totalIPs.toLocaleString()} IPv4 addresses`}
              to="/ipam"
            />
            <InventoryStat
              value={totalZones}
              label="DNS zones"
              title={`across ${dnsGroups.length} group${dnsGroups.length === 1 ? "" : "s"}`}
              to="/dns"
            />
            <InventoryStat
              value={allServers.length}
              label="servers"
              title={`${activeServers} active`}
              to="/dns"
            />
          </div>
        )}

        {/* ── Network overview cards (Overview tab) ───────────────────
              ``items-start`` is the fix for the whitespace, not styling
              (#942): the grid's default stretch made every card as tall
              as the tallest in its row, so a card whose whole content is
              "No subnets scheduled for decommission" rendered as a
              full-height panel of nothing. Each card is now its natural
              height, which self-compacts the empty ones without five
              components needing an empty-state variant. */}
        {tab === "overview" && (
          <div className="grid items-start gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
            <WidgetErrorBoundary title="ASN summary">
              <AsnSummaryCard />
            </WidgetErrorBoundary>
            <WidgetErrorBoundary title="VRF summary">
              <VrfSummaryCard />
            </WidgetErrorBoundary>
            <WidgetErrorBoundary title="Domain summary">
              <DomainsSummaryCard />
            </WidgetErrorBoundary>
            <WidgetErrorBoundary title="Subnet decommissioning">
              <SubnetDecomCard />
            </WidgetErrorBoundary>
            <WidgetErrorBoundary title="Looking Glass health">
              <LookingGlassHealthCard />
            </WidgetErrorBoundary>
          </div>
        )}

        {/* ── DNS query rate (DNS tab only) ──────────────────────────── */}
        {tab === "dns" && (
          <WidgetErrorBoundary title="DNS query rate">
            <DNSQueryRateCard dnsServers={allDnsServers} />
          </WidgetErrorBoundary>
        )}

        {/* ── DHCP pools + traffic (DHCP tab only) ───────────────────── */}
        {tab === "dhcp" && (
          <WidgetErrorBoundary title="DHCP pools">
            <DhcpPoolPressure />
          </WidgetErrorBoundary>
        )}
        {tab === "dhcp" && (
          <WidgetErrorBoundary title="DHCP traffic">
            <DHCPTrafficCard dhcpServers={dhcpServers} />
          </WidgetErrorBoundary>
        )}

        {/* ── Heatmap (Overview + IPAM) ──────────────────────────────── */}
        {(tab === "overview" || tab === "ipam") && (
          <WidgetErrorBoundary title="Subnet heatmap">
            <SubnetHeatmap subnets={reporting} />
          </WidgetErrorBoundary>
        )}

        {/* ── IPAM-specific summary cards ───────────────────────────── */}
        {tab === "ipam" && (
          <div className="grid gap-3 grid-cols-2 md:grid-cols-3">
            {/* IPv4 vs IPv6 split — counts only; v6 host counts are
                meaningless. */}
            <div className="rounded-lg border bg-card p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">
                  IPv4 / IPv6 split
                </span>
                <Layers className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="mt-3 space-y-2">
                <div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono">IPv4</span>
                    <span className="text-muted-foreground">
                      {v4SubnetCount} subnet
                      {v4SubnetCount === 1 ? "" : "s"} ·{" "}
                      {allocatedIPs.toLocaleString()} alloc
                    </span>
                  </div>
                  <div className="mt-1 h-2 overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full bg-blue-500"
                      style={{
                        width: `${
                          v4SubnetCount + v6SubnetCount === 0
                            ? 0
                            : (v4SubnetCount /
                                (v4SubnetCount + v6SubnetCount)) *
                              100
                        }%`,
                      }}
                    />
                  </div>
                </div>
                <div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono">IPv6</span>
                    <span className="text-muted-foreground">
                      {v6SubnetCount} subnet
                      {v6SubnetCount === 1 ? "" : "s"} ·{" "}
                      {v6AllocCount.toLocaleString()} alloc
                    </span>
                  </div>
                  <div className="mt-1 h-2 overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full bg-purple-500"
                      style={{
                        width: `${
                          v4SubnetCount + v6SubnetCount === 0
                            ? 0
                            : (v6SubnetCount /
                                (v4SubnetCount + v6SubnetCount)) *
                              100
                        }%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>

            <KpiCard
              label="NAT mappings"
              value={natTotal ?? "—"}
              sub={natTotal === 0 ? "none configured" : "operator-curated"}
              icon={Plug}
              to="/ipam/nat"
            />

            <KpiCard
              label="Capacity headroom"
              value={`${(100 - overallUtil).toFixed(1)}%`}
              sub={`${freeIPs.toLocaleString()} IPv4 free`}
              icon={HardDrive}
              tone={
                overallUtil >= 95 ? "bad" : overallUtil >= 80 ? "warn" : "good"
              }
            />

            {/* New-device watch (#459) — renders nothing when the
                security.new_device_watch module is off. */}
            <NewDevicesKpi />
          </div>
        )}

        {/* ── Overview: Top subnets (compact) + Live activity ─────────── */}
        {tab === "overview" && (
          <div className="grid gap-5 lg:grid-cols-2">
            {/* Top Subnets */}
            <div className="rounded-lg border bg-card">
              <div className="flex items-center justify-between border-b px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  <h3 className="text-xs font-semibold uppercase tracking-wider">
                    Top Subnets by Utilization
                  </h3>
                </div>
                <span className="text-[11px] text-muted-foreground">
                  Showing {topSubnets.length} of {subnets?.length ?? 0}
                </span>
              </div>
              <div className="overflow-x-auto">
                <div className="min-w-[480px] divide-y">
                  {topSubnets.length === 0 ? (
                    <div className="px-4 py-8 text-center text-xs text-muted-foreground">
                      No subnets have allocated IPs yet.
                    </div>
                  ) : (
                    topSubnets.map((subnet) => (
                      <Link
                        key={subnet.id}
                        to={`/ipam?subnet=${subnet.id}`}
                        className="flex items-center gap-4 px-4 py-2.5 transition-colors hover:bg-accent/40"
                      >
                        <span className="w-32 flex-shrink-0 font-mono text-xs">
                          {subnet.network}
                        </span>
                        <span className="w-32 truncate text-xs text-muted-foreground">
                          {subnet.name || (
                            <span className="text-muted-foreground/40">—</span>
                          )}
                        </span>
                        <div className="flex-1">
                          <UtilizationBar
                            percent={subnet.utilization_percent}
                            network={subnet.network}
                          />
                        </div>
                        <span className="w-24 shrink-0 whitespace-nowrap text-right text-[11px] tabular-nums text-muted-foreground">
                          {capacityLabel(subnet)}
                        </span>
                      </Link>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Live activity */}
            <div className="rounded-lg border bg-card">
              <div className="flex items-center justify-between border-b px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="relative inline-flex h-1.5 w-1.5">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  </span>
                  <h3 className="text-xs font-semibold uppercase tracking-wider">
                    Live Activity
                  </h3>
                </div>
                <Link
                  to="/admin/audit"
                  className="text-[11px] text-muted-foreground hover:text-foreground"
                >
                  view all →
                </Link>
              </div>
              <div className="overflow-x-auto">
                <div className="min-w-[440px] divide-y">
                  {!recent || recent.items.length === 0 ? (
                    <div className="px-4 py-8 text-center text-xs text-muted-foreground">
                      No recent activity. Try creating a subnet or a DNS record.
                    </div>
                  ) : (
                    recent.items.slice(0, 12).map((entry) => (
                      <div
                        key={entry.id}
                        className="flex items-center gap-2.5 px-4 py-2 text-[11px]"
                      >
                        <span className="w-14 flex-shrink-0 tabular-nums text-muted-foreground">
                          {humanTime(entry.timestamp)}
                        </span>
                        {/* The badge used to reserve 144 px for names that
                            are usually six characters, so the two columns
                            that identify WHAT changed and WHO changed it
                            were squeezed into what was left and truncated
                            to "Administr…". It now takes what it needs and
                            truncates itself, with the full text on hover
                            everywhere (#942). */}
                        <span
                          className="min-w-0 max-w-[9rem] flex-shrink-0 truncate"
                          title={`${entry.action}${entry.resource_type ? ` · ${entry.resource_type.replace(/_/g, " ")}` : ""}`}
                        >
                          <ActionBadge
                            action={entry.action}
                            result={entry.result}
                          />
                        </span>
                        <span
                          className="flex-1 truncate font-mono"
                          title={entry.resource_display}
                        >
                          {entry.resource_display}
                        </span>
                        <span
                          className="w-24 flex-shrink-0 truncate text-right text-muted-foreground"
                          title={entry.user_display_name}
                        >
                          {entry.user_display_name}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── IPAM tab: Top Subnets (extended list) ──────────────────── */}
        {tab === "ipam" && (
          <div className="rounded-lg border bg-card">
            <div className="flex items-center justify-between border-b px-4 py-2.5">
              <div className="flex items-center gap-2">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <h3 className="text-xs font-semibold uppercase tracking-wider">
                  Top Subnets by Utilization
                </h3>
              </div>
              <span className="text-[11px] text-muted-foreground">
                Showing {ipamTopSubnets.length} of {subnetsScoped.length}
              </span>
            </div>
            <div className="divide-y">
              {ipamTopSubnets.length === 0 ? (
                <div className="px-4 py-8 text-center text-xs text-muted-foreground">
                  No subnets have allocated IPs yet.
                </div>
              ) : (
                ipamTopSubnets.map((subnet) => (
                  <Link
                    key={subnet.id}
                    to={`/ipam?subnet=${subnet.id}`}
                    className="flex items-center gap-4 px-4 py-2.5 transition-colors hover:bg-accent/40"
                  >
                    <span className="w-32 flex-shrink-0 font-mono text-xs">
                      {subnet.network}
                    </span>
                    <span className="w-40 truncate text-xs text-muted-foreground">
                      {subnet.name || (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                    </span>
                    <div className="flex-1">
                      <UtilizationBar
                        percent={subnet.utilization_percent}
                        network={subnet.network}
                      />
                    </div>
                    <span className="w-28 shrink-0 whitespace-nowrap text-right text-[11px] tabular-nums text-muted-foreground">
                      {capacityLabel(subnet)}
                    </span>
                  </Link>
                ))
              )}
            </div>
          </div>
        )}

        {/* ── DNS tab: Server list ──────────────────────────────────── */}
        {tab === "dns" && allDnsServers.length > 0 && (
          <div className="rounded-lg border bg-card">
            <div className="flex items-center justify-between border-b px-4 py-2.5">
              <div className="flex items-center gap-2">
                <Globe2 className="h-3.5 w-3.5 text-muted-foreground" />
                <h3 className="text-xs font-semibold uppercase tracking-wider">
                  DNS Servers ({allDnsServers.length})
                </h3>
                <span className="text-[11px] text-muted-foreground">
                  {totalZones} zone{totalZones === 1 ? "" : "s"} ·{" "}
                  {dnsGroups.length} group{dnsGroups.length === 1 ? "" : "s"}
                </span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <div className="min-w-[520px] divide-y">
                {allDnsServers.map((s) => {
                  const group = dnsGroups.find((g) => g.id === s.group_id);
                  return (
                    <ServerRow
                      key={s.id}
                      name={s.name}
                      host={`${s.host}:${s.port}`}
                      driver={s.driver}
                      status={s.status}
                      groupName={group?.name ?? "—"}
                      lastSeen={s.last_health_check_at}
                      isEnabled={s.is_enabled !== false}
                      maintenance={s.maintenance_mode}
                      configApplyStatus={s.config_apply_status}
                      configApplyError={s.config_apply_error}
                      daemonStatus={s.daemon_status}
                      daemonReason={s.daemon_reason}
                    />
                  );
                })}
              </div>
            </div>
          </div>
        )}
        {tab === "dns" && allDnsServers.length === 0 && (
          <div className="rounded-lg border border-dashed p-10 text-center">
            <Globe2 className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
            <p className="text-sm font-medium">No DNS servers registered</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Register a DNS server to see query rates, zones, and health here.
            </p>
          </div>
        )}

        {/* ── DHCP tab: Server list + HA pairs ──────────────────────── */}
        {tab === "dhcp" && dhcpServers.length > 0 && (
          <div className="rounded-lg border bg-card">
            <div className="flex items-center justify-between border-b px-4 py-2.5">
              <div className="flex items-center gap-2">
                <Server className="h-3.5 w-3.5 text-muted-foreground" />
                <h3 className="text-xs font-semibold uppercase tracking-wider">
                  DHCP Servers ({dhcpServers.length})
                </h3>
                <span className="text-[11px] text-muted-foreground">
                  {dhcpGroups.length} group
                  {dhcpGroups.length === 1 ? "" : "s"}
                  {haGroups.length > 0 &&
                    ` · ${haGroups.length} HA pair${haGroups.length === 1 ? "" : "s"}`}
                </span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <div className="min-w-[520px] divide-y">
                {dhcpServers.map((s) => {
                  const group = dhcpGroups.find(
                    (g) => g.id === s.server_group_id,
                  );
                  return (
                    <ServerRow
                      key={s.id}
                      name={s.name}
                      host={`${s.host}:${s.port}`}
                      driver={s.driver}
                      status={
                        !s.agent_approved ? "pending" : (s.status ?? "unknown")
                      }
                      groupName={group?.name ?? "ungrouped"}
                      lastSeen={s.last_health_check_at}
                      maintenance={s.maintenance_mode}
                      configApplyStatus={s.config_apply_status}
                      configApplyError={s.config_apply_error}
                      daemonStatus={s.daemon_status}
                      daemonReason={s.daemon_reason}
                    />
                  );
                })}
              </div>
            </div>
            {haGroups.length > 0 && (
              <>
                <div className="flex items-center gap-1.5 border-t bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <Shield className="h-3 w-3" />
                  HA Pairs ({haGroups.length})
                </div>
                <div className="divide-y">
                  {haGroups.map((g) => (
                    <FailoverRow key={g.id} group={g} />
                  ))}
                </div>
              </>
            )}
          </div>
        )}
        {tab === "dhcp" && dhcpServers.length === 0 && (
          <div className="rounded-lg border border-dashed p-10 text-center">
            <Server className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
            <p className="text-sm font-medium">No DHCP servers registered</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Register a DHCP server to see lease activity, scopes, and HA state
              here.
            </p>
          </div>
        )}

        {/* ── Integrations panel (IPAM tab — they populate IPAM) ────── */}
        {tab === "ipam" &&
          (kubernetesEnabled ||
            dockerEnabled ||
            proxmoxEnabled ||
            opnsenseEnabled ||
            panosEnabled ||
            fortinetEnabled ||
            merakiEnabled ||
            cloudEnabled ||
            tailscaleEnabled ||
            unifiEnabled ||
            netbirdEnabled) && (
            <div className="space-y-1.5">
              {ipamFilterActive && (
                <p className="px-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                  Integrations are not space-scoped — the filter doesn't apply
                  here.
                </p>
              )}
              <IntegrationsPanel
                kubernetesEnabled={kubernetesEnabled}
                dockerEnabled={dockerEnabled}
                proxmoxEnabled={proxmoxEnabled}
                opnsenseEnabled={opnsenseEnabled}
                panosEnabled={panosEnabled}
                fortinetEnabled={fortinetEnabled}
                merakiEnabled={merakiEnabled}
                cloudEnabled={cloudEnabled}
                tailscaleEnabled={tailscaleEnabled}
                unifiEnabled={unifiEnabled}
                clusters={k8sClusters}
                hosts={dockerHosts}
                proxmoxNodes={proxmoxNodes}
                opnsenseRouters={opnsenseRouters}
                panosFirewalls={panosFirewalls}
                fortinetFirewalls={fortinetFirewalls}
                merakiOrgs={merakiOrgs}
                cloudEndpoints={cloudEndpoints}
                tailscaleTenants={tailscaleTenants}
                unifiControllers={unifiControllers}
                netbirdEnabled={netbirdEnabled}
                netbirdInstances={netbirdInstances}
              />
            </div>
          )}

        {/* ── Network tab ───────────────────────────────────────────── */}
        {tab === "network" && <NetworkPanel />}

        {tab === "integrations" && <IntegrationsDashboardTabPanel />}

        {tab === "security" && <SecurityPanel />}

        {tab === "compliance" && <CompliancePanel subnets={subnets ?? []} />}

        {/* ── Conformity tab ────────────────────────────────────────── */}
        {tab === "conformity" && <ConformityPanel />}

        {/* ── Empty state (Overview only) ───────────────────────────── */}
        {tab === "overview" &&
          subnets?.length === 0 &&
          spaces?.length === 0 && (
            <div className="rounded-lg border border-dashed p-10 text-center">
              <FileText className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
              <p className="text-sm font-medium">Welcome to SpatiumDDI</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Head to{" "}
                <Link
                  to="/ipam"
                  className="text-primary underline underline-offset-2"
                >
                  IPAM
                </Link>{" "}
                to create your first IP space + subnet.
              </p>
            </div>
          )}
      </div>
    </div>
  );
}

/**
 * Multi-select IP-space filter pill (issue #115). Default "All spaces";
 * selecting a subset narrows every IPAM-tab card. Renders nothing when
 * fewer than two spaces exist — there's nothing to filter against.
 */
function IpamSpaceFilter({
  spaces,
  selected,
  onChange,
}: {
  spaces: IPSpace[];
  selected: string[];
  onChange: (next: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (
        wrapperRef.current &&
        !wrapperRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open]);

  const sortedSpaces = useMemo(
    () => [...spaces].sort((a, b) => a.name.localeCompare(b.name)),
    [spaces],
  );

  if (sortedSpaces.length < 2) return null;

  const allSelected = selected.length === 0;
  const label = allSelected
    ? "Spaces: All"
    : `Spaces: ${selected.length} selected`;

  function toggle(id: string) {
    if (selected.includes(id)) {
      onChange(selected.filter((x) => x !== id));
    } else {
      onChange([...selected, id]);
    }
  }

  return (
    <div className="relative" ref={wrapperRef}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        title="Scope IPAM-tab cards to one or more IP spaces"
        className={cn(
          "inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-accent",
          !allSelected &&
            "border-primary/40 bg-primary/5 text-primary dark:bg-primary/10",
        )}
      >
        <Layers className="h-3.5 w-3.5" />
        {label}
        <ChevronDown className="h-3 w-3 opacity-60" />
      </button>

      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 w-[260px] rounded-md border bg-popover shadow-lg">
          <div className="flex items-center justify-between border-b px-3 py-2 text-[11px] text-muted-foreground">
            <span className="font-medium uppercase tracking-wide">
              IP Spaces
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onChange([])}
                className="hover:text-foreground"
                title="Show all spaces"
              >
                All
              </button>
              <span className="opacity-40">·</span>
              <button
                type="button"
                onClick={() => onChange(sortedSpaces.map((s) => s.id))}
                className="hover:text-foreground"
                title="Select every space (effectively the same as All — kept for symmetry)"
              >
                None
              </button>
            </div>
          </div>
          <div className="max-h-[280px] overflow-auto py-1">
            {sortedSpaces.map((s) => {
              const checked = !allSelected && selected.includes(s.id);
              return (
                <label
                  key={s.id}
                  className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-xs hover:bg-accent"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggle(s.id)}
                    className="h-3.5 w-3.5"
                  />
                  <span className="truncate">{s.name}</span>
                  {s.is_default && (
                    <span className="ml-auto rounded bg-muted px-1.5 py-0 text-[10px] uppercase text-muted-foreground">
                      Default
                    </span>
                  )}
                </label>
              );
            })}
          </div>
          {!allSelected && (
            <div className="border-t px-3 py-2">
              <button
                type="button"
                onClick={() => onChange([])}
                className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
              >
                <X className="h-3 w-3" />
                Clear filter
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Config-apply verdict chip (#882, surfaced here by #942).
 *
 * The failure this makes visible is silent by construction: an agent
 * that could not apply its config keeps serving the PREVIOUS one and
 * keeps heartbeating, so `status`, the health probe and `last_seen_at`
 * all read normal while the zone or scope the operator saved is live
 * nowhere.
 *
 * NULL renders nothing rather than "ok" — an agent too old to report a
 * verdict is exactly where a silent revert would hide, and painting
 * that green would be the same lie in a different colour.
 */
function ConfigApplyChip({
  status,
  error,
}: {
  status: ConfigApplyStatus | null;
  error?: string | null;
}) {
  if (status == null || status === "ok") return null;
  // `reverted` means a known-good config is still serving; the other two
  // mean the running state is wrong or unknown.
  const tone = status === "reverted" ? "amber" : "red";
  const label = status === "reverted" ? "config reverted" : `config ${status}`;
  return (
    <StatusChip
      tone={tone}
      label={label.replace(/_/g, " ")}
      title={
        error ||
        (status === "reverted"
          ? "The saved config failed to apply; the agent rolled back and is serving the previous one."
          : "The saved config failed to apply and the rollback did not succeed. Running state is unknown.")
      }
    />
  );
}

/**
 * #1067 — the daemon state the agent itself reports. A DNS agent whose
 * `named` never started (no bundle yet) heartbeats every 30 s with
 * `daemon.status = degraded`; before #1067 the control plane dropped the
 * field and the row read healthy. Renders nothing on `ok` and on null
 * (never reported: a pre-#1061 agent or an agentless driver — unknown, not
 * healthy, and not a failure either, the same posture as the config chip).
 */
function DaemonChip({
  status,
  reason,
}: {
  status: string | null;
  reason?: string | null;
}) {
  if (status == null || status === "ok") return null;
  return (
    <StatusChip
      tone="red"
      label={`daemon ${status}`.replace(/_/g, " ")}
      title={
        reason ||
        "The agent is heartbeating but reports that its daemon is not serving."
      }
    />
  );
}

function ServerRow({
  name,
  host,
  driver,
  status,
  groupName,
  lastSeen,
  isEnabled = true,
  maintenance = false,
  configApplyStatus = null,
  configApplyError = null,
  daemonStatus = null,
  daemonReason = null,
}: {
  name: string;
  host: string;
  driver: string;
  status: string;
  groupName: string;
  lastSeen?: string | null;
  isEnabled?: boolean;
  maintenance?: boolean;
  configApplyStatus?: ConfigApplyStatus | null;
  configApplyError?: string | null;
  daemonStatus?: string | null;
  daemonReason?: string | null;
}) {
  const dotCls =
    status === "active"
      ? "bg-emerald-500"
      : status === "syncing"
        ? "bg-blue-500"
        : status === "pending"
          ? "bg-amber-500"
          : status === "unreachable" || status === "error"
            ? "bg-red-500"
            : "bg-muted-foreground/40";
  const StatusIcon =
    status === "active"
      ? Check
      : status === "unreachable" || status === "error"
        ? Ban
        : Activity;
  return (
    <div className="flex items-center gap-3 px-4 py-2 text-[11px]">
      <span className="relative inline-flex h-2 w-2 flex-shrink-0">
        {status === "active" && isEnabled && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
        )}
        <span
          className={cn(
            "relative inline-flex h-2 w-2 rounded-full",
            isEnabled ? dotCls : "bg-muted-foreground/40",
          )}
          title={isEnabled ? status : "disabled"}
        />
      </span>
      <span className="w-28 truncate font-semibold" title={name}>
        {name}
      </span>
      <span
        className="w-36 truncate font-mono text-muted-foreground"
        title={host}
      >
        {host}
      </span>
      <span className="w-20 truncate text-muted-foreground" title={driver}>
        {driver}
      </span>
      <span className="w-24 truncate text-muted-foreground" title={groupName}>
        {groupName}
      </span>
      <div className="ml-auto flex flex-shrink-0 items-center gap-1.5">
        {maintenance && (
          <StatusChip
            tone="amber"
            label="maintenance"
            title="Operator-set maintenance mode — health alerts are suppressed for this server."
          />
        )}
        <ConfigApplyChip status={configApplyStatus} error={configApplyError} />
        <DaemonChip status={daemonStatus} reason={daemonReason} />
        <StatusIcon className="h-3 w-3 text-muted-foreground/50" />
      </div>
      <span className="w-20 flex-shrink-0 text-right text-muted-foreground">
        {!isEnabled ? "disabled" : lastSeen ? humanTime(lastSeen) : "never"}
      </span>
    </div>
  );
}

/**
 * DHCP pool pressure (#942, over the #913 occupancy computation).
 *
 * The DHCP tab used to show an empty traffic chart and a server list —
 * nothing about leases or pools, despite "can a client still get an
 * address" being the flagship DHCP question and the arithmetic having
 * existed since #339. This answers it fleet-wide in one call.
 *
 * Dynamic pools only, matching the endpoint, the per-scope endpoint and
 * the `dhcp_pool_exhaustion` alert evaluator: an excluded range is never
 * offered to a client and a reserved one is *supposed* to fill up, so
 * either would render as a red exhaustion bar for behaving correctly.
 */
function DhcpPoolPressure() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dhcp-pool-occupancy", "fleet"],
    queryFn: () => dhcpApi.fleetPoolOccupancy(8),
    refetchInterval: 60_000,
  });

  // A failed fetch must not render as "no pools configured" — that is the
  // same false-calm this panel exists to prevent, and an error boundary
  // does not catch a rejected query.
  if (isError) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-400">
        Could not load pool occupancy — allocation pressure is unknown, not
        clear.
      </div>
    );
  }
  if (isLoading) {
    return (
      <div className="rounded-lg border bg-card px-4 py-3 text-xs text-muted-foreground">
        Loading pool occupancy…
      </div>
    );
  }
  if (!data || data.pool_count === 0) {
    return (
      <div className="rounded-lg border bg-card px-4 py-3 text-xs text-muted-foreground">
        No dynamic DHCP pools configured. Add a pool to a scope to see
        allocation pressure here.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Active leases"
          value={data.active_lease_count.toLocaleString()}
          sub="distinct addresses"
          icon={Activity}
          to="/dhcp"
        />
        <KpiCard
          label="Dynamic pools"
          value={data.pool_count}
          sub="fleet-wide"
          icon={Layers}
          to="/dhcp"
        />
        <KpiCard
          label="Pools ≥ 80%"
          value={data.pools_warning}
          tone={data.pools_warning > 0 ? "warn" : "good"}
          sub="nearing exhaustion"
          icon={AlertTriangle}
          to="/dhcp"
        />
        <KpiCard
          label="Pools ≥ 95%"
          value={data.pools_critical}
          tone={data.pools_critical > 0 ? "bad" : "good"}
          sub="effectively full"
          icon={AlertTriangle}
          to="/dhcp"
        />
      </div>

      <div className="rounded-lg border bg-card">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
          <div className="flex items-center gap-2">
            <Server className="h-3.5 w-3.5 text-muted-foreground" />
            <h3 className="text-xs font-semibold uppercase tracking-wider">
              Pools nearest exhaustion
            </h3>
            <span className="text-[11px] text-muted-foreground">
              showing {data.pools.length} of {data.pool_count}
            </span>
          </div>
          <span
            className="text-[11px] text-muted-foreground"
            title="Occupancy is derived from mirrored lease rows, so its freshness follows the last lease pull — not the moment this page rendered."
          >
            as of {humanTime(data.computed_at)}
          </span>
        </div>
        <div className="overflow-x-auto">
          <div className="min-w-[620px] divide-y">
            {data.pools.map((p) => (
              <Link
                key={p.pool_id}
                // DHCPPage restores from ``group`` / ``server`` only —
                // a ``scope`` param is silently dropped and the click
                // lands on whatever was last selected. Deep-link to the
                // owning group, whose panel lists this scope.
                to={`/dhcp?group=${p.group_id}`}
                className="flex items-center gap-4 px-4 py-2.5 transition-colors hover:bg-accent/40"
              >
                <span
                  className="w-52 shrink-0 truncate font-mono text-xs"
                  title={`${p.start_ip} – ${p.end_ip}`}
                >
                  {p.start_ip}–{p.end_ip}
                </span>
                <span className="w-36 truncate text-xs text-muted-foreground">
                  {p.scope_name || p.subnet_network || (
                    <span className="text-muted-foreground/40">—</span>
                  )}
                </span>
                <span className="w-24 truncate text-[11px] text-muted-foreground">
                  {p.group_name}
                </span>
                {/* A scope the operator deactivated is not handing out
                    addresses, so its number is real but not urgent. Flagged
                    rather than hidden — the exhaustion alert still fires on
                    these, and a panel that silently disagreed with the
                    alerting is how a wrong all-clear gets reported. */}
                {!p.scope_is_active && (
                  <StatusChip
                    tone="gray"
                    label="inactive"
                    title="The parent scope is deactivated — it is not currently serving addresses."
                  />
                )}
                <div className="flex-1">
                  <UtilizationBar percent={p.percent} />
                </div>
                <span className="w-28 shrink-0 whitespace-nowrap text-right text-[11px] tabular-nums text-muted-foreground">
                  {p.assigned.toLocaleString()} / {p.total.toLocaleString()}
                </span>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Failover channel row ───────────────────────────────────────────────────
// Kea HA states: normal / hot-standby / load-balancing / ready → green;
// waiting / syncing / communications-interrupted → amber;
// partner-down / terminated → red; null/unknown → muted.
function haStateDotCls(state: string | null | undefined): string {
  if (!state) return "bg-muted-foreground/40";
  if (
    state === "normal" ||
    state === "hot-standby" ||
    state === "load-balancing" ||
    state === "ready"
  )
    return "bg-emerald-500";
  if (state === "partner-down" || state === "terminated") return "bg-red-500";
  return "bg-amber-500";
}

function FailoverRow({ group }: { group: DHCPServerGroup }) {
  // Only Kea members participate in HA. Sort by name for stable display.
  const kea = [...(group.servers ?? [])]
    .filter((s) => s.driver === "kea")
    .sort((a, b) => a.name.localeCompare(b.name));
  return (
    <Link
      to="/dhcp"
      className="flex items-center gap-3 px-4 py-2 text-[11px] hover:bg-muted/30"
    >
      <Shield className="h-3 w-3 flex-shrink-0 text-muted-foreground/60" />
      <span className="w-28 truncate font-semibold" title={group.name}>
        {group.name}
      </span>
      <span className="w-24 truncate text-muted-foreground" title={group.mode}>
        {group.mode}
      </span>
      <span className="ml-auto flex items-center gap-3">
        {kea.map((s) => (
          <span key={s.id} className="flex items-center gap-1">
            <span
              className={cn(
                "inline-block h-2 w-2 rounded-full",
                haStateDotCls(s.ha_state),
              )}
              title={`${s.name}: ${s.ha_state ?? "unknown"}`}
            />
            <span className="text-muted-foreground">
              {s.name}
              <span className="text-muted-foreground/60">
                {" · "}
                {s.ha_state ?? "unknown"}
              </span>
            </span>
          </span>
        ))}
      </span>
    </Link>
  );
}

// ── Platform health card ────────────────────────────────────────────────
// One row per control-plane component (api / postgres / redis / celery
// workers / celery beat). Each comes back from /health/platform with a
// green/amber/red status — we render them as a compact inline strip so
// the whole card fits in roughly the height of a single KPI row.
function platformStatusDotCls(status: PlatformHealthStatus): string {
  return status === "ok"
    ? "bg-emerald-500"
    : status === "warn"
      ? "bg-amber-500"
      : "bg-red-500";
}

function prettyComponentName(name: string): string {
  const map: Record<string, string> = {
    api: "API",
    postgres: "PostgreSQL",
    redis: "Redis",
    "celery-workers": "Workers",
    "celery-beat": "Beat",
  };
  return map[name] ?? name;
}

function PlatformHealthCard({ health }: { health: PlatformHealthResponse }) {
  const headlineTone = health.status === "ok" ? "bg-emerald-500" : "bg-red-500";
  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className={cn("h-1.5 w-1.5 rounded-full", headlineTone)} />
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            Platform Health
          </h3>
          <span className="text-[11px] text-muted-foreground">
            {health.status === "ok" ? "all good" : "degraded"}
          </span>
        </div>
      </div>
      <div className="divide-y sm:grid sm:grid-cols-2 sm:divide-y-0 sm:divide-x lg:grid-cols-5">
        {health.components.map((c) => (
          <div
            key={c.name}
            className="flex min-w-0 items-center gap-2 px-4 py-2.5"
            title={
              c.workers && c.workers.length > 0
                ? `${c.detail}\n${c.workers.join("\n")}`
                : c.detail
            }
          >
            <span
              className={cn(
                "h-1.5 w-1.5 flex-shrink-0 rounded-full",
                platformStatusDotCls(c.status),
              )}
            />
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-medium">
                {prettyComponentName(c.name)}
              </div>
              <div className="truncate text-[10px] text-muted-foreground">
                {c.detail}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Integrations panel ─────────────────────────────────────────────────────
// One section per enabled integration — each row shows name, endpoint
// hint, sync age, mirrored counts, and a status dot that folds
// last_sync_error + staleness into a single green/amber/red signal.
function integrationDotCls(
  lastSyncedAt: string | null,
  lastSyncError: string | null,
  intervalSeconds: number,
  lastSyncWarning?: string | null,
): string {
  if (lastSyncError) return "bg-red-500";
  if (!lastSyncedAt) return "bg-muted-foreground/40";
  // #797 — a pass can be on time and error-free and still mirror nothing
  // (no DHCP backend on the firmware, credentials refused by one backend).
  // Amber rather than green, or the dashboard vouches for an integration
  // that has never produced a row.
  if (lastSyncWarning) return "bg-amber-500";
  const age = (Date.now() - new Date(lastSyncedAt).getTime()) / 1000;
  // Amber when the last sync is older than ~3 intervals — implies the
  // reconcile beat sweep is stalled or the target is unreachable.
  return age > intervalSeconds * 3 ? "bg-amber-500" : "bg-emerald-500";
}

function IntegrationsPanel({
  kubernetesEnabled,
  dockerEnabled,
  proxmoxEnabled,
  opnsenseEnabled,
  panosEnabled,
  fortinetEnabled,
  merakiEnabled,
  cloudEnabled,
  tailscaleEnabled,
  unifiEnabled,
  clusters,
  hosts,
  proxmoxNodes,
  opnsenseRouters,
  panosFirewalls,
  fortinetFirewalls,
  merakiOrgs,
  cloudEndpoints,
  tailscaleTenants,
  unifiControllers,
  netbirdEnabled,
  netbirdInstances,
}: {
  kubernetesEnabled: boolean;
  dockerEnabled: boolean;
  proxmoxEnabled: boolean;
  opnsenseEnabled: boolean;
  panosEnabled: boolean;
  fortinetEnabled: boolean;
  merakiEnabled: boolean;
  cloudEnabled: boolean;
  tailscaleEnabled: boolean;
  unifiEnabled: boolean;
  clusters: KubernetesCluster[];
  hosts: DockerHost[];
  proxmoxNodes: ProxmoxNode[];
  opnsenseRouters: OPNsenseRouter[];
  panosFirewalls: PANOSFirewall[];
  fortinetFirewalls: FortinetFirewall[];
  merakiOrgs: MerakiOrg[];
  cloudEndpoints: CloudEndpoint[];
  tailscaleTenants: TailscaleTenant[];
  unifiControllers: UnifiController[];
  netbirdEnabled: boolean;
  netbirdInstances: NetbirdInstance[];
}) {
  const hasK8s = kubernetesEnabled;
  const hasDocker = dockerEnabled;
  const hasProxmox = proxmoxEnabled;
  const hasOpnsense = opnsenseEnabled;
  const hasPanos = panosEnabled;
  const hasFortinet = fortinetEnabled;
  const hasMeraki = merakiEnabled;
  const hasCloud = cloudEnabled;
  const hasTailscale = tailscaleEnabled;
  const hasUnifi = unifiEnabled;
  const hasNetbird = netbirdEnabled;
  const cols = [
    hasK8s,
    hasDocker,
    hasProxmox,
    hasOpnsense,
    hasPanos,
    hasFortinet,
    hasMeraki,
    hasCloud,
    hasTailscale,
    hasUnifi,
    hasNetbird,
  ].filter(Boolean).length;
  const totalTargets =
    clusters.length +
    hosts.length +
    proxmoxNodes.length +
    opnsenseRouters.length +
    panosFirewalls.length +
    fortinetFirewalls.length +
    merakiOrgs.length +
    cloudEndpoints.length +
    tailscaleTenants.length +
    unifiControllers.length +
    netbirdInstances.length;
  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Plug className="h-3.5 w-3.5 text-muted-foreground" />
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            Integrations
          </h3>
          <span className="text-[11px] text-muted-foreground">
            {totalTargets} target
            {totalTargets === 1 ? "" : "s"}
          </span>
        </div>
      </div>
      <div
        className={cn(
          "grid divide-y",
          cols === 2 && "md:grid-cols-2 md:divide-x md:divide-y-0",
          cols === 3 && "md:grid-cols-3 md:divide-x md:divide-y-0",
          cols === 4 && "md:grid-cols-4 md:divide-x md:divide-y-0",
          cols === 5 && "md:grid-cols-5 md:divide-x md:divide-y-0",
          cols === 6 && "md:grid-cols-6 md:divide-x md:divide-y-0",
          cols === 7 && "md:grid-cols-7 md:divide-x md:divide-y-0",
          cols === 8 && "md:grid-cols-8 md:divide-x md:divide-y-0",
          cols === 9 && "md:grid-cols-9 md:divide-x md:divide-y-0",
          cols === 10 && "md:grid-cols-10 md:divide-x md:divide-y-0",
          cols === 11 && "md:grid-cols-11 md:divide-x md:divide-y-0",
        )}
      >
        {hasK8s && (
          <div className="min-w-0">
            <Link
              to="/kubernetes"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Boxes className="h-3 w-3" />
              Kubernetes ({clusters.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {clusters.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No clusters registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {clusters.map((c) => (
                    <IntegrationRow
                      key={c.id}
                      to={`/kubernetes`}
                      name={c.name}
                      subtitle={c.api_server_url}
                      meta={
                        c.node_count != null ? `${c.node_count} nodes` : "—"
                      }
                      lastSyncedAt={c.last_synced_at}
                      lastSyncError={c.last_sync_error}
                      intervalSeconds={c.sync_interval_seconds}
                      enabled={c.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasDocker && (
          <div className="min-w-0">
            <Link
              to="/docker"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <ContainerIcon className="h-3 w-3" />
              Docker ({hosts.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {hosts.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No hosts registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {hosts.map((h) => (
                    <IntegrationRow
                      key={h.id}
                      to={`/docker`}
                      name={h.name}
                      subtitle={h.endpoint}
                      meta={
                        h.container_count != null
                          ? `${h.container_count} containers`
                          : "—"
                      }
                      lastSyncedAt={h.last_synced_at}
                      lastSyncError={h.last_sync_error}
                      intervalSeconds={h.sync_interval_seconds}
                      enabled={h.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasProxmox && (
          <div className="min-w-0">
            <Link
              to="/proxmox"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <HardDrive className="h-3 w-3" />
              Proxmox ({proxmoxNodes.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {proxmoxNodes.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No endpoints registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {proxmoxNodes.map((p) => (
                    <IntegrationRow
                      key={p.id}
                      to={`/proxmox`}
                      name={p.name}
                      subtitle={`${p.host}:${p.port}`}
                      meta={
                        p.cluster_name
                          ? `${p.cluster_name} (${p.node_count ?? "?"})`
                          : p.node_count != null
                            ? `${p.node_count} node${p.node_count === 1 ? "" : "s"}`
                            : "—"
                      }
                      lastSyncedAt={p.last_synced_at}
                      lastSyncError={p.last_sync_error}
                      intervalSeconds={p.sync_interval_seconds}
                      enabled={p.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasOpnsense && (
          <div className="min-w-0">
            <Link
              to="/opnsense"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Shield className="h-3 w-3" />
              OPNsense ({opnsenseRouters.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {opnsenseRouters.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No firewalls registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {opnsenseRouters.map((r) => (
                    <IntegrationRow
                      key={r.id}
                      to={`/opnsense`}
                      name={r.name}
                      subtitle={`${r.host}:${r.port}`}
                      meta={
                        r.interface_count != null
                          ? `${r.interface_count} iface${r.interface_count === 1 ? "" : "s"}` +
                            (r.lease_count != null
                              ? ` · ${r.lease_count} lease${r.lease_count === 1 ? "" : "s"}`
                              : "")
                          : "—"
                      }
                      lastSyncedAt={r.last_synced_at}
                      lastSyncError={r.last_sync_error}
                      lastSyncWarning={r.last_sync_warning}
                      intervalSeconds={r.sync_interval_seconds}
                      enabled={r.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasPanos && (
          <div className="min-w-0">
            <Link
              to="/paloalto"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <ShieldAlert className="h-3 w-3" />
              Palo Alto ({panosFirewalls.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {panosFirewalls.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No firewalls registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {panosFirewalls.map((f) => (
                    <IntegrationRow
                      key={f.id}
                      to={`/paloalto`}
                      name={f.name}
                      subtitle={`${f.host}:${f.port}`}
                      meta={
                        f.object_count != null
                          ? `${f.object_count} obj${f.object_count === 1 ? "" : "s"}` +
                            (f.nat_rule_count != null
                              ? ` · ${f.nat_rule_count} NAT`
                              : "")
                          : f.is_panorama
                            ? "Panorama"
                            : "—"
                      }
                      lastSyncedAt={f.last_synced_at}
                      lastSyncError={f.last_sync_error}
                      intervalSeconds={f.sync_interval_seconds}
                      enabled={f.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasFortinet && (
          <div className="min-w-0">
            <Link
              to="/fortinet"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Flame className="h-3 w-3" />
              Fortinet ({fortinetFirewalls.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {fortinetFirewalls.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No firewalls registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {fortinetFirewalls.map((f) => (
                    <IntegrationRow
                      key={f.id}
                      to={`/fortinet`}
                      name={f.name}
                      subtitle={`${f.host}:${f.port}`}
                      meta={
                        f.object_count != null
                          ? `${f.object_count} obj${f.object_count === 1 ? "" : "s"}` +
                            (f.nat_rule_count != null
                              ? ` · ${f.nat_rule_count} NAT`
                              : "")
                          : "—"
                      }
                      lastSyncedAt={f.last_synced_at}
                      lastSyncError={f.last_sync_error}
                      intervalSeconds={f.sync_interval_seconds}
                      enabled={f.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasMeraki && (
          <div className="min-w-0">
            <Link
              to="/meraki"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Network className="h-3 w-3" />
              Meraki ({merakiOrgs.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {merakiOrgs.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No organizations registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {merakiOrgs.map((o) => (
                    <IntegrationRow
                      key={o.id}
                      to={`/meraki`}
                      name={o.name}
                      subtitle={`org ${o.org_id}`}
                      meta={
                        o.network_count != null
                          ? `${o.network_count} net${o.network_count === 1 ? "" : "s"}` +
                            (o.object_count != null
                              ? ` · ${o.object_count} obj`
                              : "")
                          : "—"
                      }
                      lastSyncedAt={o.last_synced_at}
                      lastSyncError={o.last_sync_error}
                      intervalSeconds={o.sync_interval_seconds}
                      enabled={o.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasCloud && (
          <div className="min-w-0">
            <Link
              to="/cloud"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Cloud className="h-3 w-3" />
              Cloud ({cloudEndpoints.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {cloudEndpoints.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No accounts registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {cloudEndpoints.map((ep) => (
                    <IntegrationRow
                      key={ep.id}
                      to={`/cloud`}
                      name={ep.name}
                      subtitle={
                        ep.provider_account_id
                          ? `${ep.provider} · ${ep.provider_account_id}`
                          : ep.provider
                      }
                      meta={
                        ep.network_count != null || ep.instance_count != null
                          ? `${ep.network_count ?? 0} net${
                              ep.network_count === 1 ? "" : "s"
                            } · ${ep.instance_count ?? 0} inst`
                          : "—"
                      }
                      lastSyncedAt={ep.last_synced_at}
                      lastSyncError={ep.last_sync_error}
                      intervalSeconds={ep.sync_interval_seconds}
                      enabled={ep.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasTailscale && (
          <div className="min-w-0">
            <Link
              to="/tailscale"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Waypoints className="h-3 w-3" />
              Tailscale ({tailscaleTenants.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {tailscaleTenants.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No tenants registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {tailscaleTenants.map((t) => (
                    <IntegrationRow
                      key={t.id}
                      to={`/tailscale`}
                      name={t.name}
                      subtitle={t.tailnet_domain ?? `tailnet ${t.tailnet}`}
                      meta={
                        t.device_count != null
                          ? `${t.device_count} device${t.device_count === 1 ? "" : "s"}`
                          : "—"
                      }
                      lastSyncedAt={t.last_synced_at}
                      lastSyncError={t.last_sync_error}
                      intervalSeconds={t.sync_interval_seconds}
                      enabled={t.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasUnifi && (
          <div className="min-w-0">
            <Link
              to="/unifi"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Wifi className="h-3 w-3" />
              UniFi ({unifiControllers.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {unifiControllers.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No controllers registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {unifiControllers.map((c) => (
                    <IntegrationRow
                      key={c.id}
                      to={`/unifi/${c.id}`}
                      name={c.name}
                      subtitle={
                        c.mode === "cloud"
                          ? `cloud · ${c.cloud_host_id ? c.cloud_host_id.slice(0, 8) + "…" : "?"}`
                          : `${c.host ?? "?"}:${c.port}`
                      }
                      meta={
                        c.site_count != null
                          ? `${c.site_count} site${c.site_count === 1 ? "" : "s"}` +
                            (c.network_count != null
                              ? ` · ${c.network_count} net${c.network_count === 1 ? "" : "s"}`
                              : "")
                          : "—"
                      }
                      lastSyncedAt={c.last_synced_at}
                      lastSyncError={c.last_sync_error}
                      intervalSeconds={c.sync_interval_seconds}
                      enabled={c.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {hasNetbird && (
          <div className="min-w-0">
            <Link
              to="/netbird"
              className="flex items-center gap-1.5 bg-muted/30 px-4 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/50"
            >
              <Bird className="h-3 w-3" />
              NetBird ({netbirdInstances.length})
              <span className="ml-auto text-[10px] text-muted-foreground/70">
                view all →
              </span>
            </Link>
            {netbirdInstances.length === 0 ? (
              <p className="px-4 py-3 text-[11px] italic text-muted-foreground">
                No instances registered.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <div className="min-w-[520px] divide-y">
                  {netbirdInstances.map((t) => (
                    <IntegrationRow
                      key={t.id}
                      to={`/netbird`}
                      name={t.name}
                      subtitle={t.dns_domain ?? t.api_url}
                      meta={
                        t.peer_count != null
                          ? `${t.peer_count} peer${t.peer_count === 1 ? "" : "s"}`
                          : "—"
                      }
                      lastSyncedAt={t.last_synced_at}
                      lastSyncError={t.last_sync_error}
                      intervalSeconds={t.sync_interval_seconds}
                      enabled={t.enabled}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function IntegrationRow({
  to,
  name,
  subtitle,
  meta,
  lastSyncedAt,
  lastSyncError,
  lastSyncWarning,
  intervalSeconds,
  enabled,
}: {
  to: string;
  name: string;
  subtitle: string;
  meta: string;
  lastSyncedAt: string | null;
  lastSyncError: string | null;
  // Optional — only integrations that compute non-fatal findings pass it.
  lastSyncWarning?: string | null;
  intervalSeconds: number;
  enabled: boolean;
}) {
  const dotCls = !enabled
    ? "bg-muted-foreground/40"
    : integrationDotCls(
        lastSyncedAt,
        lastSyncError,
        intervalSeconds,
        lastSyncWarning,
      );
  return (
    <Link
      to={to}
      className="flex items-center gap-3 px-4 py-2 text-[11px] hover:bg-muted/30"
      title={lastSyncError ?? lastSyncWarning ?? undefined}
    >
      <span className={cn("h-1.5 w-1.5 flex-shrink-0 rounded-full", dotCls)} />
      <span className="w-28 truncate font-semibold" title={name}>
        {name}
      </span>
      <span
        className="w-48 truncate font-mono text-muted-foreground"
        title={subtitle}
      >
        {subtitle}
      </span>
      <span className="w-28 truncate text-muted-foreground" title={meta}>
        {meta}
      </span>
      <span className="ml-auto w-20 flex-shrink-0 text-right text-muted-foreground">
        {!enabled
          ? "disabled"
          : lastSyncedAt
            ? humanTime(lastSyncedAt)
            : "never"}
      </span>
    </Link>
  );
}

// ── Compliance dashboard tab (issue #105 + classification roll-up) ──
//
// Static + reactive view of compliance state:
//
//   - Three KPI cards for the classification flag counts (PCI / HIPAA /
//     internet-facing), click-through to the filtered IPAM list.
//   - Compliance-change rule status — the three seed rules + their
//     enabled / disabled state. Click-through to /admin/alerts.
//   - Recent compliance-change events table — last 20 firings keyed
//     off the ``audit:`` subject_type prefix the evaluator emits.
//
// Conformity (proactive policy evaluation) gets its own tab next to
// this one — different audience question. This tab answers "is
// anything *changing* in scope?", the conformity tab answers "is
// scope still in policy *right now*?".
function CompliancePanel({ subnets }: { subnets: Subnet[] }) {
  const pciCount = subnets.filter((s) => s.pci_scope).length;
  const hipaaCount = subnets.filter((s) => s.hipaa_scope).length;
  const internetCount = subnets.filter((s) => s.internet_facing).length;

  const { data: rules = [] } = useQuery<AlertRule[]>({
    queryKey: ["alert-rules"],
    queryFn: () => alertsApi.listRules(),
    staleTime: 30_000,
  });
  const complianceRules = rules.filter(
    (r) => r.rule_type === "compliance_change",
  );

  // Open + recently-resolved compliance-change events. ``subject_type``
  // for these is ``audit:<resource_type>`` (see services/alerts.py).
  const { data: events = [] } = useQuery<AlertEvent[]>({
    queryKey: ["alert-events", { compliance: true }],
    queryFn: () => alertsApi.listEvents({ limit: 200 }),
    refetchInterval: 30_000,
  });
  const complianceEvents = events
    .filter((e) => e.subject_type.startsWith("audit:"))
    .slice(0, 20);

  return (
    <div className="space-y-5">
      {/* Headline KPIs */}
      <div className="grid gap-3 grid-cols-1 md:grid-cols-2 xl:grid-cols-4">
        <ComplianceKpi
          label="PCI scope"
          count={pciCount}
          total={subnets.length}
          to="/admin/compliance"
          tone="bad"
        />
        <ComplianceKpi
          label="HIPAA scope"
          count={hipaaCount}
          total={subnets.length}
          to="/admin/compliance"
          tone="warn"
        />
        <ComplianceKpi
          label="Internet-facing"
          count={internetCount}
          total={subnets.length}
          to="/admin/compliance"
          tone="warn"
        />
        <CertsExpiringKpi />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Rule coverage card */}
        <div className="rounded-lg border bg-card">
          <div className="flex items-center justify-between border-b px-4 py-2.5">
            <h3 className="text-xs font-semibold uppercase tracking-wider">
              Compliance-change rule coverage
            </h3>
            <Link
              to="/admin/alerts"
              className="text-[11px] text-primary hover:underline"
            >
              Manage rules →
            </Link>
          </div>
          {complianceRules.length === 0 ? (
            <div className="px-4 py-6 text-center text-xs text-muted-foreground">
              No <code>compliance_change</code> rules yet. Three disabled seed
              rules ship at first boot — toggle one on in{" "}
              <Link to="/admin/alerts" className="text-primary hover:underline">
                /admin/alerts
              </Link>
              .
            </div>
          ) : (
            <ul className="divide-y">
              {complianceRules.map((r) => (
                <li
                  key={r.id}
                  className="flex items-center gap-3 px-4 py-2.5 text-xs"
                >
                  <span
                    className={cn(
                      "inline-block h-1.5 w-1.5 rounded-full",
                      r.enabled ? "bg-emerald-500" : "bg-muted-foreground/40",
                    )}
                  />
                  <span className="flex-1 truncate font-medium">{r.name}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {r.classification ?? "—"}
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {r.change_scope ?? "—"}
                  </span>
                  <span
                    className={cn(
                      "rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider",
                      r.enabled
                        ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300"
                        : "bg-muted text-muted-foreground",
                    )}
                  >
                    {r.enabled ? "active" : "off"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Recent events card */}
        <div className="rounded-lg border bg-card">
          <div className="flex items-center justify-between border-b px-4 py-2.5">
            <div className="flex items-center gap-2">
              <span className="relative inline-flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-50" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-amber-500" />
              </span>
              <h3 className="text-xs font-semibold uppercase tracking-wider">
                Recent compliance changes
              </h3>
            </div>
            <Link
              to="/admin/alerts"
              className="text-[11px] text-primary hover:underline"
            >
              View all →
            </Link>
          </div>
          {complianceEvents.length === 0 ? (
            <div className="px-4 py-6 text-center text-xs text-muted-foreground">
              No compliance-change events. Either no rules are enabled or
              nothing scoped has been mutated yet.
            </div>
          ) : (
            <ul className="divide-y max-h-96 overflow-auto">
              {complianceEvents.map((e) => (
                <li key={e.id} className="px-4 py-2 text-xs">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="truncate font-medium">
                      {e.subject_display}
                    </span>
                    <span className="shrink-0 text-[10px] tabular-nums text-muted-foreground">
                      {humanTime(e.fired_at)}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                    {e.message}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <p className="text-[11px] text-muted-foreground">
        Static classification + reactive change view. The companion{" "}
        <span className="font-medium">Conformity</span> tab (next to this one)
        covers proactive evaluation against PCI / HIPAA / SOC2 policies +
        auditor-facing PDF export.
      </p>
    </div>
  );
}

// TLS certs expiring within 30 days (#118). Self-contained + gated on
// the ``security.tls_certs`` feature module so it renders nothing when
// the operator has the module turned off.
function CertsExpiringKpi() {
  const { enabled, ready } = useFeatureModules();
  const moduleOn = enabled("security.tls_certs");

  const { data } = useQuery({
    queryKey: ["tls-certs", "kpi"],
    queryFn: () => tlsCertsApi.list({ limit: 500 }),
    enabled: ready && moduleOn,
    staleTime: 60_000,
  });

  if (ready && !moduleOn) return null;

  const items = data?.items ?? [];
  const expiring = items.filter(
    (t) => t.days_remaining !== null && t.days_remaining <= 30,
  ).length;
  const cls = TONE_CLASS[expiring > 0 ? "bad" : "good"];

  return (
    <Link
      to="/network/certificates"
      className="rounded-lg border bg-card p-4 transition-colors hover:bg-accent/40"
    >
      <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
        Certs expiring ≤30d
      </p>
      <p className={cn("mt-2 text-3xl font-bold tabular-nums", cls.value)}>
        {expiring}
      </p>
      <p className="text-[11px] text-muted-foreground">
        of {items.length} monitored · click to review
      </p>
    </Link>
  );
}

// New devices seen in the last 24h (#459). Self-contained + gated on the
// (default-off) ``security.new_device_watch`` feature module so it renders
// nothing — and fires no query — when the module is turned off.
function NewDevicesKpi() {
  const { enabled, ready } = useFeatureModules();
  const moduleOn = enabled("security.new_device_watch");

  const { data } = useQuery({
    queryKey: ["new-devices", "summary", "kpi"],
    queryFn: () => newDeviceApi.summary(),
    enabled: ready && moduleOn,
    staleTime: 30_000,
  });

  if (ready && !moduleOn) return null;

  const last24h = data?.new_last_24h ?? 0;
  const cls = TONE_CLASS[last24h > 0 ? "bad" : "good"];

  return (
    <Link
      to="/security/new-devices"
      className="rounded-lg border bg-card p-4 transition-colors hover:bg-accent/40"
    >
      <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
        New devices (24h)
      </p>
      <p className={cn("mt-2 text-3xl font-bold tabular-nums", cls.value)}>
        {last24h}
      </p>
      <p className="text-[11px] text-muted-foreground">
        {data?.new_count ?? 0} awaiting review · click to triage
      </p>
    </Link>
  );
}

function ComplianceKpi({
  label,
  count,
  total,
  to,
  tone,
}: {
  label: string;
  count: number;
  total: number;
  to: string;
  tone: Tone;
}) {
  const cls = TONE_CLASS[tone];
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <Link
      to={to}
      className="rounded-lg border bg-card p-4 transition-colors hover:bg-accent/40"
    >
      <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
      <p className={cn("mt-2 text-3xl font-bold tabular-nums", cls.value)}>
        {count}
      </p>
      <p className="text-[11px] text-muted-foreground">
        {pct}% of {total} subnets · click to filter
      </p>
    </Link>
  );
}

// ── Conformity dashboard tab (issue #106) ───────────────────────────
//
// Proactive evaluation view:
//
//   - Per-framework summary cards (pulls /conformity/summary).
//   - "Generate audit PDF" button (uses the authenticated blob fetch).
//   - Recent failing results table (top 20 fail status).
//   - Quick link to /admin/conformity for full management.
//
// The companion Compliance tab covers the static + reactive picture
// (classification roll-up + audit-log change events).
function ConformityPanel() {
  const { enabled, ready } = useFeatureModules();
  const moduleEnabled = enabled("compliance.conformity");
  // Gate queries on ``ready`` so they wait for the real module state; show the
  // "disabled" empty state only once we KNOW it's off (not while still loading).
  const moduleOn = ready && moduleEnabled;
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [pdfBusy, setPdfBusy] = useState(false);
  const summaryQ = useQuery<ConformitySummary>({
    queryKey: ["conformity-summary"],
    queryFn: () => conformityApi.summary(),
    refetchInterval: 60_000,
    enabled: moduleOn,
  });
  const failingQ = useQuery<ConformityResult[]>({
    queryKey: ["conformity-results", "fail-recent"],
    queryFn: () => conformityApi.listResults({ status: "fail", limit: 20 }),
    refetchInterval: 60_000,
    enabled: moduleOn,
  });

  async function handleExportPdf() {
    setPdfError(null);
    setPdfBusy(true);
    try {
      await conformityApi.exportPdf();
    } catch (err) {
      setPdfError(
        err instanceof Error ? err.message : "Failed to generate audit PDF.",
      );
    } finally {
      setPdfBusy(false);
    }
  }

  // When the Conformity module is off the /conformity/* endpoints 404 —
  // show a muted empty state instead of a wall of red error cards. Only once
  // ready (known-off), so we don't flash this during the module-load window.
  if (ready && !moduleEnabled) {
    return (
      <div className="rounded-lg border bg-card p-8 text-center text-sm text-muted-foreground">
        Conformity module is disabled — enable it in Settings → Features.
      </div>
    );
  }

  const summary = summaryQ.data;
  const totalEvaluated = summary
    ? summary.overall_pass +
      summary.overall_warn +
      summary.overall_fail +
      summary.overall_not_applicable
    : 0;
  const totalPassPct =
    summary && totalEvaluated > 0
      ? Math.round((summary.overall_pass / totalEvaluated) * 100)
      : 0;

  return (
    <div className="space-y-5">
      {/* Headline */}
      <div className="grid gap-3 grid-cols-2 md:grid-cols-4">
        <div className="rounded-lg border bg-card p-4">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
            Overall pass rate
          </p>
          <p className="mt-2 text-3xl font-bold tabular-nums">
            {totalEvaluated > 0 ? `${totalPassPct}%` : "—"}
          </p>
          <p className="text-[11px] text-muted-foreground">
            {summary?.overall_pass ?? 0} pass · {summary?.overall_fail ?? 0}{" "}
            fail · {summary?.overall_warn ?? 0} warn
          </p>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
            Failing
          </p>
          <p
            className={cn(
              "mt-2 text-3xl font-bold tabular-nums",
              (summary?.overall_fail ?? 0) > 0
                ? TONE_CLASS.bad.value
                : TONE_CLASS.good.value,
            )}
          >
            {summary?.overall_fail ?? 0}
          </p>
          <p className="text-[11px] text-muted-foreground">
            policy / resource pairs currently failing
          </p>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
            Frameworks
          </p>
          <p className="mt-2 text-3xl font-bold tabular-nums">
            {summary?.frameworks.length ?? 0}
          </p>
          <p className="text-[11px] text-muted-foreground">
            {summary?.frameworks.reduce((s, f) => s + f.policies_enabled, 0) ??
              0}{" "}
            policies enabled
          </p>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
            Last evaluated
          </p>
          <p className="mt-2 text-sm font-medium">
            {summary?.last_evaluated_at
              ? humanTime(summary.last_evaluated_at)
              : "never"}
          </p>
          <p className="text-[11px] text-muted-foreground">
            beat ticks every 60 s; per-policy interval gate
          </p>
        </div>
      </div>

      {/* Action bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border bg-card px-4 py-2.5">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <ClipboardCheck className="h-4 w-4" />
          Auditor PDF export covers every framework + policy + resource with the
          latest result, plus a SHA-256 integrity hash.
        </div>
        <div className="flex flex-col items-end gap-1">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleExportPdf}
              disabled={pdfBusy}
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
            >
              <FileDown className="h-3.5 w-3.5" />
              {pdfBusy ? "Generating…" : "Generate audit PDF"}
            </button>
            <Link
              to="/admin/conformity"
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-accent"
            >
              Manage policies →
            </Link>
          </div>
          {pdfError && (
            <p className="text-[11px] text-red-600 dark:text-red-400">
              {pdfError}
            </p>
          )}
        </div>
      </div>

      {/* Per-framework cards */}
      {summary && summary.frameworks.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {summary.frameworks.map((fw) => {
            const fwTotal =
              fw.pass_count +
              fw.warn_count +
              fw.fail_count +
              fw.not_applicable_count;
            const passPct =
              fwTotal > 0 ? Math.round((fw.pass_count / fwTotal) * 100) : 0;
            return (
              <Link
                key={fw.framework}
                to="/admin/conformity"
                className="rounded-lg border bg-card p-3 transition-colors hover:bg-accent/40"
              >
                <p className="text-xs font-semibold">{fw.framework}</p>
                <p className="text-[11px] text-muted-foreground">
                  {fw.policies_enabled}/{fw.policies_total} policies enabled
                </p>
                <p
                  className={cn(
                    "mt-2 text-xl font-bold tabular-nums",
                    fw.fail_count > 0
                      ? TONE_CLASS.bad.value
                      : passPct >= 95
                        ? TONE_CLASS.good.value
                        : TONE_CLASS.warn.value,
                  )}
                >
                  {fwTotal === 0 ? "—" : `${passPct}%`}
                </p>
                <p className="text-[11px] text-muted-foreground">
                  <span className="text-emerald-600 dark:text-emerald-400">
                    {fw.pass_count}p
                  </span>{" "}
                  ·{" "}
                  <span className="text-amber-600 dark:text-amber-400">
                    {fw.warn_count}w
                  </span>{" "}
                  ·{" "}
                  <span className="text-red-600 dark:text-red-400">
                    {fw.fail_count}f
                  </span>
                </p>
              </Link>
            );
          })}
        </div>
      )}

      {/* Failing results */}
      <div className="rounded-lg border bg-card">
        <div className="flex items-center justify-between border-b px-4 py-2.5">
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            Recent failing results
          </h3>
          <Link
            to="/admin/conformity"
            className="text-[11px] text-primary hover:underline"
          >
            View all →
          </Link>
        </div>
        {failingQ.isLoading ? (
          <div className="px-4 py-6 text-center text-xs text-muted-foreground">
            Loading…
          </div>
        ) : (failingQ.data ?? []).length === 0 ? (
          <div className="px-4 py-6 text-center text-xs text-muted-foreground">
            <Check className="mx-auto mb-2 h-4 w-4 text-emerald-500" />
            Nothing currently failing. Either no policies are enabled, or every
            evaluated resource is in policy.
          </div>
        ) : (
          <ul className="divide-y max-h-96 overflow-auto">
            {(failingQ.data ?? []).map((r) => (
              <li key={r.id} className="px-4 py-2 text-xs">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate font-medium">
                    {r.resource_kind} {r.resource_display}
                  </span>
                  <span className="shrink-0 text-[10px] tabular-nums text-muted-foreground">
                    {humanTime(r.evaluated_at)}
                  </span>
                </div>
                <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                  {r.detail || "(no detail)"}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── Network dashboard tab (issue #107) ──────────────────────────────
//
// Single rollup endpoint at /dashboards/network/summary aggregates
// the cross-entity network signals (ASN drift / RPKI ROA expiry /
// circuit term + status / service orphans / overlay impact) into one
// payload, so the front end does one query per tab visit.
//
// Layout:
//
//   - Six KPI cards (drift / ROA expiring / ROA expired / circuits /
//     orphan services / overlay impact) — click-through to the
//     canonical admin pages.
//   - Two-column detail grid: ASN drift list + RPKI ROAs expiring
//     soon (left), circuit alerts + orphan services + overlay
//     impact (right).
function NetworkPanel() {
  const { data, isLoading } = useQuery<NetworkDashboardSummary>({
    queryKey: ["dashboards", "network"],
    queryFn: () => dashboardsApi.networkSummary(),
    refetchInterval: 60_000,
  });

  if (isLoading || !data) {
    return (
      <div className="rounded-lg border bg-card p-8 text-center text-xs text-muted-foreground">
        Loading network signals…
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* KPI ribbon */}
      <div className="grid gap-3 grid-cols-2 md:grid-cols-3 xl:grid-cols-6">
        <NetworkKpi
          label="ASN drift"
          value={data.asn_drift_count}
          tone={data.asn_drift_count > 0 ? "warn" : "good"}
          to="/network/asns"
        />
        <RpkiExpiringKpi data={data} />
        <NetworkKpi
          label="RPKI expired"
          value={data.rpki_expired_count}
          tone={data.rpki_expired_count > 0 ? "bad" : "good"}
          to="/network/asns"
        />
        <NetworkKpi
          label="Circuit alerts"
          value={
            data.circuit_term_expiring_count + data.circuit_status_changed_count
          }
          tone={
            data.circuit_term_expiring_count +
              data.circuit_status_changed_count >
            0
              ? "warn"
              : "good"
          }
          to="/network/circuits"
          hint={`${data.circuit_term_expiring_count} term · ${data.circuit_status_changed_count} status`}
        />
        <NetworkKpi
          label="Orphan services"
          value={data.service_orphan_count}
          tone={data.service_orphan_count > 0 ? "bad" : "good"}
          to="/network/services"
        />
        <NetworkKpi
          label="Overlays impacted"
          value={data.overlay_impacted_count}
          tone={data.overlay_impacted_count > 0 ? "warn" : "good"}
          to="/network/overlays"
        />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <DashboardListCard
          title="ASN holder drift"
          emptyHint="No ASNs in drift state right now."
        >
          {data.asn_drift.map((row) => (
            <Link
              key={row.id}
              to={`/network/asns/${row.id}`}
              className="block px-4 py-2 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-medium">
                  AS{row.number}
                  {row.name ? ` · ${row.name}` : ""}
                </span>
                <span className="text-[10px] text-muted-foreground">drift</span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                {row.previous_holder ? `${row.previous_holder} → ` : ""}
                {row.holder_org ?? "(unknown)"}
              </p>
            </Link>
          ))}
        </DashboardListCard>
        <DashboardListCard
          title="RPKI ROAs expiring soon"
          emptyHint="No ROAs are expiring in the next 30 days."
        >
          {data.rpki_expiring.map((row) => (
            <Link
              key={row.id}
              to={row.asn_id ? `/network/asns/${row.asn_id}` : "/network/asns"}
              className="block px-4 py-2 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-mono">
                  AS{row.asn_number ?? "?"} {row.prefix}
                  {row.max_length != null ? `-${row.max_length}` : ""}
                </span>
                <span
                  className="text-[10px] text-muted-foreground tabular-nums"
                  title={row.valid_to ?? undefined}
                >
                  {row.valid_to ? futureTime(row.valid_to) : "—"}
                </span>
              </div>
            </Link>
          ))}
        </DashboardListCard>
        <DashboardListCard
          title="Circuit alerts"
          emptyHint="No circuits past term or in suspended/decom status."
        >
          {data.circuit_alerts.map((row) => (
            <Link
              key={row.id}
              to="/network/circuits"
              className="block px-4 py-2 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-medium">{row.name}</span>
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider",
                    row.status === "decom"
                      ? "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
                      : row.status === "suspended"
                        ? "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
                        : "bg-muted text-muted-foreground",
                  )}
                >
                  {row.status}
                </span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                {row.transport ?? "—"}
                {row.term_end_date ? ` · term ${row.term_end_date}` : ""}
              </p>
            </Link>
          ))}
        </DashboardListCard>
        <DashboardListCard
          title="Orphan services + overlay impact"
          emptyHint="Service catalog clean and no overlays touching down circuits."
        >
          {data.orphan_services.map((row) => (
            <Link
              key={row.service_id + row.resource_id}
              to="/network/services"
              className="block px-4 py-2 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-medium">{row.service_name}</span>
                <span className="text-[10px] text-red-600 dark:text-red-400">
                  orphan {row.resource_kind}
                </span>
              </div>
              <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
                {row.resource_id}
              </p>
            </Link>
          ))}
          {data.overlay_impact.map((row) => (
            <Link
              key={row.id}
              to={`/network/overlays/${row.id}`}
              className="block px-4 py-2 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-medium">{row.name}</span>
                <span className="text-[10px] text-amber-700 dark:text-amber-400">
                  impacted
                </span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                {row.note}
              </p>
            </Link>
          ))}
        </DashboardListCard>
      </div>

      <p className="text-[11px] text-muted-foreground">
        Refreshes every 60 s. Click any row to deep-link into the canonical
        admin page for triage.
      </p>
    </div>
  );
}

/**
 * RPKI "expiring soon" KPI (#942).
 *
 * Three states, because a bare count answered the wrong question. An
 * empty ROA table and a healthy one both rendered a green 0, and a pull
 * that stopped days ago rendered whatever it last wrote as though it
 * were current. The count is only meaningful if the data behind it is
 * fresh, so freshness is checked first and reported instead of the
 * count when it fails.
 *
 * The threshold is 24 h against a default refresh interval of 4 h (beat
 * ticks hourly) — six missed cycles, generous enough not to flap on a
 * slow sweep and short enough to notice a dead task the same day.
 */
function RpkiExpiringKpi({ data }: { data: NetworkDashboardSummary }) {
  const STALE_AFTER_MS = 24 * 60 * 60 * 1000;
  const checkedAt = data.rpki_last_checked_at;
  const ageMs = checkedAt ? Date.now() - new Date(checkedAt).getTime() : null;
  const stale = ageMs != null && ageMs > STALE_AFTER_MS;

  if (data.rpki_total_count === 0) {
    return (
      <NetworkKpi
        label="RPKI expiring"
        value="—"
        tone="default"
        to="/network/asns"
        hint="no ROAs tracked"
        title="No RPKI ROAs have been pulled yet. Add a public ASN and the hourly refresh will populate them."
      />
    );
  }
  if (stale || checkedAt === null) {
    return (
      <NetworkKpi
        label="RPKI expiring"
        value="stale"
        tone="warn"
        to="/network/asns"
        hint={checkedAt ? `checked ${humanTime(checkedAt)}` : "never checked"}
        title={`The ROA refresh has not run recently, so any count here would be fiction. ${data.rpki_total_count} ROAs tracked.`}
      />
    );
  }
  return (
    <NetworkKpi
      label="RPKI expiring"
      value={data.rpki_expiring_count}
      tone={data.rpki_expiring_count > 0 ? "warn" : "good"}
      to="/network/asns"
      hint={`< 30 d · of ${data.rpki_total_count.toLocaleString()} · checked ${humanTime(checkedAt)}`}
      title="ROAs inside 30 days of their certificate expiry. Only sources whose validity field is a per-ROA lifetime contribute — Cloudflare's rpki.json ships a short-cycle cache expiry that every ROA carries, so it is deliberately not counted here."
    />
  );
}

function NetworkKpi({
  label,
  value,
  tone,
  to,
  hint,
  title,
}: {
  label: string;
  value: number | string;
  tone: Tone;
  to: string;
  hint?: string;
  title?: string;
}) {
  const cls = TONE_CLASS[tone];
  return (
    <Link
      to={to}
      title={title}
      className="rounded-lg border bg-card p-3 transition-colors hover:bg-accent/40"
    >
      <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
      <p className={cn("mt-1 text-2xl font-bold tabular-nums", cls.value)}>
        {value}
      </p>
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </Link>
  );
}

// ── Integrations dashboard tab (issue #108) ─────────────────────────
//
// Per-integration health rollup. Renders one card per *enabled*
// integration; disabled ones get a one-line placeholder pointing to
// /settings → integrations. Recent reconciler errors at the bottom
// pull from the audit log via the same rollup endpoint.
//
// Named with the ``DashboardTab`` suffix so it doesn't collide with
// the existing ``IntegrationsPanel`` component used inside the
// Overview tab (the legacy one is per-target chips, this one is the
// rollup-driven tab body).
function IntegrationsDashboardTabPanel() {
  const { data, isLoading } = useQuery<IntegrationsDashboardSummary>({
    queryKey: ["dashboards", "integrations"],
    queryFn: () => dashboardsApi.integrationsSummary(),
    refetchInterval: 30_000,
  });

  if (isLoading || !data) {
    return (
      <div className="rounded-lg border bg-card p-8 text-center text-xs text-muted-foreground">
        Loading integration health…
      </div>
    );
  }

  const enabledPanels = data.panels.filter((p) => p.enabled);
  if (enabledPanels.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-10 text-center">
        <Plug className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
        <p className="text-sm font-medium">No integrations are enabled yet</p>
        <p className="mt-1 text-xs text-muted-foreground">
          Head to{" "}
          <Link
            to="/admin/features"
            className="text-primary underline underline-offset-2"
          >
            Features → Integrations
          </Link>{" "}
          to enable read-only infrastructure mirrors.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {enabledPanels.map((p) => (
          <IntegrationCard key={p.kind} panel={p} />
        ))}
      </div>

      <DashboardListCard
        title="Recent reconciler errors"
        emptyHint="No reconciler errors in recent history."
      >
        {data.recent_errors.map((e) => (
          <div key={e.id} className="px-4 py-2 text-xs">
            <div className="flex items-baseline justify-between gap-2">
              <span className="font-medium">
                {e.integration} · {e.target_display || e.target_id}
              </span>
              <span className="text-[10px] tabular-nums text-muted-foreground">
                {humanTime(e.timestamp)}
              </span>
            </div>
            {e.error_detail && (
              <p className="mt-0.5 truncate font-mono text-[10px] text-red-600 dark:text-red-400">
                {e.error_detail}
              </p>
            )}
          </div>
        ))}
      </DashboardListCard>

      <p className="text-[11px] text-muted-foreground">
        Refreshes every 30 s. A target is flagged stale when its last sync is
        older than 2× its configured
        <code className="mx-1 rounded bg-muted px-1 font-mono text-[10px]">
          sync_interval_seconds
        </code>
        .
      </p>
    </div>
  );
}

function IntegrationCard({ panel }: { panel: IntegrationsDashboardPanel }) {
  // #797 — a warned target syncs on time and without error but isn't
  // producing what it was configured to produce, so it must not read as
  // green here while the IPAM-tab panel shows it amber.
  const tone: Tone =
    panel.error_count > 0
      ? "bad"
      : panel.stale_count > 0 || panel.warning_count > 0
        ? "warn"
        : "good";
  const cls = TONE_CLASS[tone];
  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold">{panel.label}</p>
        <span
          className={cn("inline-block h-1.5 w-1.5 rounded-full", cls.accent)}
        />
      </div>
      <p className={cn("mt-1 text-2xl font-bold tabular-nums", cls.value)}>
        {panel.target_count}
      </p>
      <p className="text-[11px] text-muted-foreground">
        <span className="text-emerald-600 dark:text-emerald-400">
          {panel.healthy_count} healthy
        </span>
        {panel.stale_count > 0 && (
          <>
            {" · "}
            <span className="text-amber-600 dark:text-amber-400">
              {panel.stale_count} stale
            </span>
          </>
        )}
        {panel.warning_count > 0 && (
          <>
            {" · "}
            <span className="text-amber-600 dark:text-amber-400">
              {panel.warning_count} warning
            </span>
          </>
        )}
        {panel.error_count > 0 && (
          <>
            {" · "}
            <span className="text-red-600 dark:text-red-400">
              {panel.error_count} error
            </span>
          </>
        )}
      </p>
      {panel.targets.length > 0 && (
        <ul className="mt-2 space-y-1 text-[11px]">
          {panel.targets.slice(0, 3).map((t) => (
            <li
              key={t.id}
              className="flex items-baseline justify-between gap-2"
            >
              <span
                className="truncate"
                title={t.last_sync_warning ?? t.display}
              >
                {t.display}
              </span>
              <span
                className={cn(
                  "shrink-0 tabular-nums",
                  t.last_sync_error
                    ? "text-red-600 dark:text-red-400"
                    : t.is_stale || t.last_sync_warning
                      ? "text-amber-600 dark:text-amber-400"
                      : "text-muted-foreground",
                )}
                title={t.last_sync_error ?? t.last_sync_warning ?? undefined}
              >
                {t.last_synced_at ? humanTime(t.last_synced_at) : "never"}
              </span>
            </li>
          ))}
          {panel.targets.length > 3 && (
            <li className="text-[10px] text-muted-foreground">
              + {panel.targets.length - 3} more
            </li>
          )}
        </ul>
      )}
    </div>
  );
}

// ── Security dashboard tab (issue #109) ─────────────────────────────
//
/**
 * DNS tunneling rollup card on the Security tab (#699).
 *
 * Deliberately silent when the feature module is off (the endpoint
 * 404s), and deliberately LOUD when it is on but has scored nothing —
 * "no data" and "no threats" look identical on a dashboard unless you
 * say which one you mean, and only one of them is reassuring.
 */
function DNSThreatCard() {
  // Gate the QUERY on the module, not just the render (#942). Hiding
  // the card on a 404 still fired the request — and with a 60 s
  // refetch, that is a console error every minute forever on every
  // install with the module off. The 404 handling below stays as a
  // backstop for the module being turned off while the page is open.
  // ``ready &&`` is load-bearing, not belt-and-braces: ``enabled``
  // optimistically returns true until the module set has loaded, so
  // gating on it alone still fires one 404 per hard page load — see
  // the hook's own docstring.
  const { enabled, ready } = useFeatureModules();
  const moduleEnabled = ready && enabled("security.dns_threat");
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboards", "dns-threat"],
    queryFn: () => dnsThreatApi.summary({ hours: 24 }),
    refetchInterval: 60_000,
    retry: false,
    enabled: moduleEnabled,
  });

  const moduleOff =
    (error as { response?: { status?: number } } | null)?.response?.status ===
    404;
  if (!moduleEnabled || moduleOff || isLoading) return null;
  if (!data) return null;

  const tone: Tone = !data.has_data
    ? "warn"
    : data.suspicious_clients > 0
      ? "bad"
      : "good";

  return (
    <div className="rounded-lg border bg-card p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">DNS tunneling (24 h)</h3>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Clients scored for exfiltration-shaped DNS behaviour
          </p>
        </div>
        <Link
          to="/logs?tab=dns-threat"
          className="shrink-0 text-xs text-primary hover:underline"
        >
          View →
        </Link>
      </div>

      {!data.has_data ? (
        <p className="mt-3 text-xs text-amber-600 dark:text-amber-400">
          Nothing scored yet — this is <strong>not</strong> an all-clear. The
          rollup needs query logging enabled on a DNS server group.
        </p>
      ) : (
        <>
          <div className="mt-3 flex items-baseline gap-2">
            <span
              className={
                tone === "bad"
                  ? "text-2xl font-semibold text-rose-600 dark:text-rose-400"
                  : "text-2xl font-semibold text-emerald-600 dark:text-emerald-400"
              }
            >
              {data.suspicious_clients}
            </span>
            <span className="text-xs text-muted-foreground">
              suspicious of {data.clients_seen} client(s) scored
            </span>
          </div>
          {data.worst_client_ip && data.worst_client_score != null && (
            <p className="mt-2 break-words text-xs text-muted-foreground">
              Worst: <span className="font-mono">{data.worst_client_ip}</span>{" "}
              at {data.worst_client_score.toFixed(0)}/100
              {data.worst_client_parent && (
                <>
                  {" "}
                  on{" "}
                  <span className="font-mono">{data.worst_client_parent}</span>
                </>
              )}
            </p>
          )}
        </>
      )}
    </div>
  );
}

// MFA coverage / API token expiry / failed-login bursts / recent
// permission changes. Single rollup endpoint at
// /dashboards/security/summary to keep the front end down to one
// query. MFA coverage uses local-auth users only — external-auth
// users authenticate against the upstream provider.
function SecurityPanel() {
  const { data, isLoading } = useQuery<SecurityDashboardSummary>({
    queryKey: ["dashboards", "security"],
    queryFn: () => dashboardsApi.securitySummary(),
    refetchInterval: 60_000,
  });

  if (isLoading || !data) {
    return (
      <div className="rounded-lg border bg-card p-8 text-center text-xs text-muted-foreground">
        Loading security signals…
      </div>
    );
  }

  const mfaTone: Tone =
    data.mfa_coverage_pct >= 90
      ? "good"
      : data.mfa_coverage_pct >= 50
        ? "warn"
        : "bad";

  return (
    <div className="space-y-5">
      <DNSThreatCard />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Link
          to="/admin/users"
          className="rounded-lg border bg-card p-3 transition-colors hover:bg-accent/40"
        >
          <div className="flex items-center justify-between">
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
              MFA coverage
            </p>
            <Lock className="h-3.5 w-3.5 text-muted-foreground" />
          </div>
          <p
            className={cn(
              "mt-1 text-2xl font-bold tabular-nums",
              TONE_CLASS[mfaTone].value,
            )}
          >
            {data.mfa_total_local_users === 0
              ? "—"
              : `${data.mfa_coverage_pct.toFixed(0)}%`}
          </p>
          <p className="text-[11px] text-muted-foreground">
            {data.mfa_enrolled_count}/{data.mfa_total_local_users} local users
          </p>
        </Link>
        <Link
          to="/admin/api-tokens"
          className="rounded-lg border bg-card p-3 transition-colors hover:bg-accent/40"
        >
          <div className="flex items-center justify-between">
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
              Tokens expiring
            </p>
            <KeyRound className="h-3.5 w-3.5 text-muted-foreground" />
          </div>
          <p
            className={cn(
              "mt-1 text-2xl font-bold tabular-nums",
              data.api_tokens_expiring_count > 0
                ? TONE_CLASS.warn.value
                : TONE_CLASS.good.value,
            )}
          >
            {data.api_tokens_expiring_count}
          </p>
          <p className="text-[11px] text-muted-foreground">
            of {data.api_tokens_total} tokens · within 30 d
          </p>
        </Link>
        <Link
          to="/admin/audit"
          className="rounded-lg border bg-card p-3 transition-colors hover:bg-accent/40"
        >
          <div className="flex items-center justify-between">
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
              Failed logins
            </p>
            <Ban className="h-3.5 w-3.5 text-muted-foreground" />
          </div>
          <p
            className={cn(
              "mt-1 text-2xl font-bold tabular-nums",
              data.failed_login_total > 0
                ? TONE_CLASS.warn.value
                : TONE_CLASS.good.value,
            )}
          >
            {data.failed_login_total}
          </p>
          <p className="text-[11px] text-muted-foreground">
            past {data.failed_login_window_hours} h
          </p>
        </Link>
        <Link
          to="/admin/audit"
          className="rounded-lg border bg-card p-3 transition-colors hover:bg-accent/40"
        >
          <div className="flex items-center justify-between">
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
              Permission changes
            </p>
            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
          </div>
          <p className="mt-1 text-2xl font-bold tabular-nums">
            {data.permission_change_count}
          </p>
          <p className="text-[11px] text-muted-foreground">
            past {data.permission_change_window_days} d
          </p>
        </Link>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <DashboardListCard
          title={`Local users without MFA (${data.mfa_unenrolled.length})`}
          emptyHint="Every local user has TOTP enrolled."
        >
          {data.mfa_unenrolled.map((u) => (
            <Link
              key={u.id}
              to="/admin/users"
              className="block px-4 py-2 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-medium">{u.display_name}</span>
                <span className="text-[10px] tabular-nums text-muted-foreground">
                  {u.last_login_at
                    ? `last seen ${humanTime(u.last_login_at)}`
                    : "never logged in"}
                </span>
              </div>
              <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                {u.username}
              </p>
            </Link>
          ))}
        </DashboardListCard>
        <DashboardListCard
          title="API tokens expiring < 30 d"
          emptyHint="No tokens are expiring in the next 30 days."
        >
          {data.api_tokens_expiring.map((t) => (
            <Link
              key={t.id}
              to="/admin/api-tokens"
              className="block px-4 py-2 transition-colors hover:bg-accent/40"
            >
              <div className="flex items-baseline justify-between gap-2 text-xs">
                <span className="font-medium">{t.name}</span>
                <span className="text-[10px] tabular-nums text-muted-foreground">
                  {t.days_remaining != null
                    ? `${t.days_remaining} d remaining`
                    : "—"}
                </span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                {t.user_display ?? "(no owner)"} ·{" "}
                {t.scopes.length === 0 ? "all scopes" : t.scopes.join(", ")}
              </p>
            </Link>
          ))}
        </DashboardListCard>
        <DashboardListCard
          title={`Failed logins past ${data.failed_login_window_hours} h`}
          emptyHint={`No failed logins in the last ${data.failed_login_window_hours} h.`}
        >
          {data.failed_login_top_sources.map((row, i) => (
            <div
              key={`${row.user_display_name}-${row.source_ip ?? "na"}-${i}`}
              className="px-4 py-2 text-xs"
            >
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-medium">{row.user_display_name}</span>
                <span
                  className={cn(
                    "rounded px-1.5 py-0.5 text-[10px] tabular-nums",
                    row.failure_count >= 5
                      ? "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
                      : "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300",
                  )}
                >
                  {row.failure_count}× fail
                </span>
              </div>
              <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
                {row.source_ip ?? "(unknown source)"} · last{" "}
                {humanTime(row.latest_at)}
              </p>
            </div>
          ))}
        </DashboardListCard>
        <DashboardListCard
          title={`Permission changes past ${data.permission_change_window_days} d`}
          emptyHint="No role / group / token / auth-provider changes recorded."
        >
          {data.permission_changes.map((row) => (
            <div key={row.id} className="px-4 py-2 text-xs">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-medium">{row.actor}</span>
                <span className="text-[10px] tabular-nums text-muted-foreground">
                  {humanTime(row.timestamp)}
                </span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                <span className="font-mono">{row.action}</span>{" "}
                {row.resource_type}{" "}
                <span className="font-mono">
                  {row.resource_display || row.resource_id}
                </span>
              </p>
            </div>
          ))}
        </DashboardListCard>
      </div>

      <p className="text-[11px] text-muted-foreground">
        MFA coverage is computed against local-auth users only — external-auth
        users (LDAP / OIDC / SAML) authenticate against the upstream provider.
        Refreshes every 60 s.
      </p>
    </div>
  );
}

// ── Shared list-card scaffold for dashboard panels ──────────────────
function DashboardListCard({
  title,
  emptyHint,
  children,
}: {
  title: string;
  emptyHint: string;
  children: React.ReactNode;
}) {
  // ``React.Children.toArray`` flattens nested arrays (a card fed two
  // separate ``.map()`` lists arrives as ``[arrayA, arrayB]``) and drops
  // ``null`` / ``false`` / empty children, so an empty card correctly
  // shows its ``emptyHint`` instead of rendering two empty <li>s.
  const childArray = Children.toArray(children).filter(Boolean);
  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2.5">
        <h3 className="text-xs font-semibold uppercase tracking-wider">
          {title}
        </h3>
      </div>
      {childArray.length === 0 ? (
        <div className="px-4 py-6 text-center text-xs text-muted-foreground">
          {emptyHint}
        </div>
      ) : (
        <ul className="divide-y max-h-96 overflow-auto">
          {childArray.map((child, i) => (
            <li key={i}>{child}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
