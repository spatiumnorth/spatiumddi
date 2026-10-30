import { useQuery } from "@tanstack/react-query";
import {
  BarChart3,
  Users,
  ClipboardList,
  Globe,
  RefreshCw,
} from "lucide-react";

import { usePermissions } from "@/hooks/usePermissions";
import { reportsApi } from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { humanTime } from "@/pages/network/_shared";
import { cn } from "@/lib/utils";

/**
 * Top-N reports (issue #47). Four fixed ranked-table cards derived
 * server-side from existing tables:
 *
 * * Subnets by utilization
 * * Owners (customers) by IP count
 * * Most-modified resources (7-day window)
 * * Noisiest DNS clients (24-hour query-log window)
 *
 * Read-only — every card is a ``useQuery`` against ``reportsApi`` with
 * loading / empty / error fallbacks. The whole surface is gated by the
 * ``reports.top_n`` feature module (sidebar entry + router both gate),
 * so a disabled module never routes here. Each report route also takes
 * its own read grant; a card whose grant the user lacks is not fetched
 * and says so, rather than reading "Failed to load" (#3130, the #2702
 * pattern).
 */
export function ReportsPage() {
  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-[1200px] space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Reports</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Fixed Top-N rollups derived from your live IPAM, audit, and
              DNS-query data.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <TopSubnetsCard />
          <TopOwnersCard />
          <TopModifiedCard />
          <TopDNSClientsCard />
        </div>
      </div>
    </div>
  );
}

// ── Shared card chrome ──────────────────────────────────────────────

const RANK_CLS =
  "w-6 shrink-0 text-right font-mono text-xs text-muted-foreground tabular-nums";

function ReportCard({
  title,
  subtitle,
  icon: Icon,
  generatedAt,
  isLoading,
  isError,
  isEmpty,
  emptyHint,
  withheld,
  onRefresh,
  children,
}: {
  title: string;
  subtitle?: string;
  icon: React.ElementType;
  generatedAt?: string;
  isLoading: boolean;
  isError: boolean;
  isEmpty: boolean;
  emptyHint: string;
  /** Set when the user lacks the route's read grant: the reason shown in
   *  place of the report, which is never fetched. */
  withheld?: string;
  onRefresh: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col rounded-lg border bg-card">
      <div className="flex items-start justify-between gap-2 border-b p-4">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span className="truncate">{title}</span>
          </h2>
          {subtitle && (
            <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>
          )}
        </div>
        {!withheld && (
          <HeaderButton
            variant="secondary"
            icon={RefreshCw}
            onClick={onRefresh}
          >
            Refresh
          </HeaderButton>
        )}
      </div>

      <div className="p-2">
        {withheld && (
          <p className="p-4 text-center text-sm text-muted-foreground">
            {withheld}
          </p>
        )}
        {!withheld && isLoading && (
          <p className="p-4 text-center text-sm text-muted-foreground">
            Loading…
          </p>
        )}
        {!withheld && !isLoading && isError && (
          <p className="p-4 text-center text-sm text-destructive">
            Failed to load this report.
          </p>
        )}
        {!withheld && !isLoading && !isError && isEmpty && (
          <p className="p-4 text-center text-sm text-muted-foreground">
            {emptyHint}
          </p>
        )}
        {!withheld && !isLoading && !isError && !isEmpty && children}
      </div>

      {!withheld && !isLoading && !isError && generatedAt && (
        <div className="border-t px-4 py-2 text-[11px] text-muted-foreground">
          As of {humanTime(generatedAt)}
        </div>
      )}
    </div>
  );
}

function Bar({ pct }: { pct: number }) {
  const clamped = Math.max(0, Math.min(100, pct));
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
      <div
        className={cn(
          "h-full rounded-full",
          clamped >= 90
            ? "bg-rose-500"
            : clamped >= 75
              ? "bg-amber-500"
              : "bg-emerald-500",
        )}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

/** The route's read grant, resolved against the caller's permissions.
 *  ``allowed`` gates the fetch; ``withheld`` is the card's message once the
 *  permission set has loaded and the grant is missing. */
function useReportGrant(resourceType: string, what: string) {
  const { can, isLoading } = usePermissions();
  const allowed = can("read", resourceType);
  return {
    allowed,
    // Shown as "Loading…" so a not-yet-fetched card never reads as empty.
    pending: isLoading,
    withheld:
      !allowed && !isLoading
        ? `You don't have permission to see ${what} (needs read on ${resourceType}).`
        : undefined,
  };
}

// ── Top subnets by utilization ──────────────────────────────────────

function TopSubnetsCard() {
  const grant = useReportGrant("subnet", "subnet utilization");
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["reports", "top-subnets"],
    queryFn: reportsApi.topSubnetsByUtilization,
    enabled: grant.allowed,
  });
  const rows = data?.rows ?? [];
  return (
    <ReportCard
      title="Top subnets by utilization"
      subtitle="Most-allocated subnets, highest first"
      icon={BarChart3}
      generatedAt={data?.generated_at}
      isLoading={isLoading || grant.pending}
      isError={isError}
      isEmpty={rows.length === 0}
      emptyHint="No subnets yet."
      withheld={grant.withheld}
      onRefresh={() => void refetch()}
    >
      <ul className="divide-y">
        {rows.map((r, i) => (
          <li key={r.id} className="flex items-center gap-3 px-2 py-2">
            <span className={RANK_CLS}>{i + 1}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm font-medium">
                  {r.name || r.network}
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums">
                  {r.utilization_percent.toFixed(1)}%
                </span>
              </div>
              <div className="mt-1 flex items-center gap-2">
                <Bar pct={r.utilization_percent} />
              </div>
              <p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
                {r.network} · {r.allocated_ips.toLocaleString()} /{" "}
                {r.total_ips.toLocaleString()} IPs
              </p>
            </div>
          </li>
        ))}
      </ul>
    </ReportCard>
  );
}

// ── Top owners by IP count ──────────────────────────────────────────

function TopOwnersCard() {
  const grant = useReportGrant("customer", "owners by IP count");
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["reports", "top-owners"],
    queryFn: reportsApi.topOwnersByIpCount,
    enabled: grant.allowed,
  });
  const rows = data?.rows ?? [];
  const max = rows.reduce((m, r) => Math.max(m, r.ip_count), 0);
  return (
    <ReportCard
      title="Top owners by IP count"
      subtitle="Customers ranked by allocated addresses"
      icon={Users}
      generatedAt={data?.generated_at}
      isLoading={isLoading || grant.pending}
      isError={isError}
      isEmpty={rows.length === 0}
      emptyHint="No IP addresses allocated yet."
      withheld={grant.withheld}
      onRefresh={() => void refetch()}
    >
      <ul className="divide-y">
        {rows.map((r, i) => (
          <li
            key={r.customer_id ?? "unowned"}
            className="flex items-center gap-3 px-2 py-2"
          >
            <span className={RANK_CLS}>{i + 1}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span
                  className={cn(
                    "truncate text-sm font-medium",
                    r.customer_id === null && "italic text-muted-foreground",
                  )}
                >
                  {r.customer_name}
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums">
                  {r.ip_count.toLocaleString()}
                </span>
              </div>
              <div className="mt-1">
                <Bar pct={max > 0 ? (r.ip_count / max) * 100 : 0} />
              </div>
            </div>
          </li>
        ))}
      </ul>
    </ReportCard>
  );
}

// ── Top modified resources ──────────────────────────────────────────

function TopModifiedCard() {
  const grant = useReportGrant("audit_log", "the audit log");
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["reports", "top-modified"],
    queryFn: reportsApi.topModifiedResources,
    enabled: grant.allowed,
  });
  const rows = data?.rows ?? [];
  return (
    <ReportCard
      title="Most-modified resources"
      subtitle={`Mutations over the trailing ${data?.window_days ?? 7} days`}
      icon={ClipboardList}
      generatedAt={data?.generated_at}
      isLoading={isLoading || grant.pending}
      isError={isError}
      isEmpty={rows.length === 0}
      emptyHint="No mutations recorded in the window."
      withheld={grant.withheld}
      onRefresh={() => void refetch()}
    >
      <ul className="divide-y">
        {rows.map((r, i) => (
          <li
            key={`${r.resource_type}:${r.resource_id}`}
            className="flex items-center gap-3 px-2 py-2"
          >
            <span className={RANK_CLS}>{i + 1}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm font-medium">
                  {r.resource_display || r.resource_id}
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums">
                  {r.change_count.toLocaleString()}×
                </span>
              </div>
              <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                {r.resource_type}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </ReportCard>
  );
}

// ── Top DNS clients ─────────────────────────────────────────────────

function TopDNSClientsCard() {
  const grant = useReportGrant("server", "DNS query-log clients");
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["reports", "top-dns-clients"],
    queryFn: reportsApi.topDnsClients,
    enabled: grant.allowed,
  });
  const rows = data?.rows ?? [];
  const max = rows.reduce((m, r) => Math.max(m, r.query_count), 0);
  return (
    <ReportCard
      title="Noisiest DNS clients"
      subtitle="Query volume over the last 24 hours"
      icon={Globe}
      generatedAt={data?.generated_at}
      isLoading={isLoading || grant.pending}
      isError={isError}
      isEmpty={rows.length === 0}
      emptyHint="No DNS query logs shipped yet."
      withheld={grant.withheld}
      onRefresh={() => void refetch()}
    >
      <ul className="divide-y">
        {rows.map((r, i) => (
          <li key={r.client_ip} className="flex items-center gap-3 px-2 py-2">
            <span className={RANK_CLS}>{i + 1}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-sm">
                  {r.client_ip}
                </span>
                <span className="shrink-0 font-mono text-xs tabular-nums">
                  {r.query_count.toLocaleString()}
                </span>
              </div>
              <div className="mt-1">
                <Bar pct={max > 0 ? (r.query_count / max) * 100 : 0} />
              </div>
            </div>
          </li>
        ))}
      </ul>
    </ReportCard>
  );
}
