import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  BarChart3,
  CheckCircle2,
  Clock,
  Copy,
  Cpu,
  FileText,
  History,
  Loader2,
  Pause,
  Play,
  RefreshCw,
  ScrollText,
  Server,
  Workflow,
} from "lucide-react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Modal } from "@/components/ui/modal";
import { formatBucket } from "@/lib/chart-time";
import { PauseServerModal } from "@/components/ui/pause-server-modal";
import { ConfigApplyBanner } from "@/components/ConfigApplyChip";
import { SpoolChip } from "@/components/SpoolChip";
import {
  dnsApi,
  logsApi,
  metricsApi,
  type DNSPendingOpEntry,
  type DNSPerServerZoneStateEntry,
  type DNSQueryLogRow,
  type DNSRenderedConfigFile,
  type DNSServer,
  type DNSServerEventEntry,
  type MetricsWindow,
} from "@/lib/api";

/**
 * Tabbed read-only inspector for a single DNS server. Mounted from
 * the ServersTab when an operator clicks a server row. Surfaces
 * everything we know about the server without operators needing to
 * SSH in:
 *
 * - **Overview** — agent status, last heartbeat, ETag drift, plus the
 *   latest `rndc status` snapshot the agent pushed
 * - **Zones** — per-zone serial drift (target vs. what this server reports)
 * - **Sync** — pending / in-flight / failed `DNSRecordOp` rows
 * - **Events** — recent audit-log rows scoped to this server
 * - **Logs** — last N parsed BIND9 query log lines (24 h retention)
 * - **Stats** — query rate timeseries + top qnames + qtype distribution
 * - **Config** — the rendered `named.conf` + zone files actually on disk
 */
type Tab =
  | "overview"
  | "zones"
  | "sync"
  | "events"
  | "logs"
  | "stats"
  | "config";

const BIND9_DRIVER = "bind9";

export function ServerDetailModal({
  server,
  onClose,
}: {
  server: DNSServer;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>("overview");
  const [showPauseModal, setShowPauseModal] = useState(false);
  const qc = useQueryClient();
  const isBind9 = server.driver === BIND9_DRIVER;

  // Issue #182: pause/resume mutations. Invalidate the dns-servers
  // query on success so the Maintenance chip on the ServersTab row
  // refreshes alongside the modal.
  const pauseMut = useMutation({
    mutationFn: (reason: string) =>
      dnsApi.pauseServer(server.group_id, server.id, reason),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-servers"] });
      setShowPauseModal(false);
    },
  });
  const resumeMut = useMutation({
    mutationFn: () => dnsApi.resumeServer(server.group_id, server.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-servers"] }),
  });

  return (
    <Modal title={server.name} onClose={onClose} wide>
      <div className="flex flex-col gap-3">
        <div className="-mt-2 mb-1 flex items-center gap-2 text-xs text-muted-foreground">
          <Cpu className="h-3.5 w-3.5" />
          <span className="rounded border px-1.5 py-0.5 text-[10px]">
            {server.driver}
          </span>
          <span className="rounded border px-1.5 py-0.5 text-[10px] font-mono">
            {server.host}:{server.port}
          </span>
          {server.is_primary && (
            <span className="rounded bg-blue-500/15 px-1.5 py-0.5 text-[10px] font-medium text-blue-600">
              primary
            </span>
          )}
          {server.maintenance_mode && (
            <span
              className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400"
              title={
                server.maintenance_reason
                  ? `Paused: ${server.maintenance_reason}`
                  : "In operator-set maintenance mode"
              }
            >
              Maintenance · {fmtRelative(server.maintenance_started_at)}
            </span>
          )}
          <div className="ml-auto">
            {server.maintenance_mode ? (
              <button
                type="button"
                onClick={() => resumeMut.mutate()}
                disabled={resumeMut.isPending}
                className="inline-flex items-center gap-1 rounded border border-emerald-600/40 bg-emerald-500/10 px-2 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-50 dark:text-emerald-400"
              >
                <Play className="h-3 w-3" />
                {resumeMut.isPending ? "Resuming…" : "Resume"}
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setShowPauseModal(true)}
                className="inline-flex items-center gap-1 rounded border border-amber-600/40 bg-amber-500/10 px-2 py-1 text-[11px] font-medium text-amber-700 hover:bg-amber-500/20 dark:text-amber-400"
              >
                <Pause className="h-3 w-3" />
                Pause
              </button>
            )}
          </div>
        </div>
        {showPauseModal && (
          <PauseServerModal
            serverName={server.name}
            serverKind="DNS"
            isPending={pauseMut.isPending}
            onConfirm={(reason) => pauseMut.mutate(reason)}
            onCancel={() => setShowPauseModal(false)}
          />
        )}
        <div className="flex flex-wrap gap-1 border-b">
          <TabButton
            active={tab === "overview"}
            onClick={() => setTab("overview")}
            icon={<Server className="h-3.5 w-3.5" />}
            label="Overview"
          />
          <TabButton
            active={tab === "zones"}
            onClick={() => setTab("zones")}
            icon={<Workflow className="h-3.5 w-3.5" />}
            label="Zones"
          />
          <TabButton
            active={tab === "sync"}
            onClick={() => setTab("sync")}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
            label="Sync"
          />
          <TabButton
            active={tab === "events"}
            onClick={() => setTab("events")}
            icon={<History className="h-3.5 w-3.5" />}
            label="Events"
          />
          {isBind9 && (
            <>
              <TabButton
                active={tab === "logs"}
                onClick={() => setTab("logs")}
                icon={<ScrollText className="h-3.5 w-3.5" />}
                label="Logs"
              />
              <TabButton
                active={tab === "stats"}
                onClick={() => setTab("stats")}
                icon={<BarChart3 className="h-3.5 w-3.5" />}
                label="Stats"
              />
              <TabButton
                active={tab === "config"}
                onClick={() => setTab("config")}
                icon={<FileText className="h-3.5 w-3.5" />}
                label="Config"
              />
            </>
          )}
        </div>

        <div className="min-h-[24rem]">
          {tab === "overview" && (
            <OverviewTab server={server} isBind9={isBind9} />
          )}
          {tab === "zones" && <ZonesTab serverId={server.id} />}
          {tab === "sync" && <SyncTab serverId={server.id} />}
          {tab === "events" && <EventsTab serverId={server.id} />}
          {tab === "logs" && isBind9 && <LogsTab serverId={server.id} />}
          {tab === "stats" && isBind9 && <StatsTab serverId={server.id} />}
          {tab === "config" && isBind9 && <ConfigTab serverId={server.id} />}
        </div>
      </div>
    </Modal>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        "flex items-center gap-1.5 border-b-2 px-3 py-2 text-xs font-medium transition-colors " +
        (active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground")
      }
    >
      {icon}
      {label}
    </button>
  );
}

// ── Overview tab ──────────────────────────────────────────────────────────

function OverviewTab({
  server,
  isBind9,
}: {
  server: DNSServer;
  isBind9: boolean;
}) {
  return (
    <div className="space-y-4">
      {/* #882 — above the status grid on purpose: every field below reports
          healthy while the agent is running a config the operator never
          approved, so this has to be the first thing read. */}
      <ConfigApplyBanner server={server} />
      <div className="flex flex-wrap gap-1.5 empty:hidden">
        <SpoolChip server={server} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <OverviewInfo server={server} />
      </div>
      {isBind9 && <RndcStatusPanel serverId={server.id} />}
    </div>
  );
}

function OverviewInfo({ server }: { server: DNSServer }) {
  return (
    <>
      <InfoCard label="Status" value={server.status}>
        <StatusDot status={server.status} />
        <span className="ml-2 text-sm font-medium capitalize">
          {server.status}
        </span>
      </InfoCard>
      <InfoCard
        label="Roles"
        value={server.roles.length === 0 ? "—" : server.roles.join(", ")}
      />
      <InfoCard label="Agent ID" value={server.agent_id ?? "—"} mono />
      <InfoCard
        label="Pending approval"
        value={server.pending_approval ? "yes" : "no"}
        accent={server.pending_approval ? "warning" : undefined}
      />
      <InfoCard
        label="Last heartbeat"
        value={fmtRelative(server.last_seen_at)}
      />
      <InfoCard
        label="Last health check"
        value={fmtRelative(server.last_health_check_at)}
      />
      <InfoCard label="Last sync" value={fmtRelative(server.last_sync_at)} />
      <InfoCard
        label="Config ETag (last acked)"
        value={server.last_config_etag ?? "—"}
        mono
      />
      <InfoCard
        label="Enabled"
        value={server.is_enabled ? "yes" : "no (paused)"}
        accent={server.is_enabled ? undefined : "warning"}
      />
      <InfoCard label="Primary" value={server.is_primary ? "yes" : "no"} />
      {server.notes && (
        <div className="col-span-2 rounded-md border bg-muted/30 p-3 text-xs">
          <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            Notes
          </div>
          <div className="whitespace-pre-wrap">{server.notes}</div>
        </div>
      )}
    </>
  );
}

function RndcStatusPanel({ serverId }: { serverId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["dns-server-rndc-status", serverId],
    queryFn: () => dnsApi.getServerRndcStatus(serverId),
    refetchInterval: 60_000,
  });

  return (
    <div className="rounded-md border bg-card">
      <div className="flex items-center justify-between border-b px-3 py-2">
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-emerald-500" />
          <h4 className="text-xs font-semibold uppercase tracking-wider">
            rndc status
          </h4>
        </div>
        <span className="text-[10px] text-muted-foreground">
          {data?.observed_at
            ? `pushed ${fmtRelative(data.observed_at)}`
            : "no snapshot yet"}
        </span>
      </div>
      <div className="p-3">
        {isLoading ? (
          <LoadingBlock />
        ) : !data?.text ? (
          <p className="rounded-md bg-muted/30 p-3 text-center text-xs text-muted-foreground">
            The agent pushes <code className="font-mono">rndc status</code>{" "}
            every 60&nbsp;s. Once it lands you'll see the daemon uptime, zone
            count, and recursion stats here.
          </p>
        ) : (
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-md bg-muted/30 p-3 font-mono text-[11px] leading-snug">
            {data.text}
          </pre>
        )}
      </div>
    </div>
  );
}

function InfoCard({
  label,
  value,
  mono,
  accent,
  children,
}: {
  label: string;
  value: string;
  mono?: boolean;
  accent?: "warning" | "good" | "bad";
  children?: React.ReactNode;
}) {
  const accentCls =
    accent === "warning"
      ? "text-amber-600 dark:text-amber-400"
      : accent === "good"
        ? "text-emerald-600 dark:text-emerald-400"
        : accent === "bad"
          ? "text-destructive"
          : "";
  return (
    <div className="rounded-md border bg-card p-3">
      <div className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      {children ?? (
        <div
          className={
            "truncate text-sm " + (mono ? "font-mono text-xs " : "") + accentCls
          }
          title={value}
        >
          {value}
        </div>
      )}
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const cls =
    {
      active: "bg-emerald-500",
      unreachable: "bg-red-500",
      syncing: "bg-blue-500",
      error: "bg-red-500",
      disabled: "bg-muted-foreground/40",
    }[status] ?? "bg-muted";
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full ${cls}`}
      title={status}
    />
  );
}

// ── Zones tab ─────────────────────────────────────────────────────────────

function ZonesTab({ serverId }: { serverId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dns-server-zone-state", serverId],
    queryFn: () => dnsApi.getServerZoneState(serverId),
    refetchInterval: 30_000,
  });

  if (isLoading) return <LoadingBlock />;
  if (isError || !data) return <ErrorBlock />;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-4 gap-2 text-xs">
        <Stat label="Zones" value={data.summary.total} />
        <Stat
          label="In sync"
          value={data.summary.in_sync}
          accent={data.summary.in_sync > 0 ? "good" : undefined}
        />
        <Stat
          label="Drift"
          value={data.summary.drift}
          accent={data.summary.drift > 0 ? "bad" : undefined}
        />
        <Stat
          label="Not reported"
          value={data.summary.not_reported}
          accent={data.summary.not_reported > 0 ? "warning" : undefined}
        />
      </div>
      {data.zones.length === 0 ? (
        <p className="rounded-md border bg-card p-4 text-center text-sm text-muted-foreground">
          No zones in this server's group.
        </p>
      ) : (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-xs">
              <tr>
                <th className="px-3 py-2 text-left font-medium">Zone</th>
                <th className="px-3 py-2 text-left font-medium">Type</th>
                <th className="px-3 py-2 text-right font-medium">Target</th>
                <th className="px-3 py-2 text-right font-medium">Current</th>
                <th className="px-3 py-2 text-right font-medium">Reported</th>
                <th className="px-3 py-2 text-center font-medium">Sync</th>
              </tr>
            </thead>
            <tbody>
              {data.zones.map((z) => (
                <ZoneRow key={z.zone_id} z={z} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ZoneRow({ z }: { z: DNSPerServerZoneStateEntry }) {
  const indicator =
    z.current_serial === null ? (
      <Clock className="h-3.5 w-3.5 text-amber-500" />
    ) : z.in_sync ? (
      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
    ) : (
      <AlertCircle className="h-3.5 w-3.5 text-red-500" />
    );
  return (
    <tr className="border-b last:border-0">
      <td className="px-3 py-1.5 font-medium">{z.zone_name}</td>
      <td className="px-3 py-1.5 text-muted-foreground">{z.zone_type}</td>
      <td className="px-3 py-1.5 text-right font-mono text-xs">
        {z.target_serial}
      </td>
      <td className="px-3 py-1.5 text-right font-mono text-xs">
        {z.current_serial ?? "—"}
      </td>
      <td className="px-3 py-1.5 text-right text-xs text-muted-foreground">
        {fmtRelative(z.reported_at)}
      </td>
      <td className="px-3 py-1.5">
        <div className="flex items-center justify-center">{indicator}</div>
      </td>
    </tr>
  );
}

// ── Sync tab ──────────────────────────────────────────────────────────────

function SyncTab({ serverId }: { serverId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dns-server-pending-ops", serverId],
    queryFn: () => dnsApi.getServerPendingOps(serverId),
    refetchInterval: 15_000,
  });

  if (isLoading) return <LoadingBlock />;
  if (isError || !data) return <ErrorBlock />;

  const states: Array<[string, "warning" | "good" | "bad" | undefined]> = [
    ["pending", "warning"],
    ["in_flight", "warning"],
    ["applied", "good"],
    ["failed", "bad"],
  ];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-4 gap-2 text-xs">
        {states.map(([state, accent]) => (
          <Stat
            key={state}
            label={state.replace("_", " ")}
            value={data.counts[state] ?? 0}
            accent={(data.counts[state] ?? 0) > 0 ? accent : undefined}
          />
        ))}
      </div>
      {data.items.length === 0 ? (
        <p className="rounded-md border bg-card p-4 text-center text-sm text-muted-foreground">
          No record ops queued for this server.
        </p>
      ) : (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-xs">
              <tr>
                <th className="px-3 py-2 text-left font-medium">When</th>
                <th className="px-3 py-2 text-left font-medium">Zone</th>
                <th className="px-3 py-2 text-left font-medium">Op</th>
                <th className="px-3 py-2 text-left font-medium">Record</th>
                <th className="px-3 py-2 text-left font-medium">State</th>
                <th className="px-3 py-2 text-right font-medium">Tries</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((op) => (
                <OpRow key={op.op_id} op={op} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function OpRow({ op }: { op: DNSPendingOpEntry }) {
  const stateCls: Record<string, string> = {
    pending: "bg-amber-500/15 text-amber-600",
    in_flight: "bg-blue-500/15 text-blue-600",
    applied: "bg-emerald-500/15 text-emerald-600",
    failed: "bg-red-500/15 text-red-600",
  };
  const r = op.record as { name?: string; type?: string; value?: string };
  const recordSummary = r.name
    ? `${r.name} ${r.type ?? ""} ${r.value ?? ""}`.trim()
    : JSON.stringify(op.record);
  return (
    <tr className="border-b last:border-0" title={op.last_error ?? undefined}>
      <td className="px-3 py-1.5 text-xs text-muted-foreground">
        {fmtRelative(op.created_at)}
      </td>
      <td className="px-3 py-1.5 font-medium">{op.zone_name}</td>
      <td className="px-3 py-1.5 text-xs uppercase">{op.op}</td>
      <td className="px-3 py-1.5 truncate font-mono text-xs">
        {recordSummary}
      </td>
      <td className="px-3 py-1.5">
        <span
          className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${
            stateCls[op.state] ?? "bg-muted text-muted-foreground"
          }`}
        >
          {op.state.replace("_", " ")}
        </span>
      </td>
      <td className="px-3 py-1.5 text-right text-xs tabular-nums">
        {op.attempts}
      </td>
    </tr>
  );
}

// ── Events tab ────────────────────────────────────────────────────────────

function EventsTab({ serverId }: { serverId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dns-server-recent-events", serverId],
    queryFn: () => dnsApi.getServerRecentEvents(serverId),
    refetchInterval: 60_000,
  });

  if (isLoading) return <LoadingBlock />;
  if (isError || !data) return <ErrorBlock />;

  if (data.items.length === 0) {
    return (
      <p className="rounded-md border bg-card p-4 text-center text-sm text-muted-foreground">
        No audit events recorded for this server.
      </p>
    );
  }

  return (
    <div className="overflow-hidden rounded-md border">
      <table className="w-full text-sm">
        <thead className="border-b bg-muted/30 text-xs">
          <tr>
            <th className="px-3 py-2 text-left font-medium">When</th>
            <th className="px-3 py-2 text-left font-medium">Action</th>
            <th className="px-3 py-2 text-left font-medium">User</th>
            <th className="px-3 py-2 text-left font-medium">Detail</th>
            <th className="px-3 py-2 text-left font-medium">Result</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((e) => (
            <EventRow key={e.id} event={e} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EventRow({ event }: { event: DNSServerEventEntry }) {
  const resultCls =
    event.result === "success"
      ? "bg-emerald-500/15 text-emerald-600"
      : "bg-red-500/15 text-red-600";
  return (
    <tr className="border-b last:border-0">
      <td
        className="px-3 py-1.5 text-xs text-muted-foreground"
        title={new Date(event.timestamp).toLocaleString()}
      >
        {fmtRelative(event.timestamp)}
      </td>
      <td className="px-3 py-1.5 text-xs uppercase">{event.action}</td>
      <td className="px-3 py-1.5 text-xs">{event.user_display_name}</td>
      <td className="px-3 py-1.5 truncate text-xs text-muted-foreground">
        {event.resource_display}
      </td>
      <td className="px-3 py-1.5">
        <span
          className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${resultCls}`}
        >
          {event.result}
        </span>
      </td>
    </tr>
  );
}

// ── Logs tab ──────────────────────────────────────────────────────────────

function LogsTab({ serverId }: { serverId: string }) {
  const [q, setQ] = useState("");
  const [qtype, setQtype] = useState("");
  const [clientIp, setClientIp] = useState("");
  const filterKey = `${q}|${qtype}|${clientIp}`;

  // Drop empty fields rather than sending "" — the backend ILIKEs the
  // empty string against every row, which is technically correct but
  // wastes a query.
  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["dns-server-query-log", serverId, filterKey],
    queryFn: () =>
      logsApi.dnsQueries({
        server_id: serverId,
        q: q || null,
        qtype: qtype || null,
        client_ip: clientIp || null,
        max_events: 200,
      }),
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 rounded-md border bg-card px-3 py-2">
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter qname / raw…"
          className="flex-1 min-w-[10rem] rounded border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        />
        <input
          type="text"
          value={qtype}
          onChange={(e) => setQtype(e.target.value.toUpperCase())}
          placeholder="qtype"
          className="w-20 rounded border bg-background px-2 py-1 text-xs uppercase focus:outline-none focus:ring-1 focus:ring-ring"
        />
        <input
          type="text"
          value={clientIp}
          onChange={(e) => setClientIp(e.target.value)}
          placeholder="client IP"
          className="w-32 rounded border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        />
        <button
          type="button"
          onClick={() => refetch()}
          className="inline-flex items-center gap-1 rounded border px-2 py-1 text-xs hover:bg-accent"
          disabled={isFetching}
        >
          <RefreshCw
            className={`h-3 w-3 ${isFetching ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {isLoading ? (
        <LoadingBlock />
      ) : isError ? (
        <ErrorBlock />
      ) : !data || data.events.length === 0 ? (
        <p className="rounded-md border bg-card p-4 text-center text-sm text-muted-foreground">
          No query log entries match — agents tail{" "}
          <code className="font-mono">/var/log/named/queries.log</code> and ship
          parsed lines on a 24&nbsp;h retention window.
        </p>
      ) : (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-xs">
              <tr>
                <th className="px-3 py-2 text-left font-medium">When</th>
                <th className="px-3 py-2 text-left font-medium">Client</th>
                <th className="px-3 py-2 text-left font-medium">Qname</th>
                <th className="px-3 py-2 text-left font-medium">Type</th>
                <th className="px-3 py-2 text-left font-medium">Flags</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((e) => (
                <QueryLogRow key={e.id} entry={e} />
              ))}
            </tbody>
          </table>
          {data.truncated && (
            <div className="border-t bg-muted/30 px-3 py-1.5 text-[11px] text-muted-foreground">
              Truncated — showing the most recent 200 entries.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function QueryLogRow({ entry }: { entry: DNSQueryLogRow }) {
  return (
    <tr className="border-b last:border-0" title={entry.raw}>
      <td
        className="px-3 py-1 text-xs text-muted-foreground"
        title={new Date(entry.ts).toLocaleString()}
      >
        {fmtRelative(entry.ts)}
      </td>
      <td className="px-3 py-1 font-mono text-xs">
        {entry.client_ip ?? "—"}
        {entry.client_port ? `:${entry.client_port}` : ""}
      </td>
      <td className="px-3 py-1 truncate font-mono text-xs">
        {entry.qname ?? "—"}
      </td>
      <td className="px-3 py-1 text-xs uppercase">{entry.qtype ?? "—"}</td>
      <td className="px-3 py-1 font-mono text-[11px] text-muted-foreground">
        {entry.flags ?? ""}
      </td>
    </tr>
  );
}

// ── Stats tab ─────────────────────────────────────────────────────────────

function StatsTab({ serverId }: { serverId: string }) {
  const [win, setWin] = useState<MetricsWindow>("24h");

  const ts = useQuery({
    queryKey: ["dns-server-metrics-ts", serverId, win],
    queryFn: () =>
      metricsApi.dnsTimeseries({ server_id: serverId, window: win }),
    refetchInterval: 60_000,
  });

  const analytics = useQuery({
    queryKey: ["dns-server-query-analytics", serverId],
    queryFn: () =>
      logsApi.dnsQueryAnalytics({ server_id: serverId, limit: 10 }),
    refetchInterval: 60_000,
  });

  // Convert per-bucket counters to per-second rates so the chart axis
  // is stable across windows (60 s buckets at 1h/6h, 300 s at 7d).
  const points = useMemo(() => {
    if (!ts.data) return [];
    const bs = ts.data.bucket_seconds || 60;
    return ts.data.points.map((p) => ({
      t: formatBucket(p.t, bs >= 3600),
      qps: round2(p.queries_total / bs),
      noerror: round2(p.noerror / bs),
      nxdomain: round2(p.nxdomain / bs),
      servfail: round2(p.servfail / bs),
      rrl_dropped: round2(p.rate_dropped / bs),
      rrl_slipped: round2(p.rate_slipped / bs),
    }));
  }, [ts.data]);

  // Only surface the RRL lines once the server has actually dropped/slipped
  // something — keeps the chart clean on the (common) non-RRL case.
  const hasRrl = useMemo(
    () => points.some((p) => p.rrl_dropped > 0 || p.rrl_slipped > 0),
    [points],
  );

  return (
    <div className="space-y-3">
      <div className="rounded-md border bg-card">
        <div className="flex items-center justify-between border-b px-3 py-2">
          <div className="flex items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-blue-500" />
            <h4 className="text-xs font-semibold uppercase tracking-wider">
              Query rate
            </h4>
          </div>
          <select
            value={win}
            onChange={(e) => setWin(e.target.value as MetricsWindow)}
            className="rounded border bg-background px-2 py-0.5 text-[11px] focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value="1h">1h</option>
            <option value="6h">6h</option>
            <option value="24h">24h</option>
            <option value="7d">7d</option>
          </select>
        </div>
        <div className="h-56 p-3">
          {ts.isLoading ? (
            <LoadingBlock />
          ) : points.length === 0 ? (
            <p className="flex h-full flex-col items-center justify-center gap-1 text-center text-xs text-muted-foreground">
              <span>No query data yet.</span>
              <span className="text-[11px]">
                BIND9 agents poll statistics-channels every 60&nbsp;s.
              </span>
            </p>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={points}
                margin={{ top: 5, right: 12, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={32} />
                <YAxis tick={{ fontSize: 10 }} width={42} />
                <Tooltip
                  contentStyle={{ fontSize: 11, borderRadius: 6 }}
                  labelStyle={{ fontWeight: 600 }}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line
                  type="monotone"
                  dataKey="qps"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  dot={false}
                  name="Total qps"
                />
                <Line
                  type="monotone"
                  dataKey="noerror"
                  stroke="#10b981"
                  strokeWidth={1.5}
                  dot={false}
                  name="NOERROR"
                />
                <Line
                  type="monotone"
                  dataKey="nxdomain"
                  stroke="#f59e0b"
                  strokeWidth={1.5}
                  dot={false}
                  name="NXDOMAIN"
                />
                <Line
                  type="monotone"
                  dataKey="servfail"
                  stroke="#ef4444"
                  strokeWidth={1.5}
                  dot={false}
                  name="SERVFAIL"
                />
                {hasRrl && (
                  <Line
                    type="monotone"
                    dataKey="rrl_dropped"
                    stroke="#a855f7"
                    strokeWidth={2}
                    dot={false}
                    name="RRL drops/s"
                  />
                )}
                {hasRrl && (
                  <Line
                    type="monotone"
                    dataKey="rrl_slipped"
                    stroke="#c084fc"
                    strokeWidth={1.5}
                    strokeDasharray="4 2"
                    dot={false}
                    name="RRL slipped/s"
                  />
                )}
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <AnalyticsCard
          title="Top qnames"
          rows={analytics.data?.top_qnames ?? []}
          isLoading={analytics.isLoading}
        />
        <AnalyticsCard
          title="Top clients"
          rows={analytics.data?.top_clients ?? []}
          isLoading={analytics.isLoading}
        />
        <AnalyticsCard
          title="qtype distribution"
          rows={analytics.data?.qtype_distribution ?? []}
          isLoading={analytics.isLoading}
          spanFull
        />
      </div>
      {analytics.data && (
        <p className="text-[11px] text-muted-foreground">
          Top-N rollups computed against the parsed BIND9 query log (24&nbsp;h
          retention) — {analytics.data.total_queries.toLocaleString()} queries
          in window.
        </p>
      )}
    </div>
  );
}

function AnalyticsCard({
  title,
  rows,
  isLoading,
  spanFull,
}: {
  title: string;
  rows: { key: string; count: number }[];
  isLoading: boolean;
  spanFull?: boolean;
}) {
  const max = rows[0]?.count ?? 0;
  return (
    <div
      className={`rounded-md border bg-card ${spanFull ? "md:col-span-2" : ""}`}
    >
      <div className="border-b px-3 py-2">
        <h4 className="text-xs font-semibold uppercase tracking-wider">
          {title}
        </h4>
      </div>
      <div className="p-2">
        {isLoading ? (
          <LoadingBlock />
        ) : rows.length === 0 ? (
          <p className="px-2 py-3 text-center text-xs text-muted-foreground">
            No data in window.
          </p>
        ) : (
          <ul className="space-y-1">
            {rows.map((r) => {
              const pct = max > 0 ? (r.count / max) * 100 : 0;
              return (
                <li key={r.key} className="flex items-center gap-2 px-1">
                  <span
                    className="flex-1 truncate font-mono text-xs"
                    title={r.key}
                  >
                    {r.key}
                  </span>
                  <div className="relative h-3 w-32 overflow-hidden rounded bg-muted/40">
                    <div
                      className="absolute inset-y-0 left-0 bg-blue-500/40"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="w-16 text-right text-xs tabular-nums text-muted-foreground">
                    {r.count.toLocaleString()}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── Config tab ────────────────────────────────────────────────────────────

function ConfigTab({ serverId }: { serverId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dns-server-rendered-config", serverId],
    queryFn: () => dnsApi.getServerRenderedConfig(serverId),
    refetchInterval: 60_000,
  });
  const [selected, setSelected] = useState<string | null>(null);

  if (isLoading) return <LoadingBlock />;
  if (isError || !data) return <ErrorBlock />;

  if (data.files.length === 0) {
    return (
      <p className="rounded-md border bg-card p-4 text-center text-sm text-muted-foreground">
        No rendered-config snapshot yet. The agent ships its{" "}
        <code className="font-mono">named.conf</code> + zone files after every
        successful structural reload — trigger one (record edit, zone create,
        etc.) or wait for the next bundle to land.
      </p>
    );
  }

  // Default to named.conf when the operator first opens the tab —
  // it's what they're most likely after.
  const activePath =
    selected ??
    data.files.find((f) => f.path === "named.conf")?.path ??
    data.files[0].path;
  const active = data.files.find((f) => f.path === activePath) ?? data.files[0];

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-[14rem_1fr]">
      <div className="rounded-md border bg-card">
        <div className="border-b px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Files
        </div>
        <ul className="max-h-[28rem] overflow-y-auto p-1 text-xs">
          {data.files.map((f) => (
            <li key={f.path}>
              <button
                type="button"
                onClick={() => setSelected(f.path)}
                className={`flex w-full items-center justify-between gap-2 truncate rounded px-2 py-1.5 text-left font-mono text-[11px] transition-colors ${
                  f.path === active.path
                    ? "bg-accent/60 font-semibold"
                    : "hover:bg-accent/30"
                }`}
                title={f.path}
              >
                <span className="truncate">{f.path}</span>
                <span className="flex-shrink-0 text-[10px] text-muted-foreground">
                  {fmtBytes(f.content.length)}
                </span>
              </button>
            </li>
          ))}
        </ul>
        {data.rendered_at && (
          <div className="border-t px-3 py-1.5 text-[10px] text-muted-foreground">
            Pushed {fmtRelative(data.rendered_at)}
          </div>
        )}
      </div>
      <FileViewer file={active} />
    </div>
  );
}

function FileViewer({ file }: { file: DNSRenderedConfigFile }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border bg-card">
      <div className="flex items-center justify-between border-b px-3 py-2">
        <span className="font-mono text-xs">{file.path}</span>
        <button
          type="button"
          onClick={() => {
            navigator.clipboard.writeText(file.content).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            });
          }}
          className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent"
        >
          <Copy className="h-3 w-3" />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-[11px] leading-snug">
        {file.content}
      </pre>
    </div>
  );
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1024 / 1024).toFixed(1)}MB`;
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

// ── Shared bits ───────────────────────────────────────────────────────────

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: "good" | "bad" | "warning";
}) {
  const accentCls =
    accent === "good"
      ? "text-emerald-600 dark:text-emerald-400"
      : accent === "bad"
        ? "text-destructive"
        : accent === "warning"
          ? "text-amber-600 dark:text-amber-400"
          : "text-foreground";
  return (
    <div className="rounded-md border bg-card px-2.5 py-1.5">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className={`text-lg font-semibold tabular-nums ${accentCls}`}>
        {value}
      </div>
    </div>
  );
}

function LoadingBlock() {
  return (
    <div className="flex items-center justify-center gap-2 rounded-md border bg-card py-8 text-sm text-muted-foreground">
      <Loader2 className="h-4 w-4 animate-spin" />
      Loading…
    </div>
  );
}

function ErrorBlock() {
  return (
    <div className="flex items-center justify-center gap-2 rounded-md border border-destructive/40 bg-destructive/5 py-8 text-sm text-destructive">
      <Activity className="h-4 w-4" />
      Failed to load — try again
    </div>
  );
}

function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const diff = Date.now() - t;
  const sec = Math.floor(diff / 1000);
  if (sec < 0) return "in the future";
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const days = Math.floor(hr / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}
