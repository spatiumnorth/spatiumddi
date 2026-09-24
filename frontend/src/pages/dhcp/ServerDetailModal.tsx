import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BarChart3,
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
} from "lucide-react";
import { bucketLoss, summariseLoss } from "@/lib/dhcp-loss";
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Modal } from "@/components/ui/modal";
import { PauseServerModal } from "@/components/ui/pause-server-modal";
import { formatBucket } from "@/lib/chart-time";
import { ConfigApplyBanner } from "@/components/ConfigApplyChip";
import { DaemonStateBanner } from "@/components/DaemonStateChip";
import { SpoolChip } from "@/components/SpoolChip";
import {
  dhcpApi,
  logsApi,
  type DHCPActivityLogRow,
  type DHCPPendingOpEntry,
  type DHCPServer,
  type DHCPServerEventEntry,
  type DHCPStatsRange,
} from "@/lib/api";

/**
 * Tabbed read-only inspector for a single DHCP server. Mounted from the
 * GroupServersList when an operator clicks a server row — mirrors the
 * DNS ServerDetailModal pattern (issue #181) so DHCP operators get the
 * same overview / sync / events / logs / config experience without
 * leaving the group view.
 *
 * Tabs:
 *
 * - **Overview** — driver / host:port / agent status / heartbeat / HA
 * - **Sync** — pending / in-flight / applied / failed DHCPConfigOp rows
 * - **Events** — audit-log rows scoped to this server
 * - **Logs** — Kea activity log entries (filtered by severity / IP / MAC)
 * - **Config** — rendered Kea JSON the agent would apply next reload
 *
 * Read-only Windows DHCP servers hide the Logs + Config tabs (the
 * driver doesn't push a Kea log pipeline and has no rendered config).
 */
type Tab = "overview" | "sync" | "events" | "logs" | "config" | "stats";

const READ_ONLY_DRIVERS = new Set(["windows_dhcp"]);

export function ServerDetailModal({
  server,
  onClose,
}: {
  server: DHCPServer;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>("overview");
  const [showPauseModal, setShowPauseModal] = useState(false);
  const qc = useQueryClient();
  const isReadOnly = READ_ONLY_DRIVERS.has(server.driver);

  // Issue #182: pause/resume mutations. Invalidate the server-list
  // query on success so the Maintenance chip on the group's Servers
  // table refreshes alongside the modal.
  const pauseMut = useMutation({
    mutationFn: (reason: string) => dhcpApi.pauseServer(server.id, reason),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-servers"] });
      setShowPauseModal(false);
    },
  });
  const resumeMut = useMutation({
    mutationFn: () => dhcpApi.resumeServer(server.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-servers"] }),
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
          {server.ha_state && (
            <span className="rounded bg-blue-500/15 px-1.5 py-0.5 text-[10px] font-medium text-blue-600">
              HA: {server.ha_state}
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
            serverKind="DHCP"
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
          {!isReadOnly && (
            <>
              <TabButton
                active={tab === "logs"}
                onClick={() => setTab("logs")}
                icon={<ScrollText className="h-3.5 w-3.5" />}
                label="Logs"
              />
              <TabButton
                active={tab === "config"}
                onClick={() => setTab("config")}
                icon={<FileText className="h-3.5 w-3.5" />}
                label="Config"
              />
              <TabButton
                active={tab === "stats"}
                onClick={() => setTab("stats")}
                icon={<BarChart3 className="h-3.5 w-3.5" />}
                label="Stats"
              />
            </>
          )}
        </div>

        <div className="min-h-[24rem]">
          {tab === "overview" && <OverviewTab server={server} />}
          {tab === "sync" && <SyncTab serverId={server.id} />}
          {tab === "events" && <EventsTab serverId={server.id} />}
          {tab === "logs" && !isReadOnly && <LogsTab serverId={server.id} />}
          {tab === "config" && !isReadOnly && (
            <ConfigTab serverId={server.id} />
          )}
          {/* #195 — DHCP lease-rate timeseries (DISCOVER/OFFER/REQUEST/ACK/
              NAK/…), scoped to this server. Stacked-area chart over the new
              GET /dhcp/servers/{id}/stats endpoint — symmetric with how the
              DNS modal's Stats tab renders its timeseries. Gated on
              !isReadOnly like Logs/Config (Windows DHCP has no Kea metric
              stream). */}
          {tab === "stats" && !isReadOnly && <StatsTab serverId={server.id} />}
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

function OverviewTab({ server }: { server: DHCPServer }) {
  // Kea agents send heartbeats; their ``agent_last_seen`` is the right
  // liveness signal. Windows DHCP is polled, so ``last_sync_at`` is
  // meaningful. Fall back to whichever exists.
  const seenAt =
    server.driver === "kea"
      ? (server.agent_last_seen ?? server.last_sync_at)
      : (server.last_sync_at ?? server.agent_last_seen);
  return (
    <div className="space-y-4">
      {/* #882 — above the status grid on purpose: every field below reports
          healthy while the agent is running a config the operator never
          approved, so this has to be the first thing read. */}
      <ConfigApplyBanner server={server} />
      <DaemonStateBanner server={server} />
      <div className="flex flex-wrap gap-1.5 empty:hidden">
        <SpoolChip server={server} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <InfoCard label="Status" value={server.status}>
          <StatusDot status={server.status} />
          <span className="ml-2 text-sm font-medium capitalize">
            {server.status}
          </span>
        </InfoCard>
        <InfoCard label="Last heartbeat" value={fmtRelative(seenAt)} />
        <InfoCard label="Last sync" value={fmtRelative(server.last_sync_at)} />
        <InfoCard
          label="Last seen IP"
          value={server.last_seen_ip ?? "—"}
          mono
        />
        <InfoCard
          label="Agent approved"
          value={
            server.is_agentless
              ? "n/a (agentless)"
              : server.agent_approved
                ? "yes"
                : "no (pending)"
          }
          accent={
            !server.is_agentless && !server.agent_approved
              ? "warning"
              : undefined
          }
        />
        <InfoCard
          label="HA state"
          value={server.ha_state ?? "—"}
          accent={
            server.ha_state === "partner-down" ||
            server.ha_state === "terminated"
              ? "bad"
              : server.ha_state === "normal" ||
                  server.ha_state === "load-balancing" ||
                  server.ha_state === "hot-standby" ||
                  server.ha_state === "ready"
                ? "good"
                : server.ha_state
                  ? "warning"
                  : undefined
          }
        />
        <InfoCard
          label="Config ETag (last acked)"
          value={server.config_etag ?? "—"}
          mono
        />
        <InfoCard
          label="Mode"
          value={
            server.is_read_only
              ? "read-only"
              : server.is_agentless
                ? "agentless"
                : "agent"
          }
        />
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
      ok: "bg-emerald-500",
      online: "bg-emerald-500",
      unreachable: "bg-red-500",
      offline: "bg-red-500",
      syncing: "bg-blue-500",
      error: "bg-red-500",
      disabled: "bg-muted-foreground/40",
      unknown: "bg-muted-foreground/40",
    }[status] ?? "bg-muted";
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full ${cls}`}
      title={status}
    />
  );
}

// ── Sync tab ──────────────────────────────────────────────────────────────

function SyncTab({ serverId }: { serverId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dhcp-server-pending-ops", serverId],
    queryFn: () => dhcpApi.getServerPendingOps(serverId),
    refetchInterval: 15_000,
  });

  if (isLoading) return <LoadingBlock />;
  if (isError || !data) return <ErrorBlock />;

  // Kea ops use ``status`` for state ("pending" / "in_flight" /
  // "applied" / "failed") — same vocabulary as DNS so the counts grid
  // is symmetric across the two server types.
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
          No config ops queued for this server.
        </p>
      ) : (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-xs">
              <tr>
                <th className="px-3 py-2 text-left font-medium">When</th>
                <th className="px-3 py-2 text-left font-medium">Op</th>
                <th className="px-3 py-2 text-left font-medium">Status</th>
                <th className="px-3 py-2 text-right font-medium">Tries</th>
                <th className="px-3 py-2 text-left font-medium">Acked</th>
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

function OpRow({ op }: { op: DHCPPendingOpEntry }) {
  const stateCls: Record<string, string> = {
    pending: "bg-amber-500/15 text-amber-600",
    in_flight: "bg-blue-500/15 text-blue-600",
    applied: "bg-emerald-500/15 text-emerald-600",
    failed: "bg-red-500/15 text-red-600",
  };
  return (
    <tr className="border-b last:border-0" title={op.error_msg ?? undefined}>
      <td className="px-3 py-1.5 text-xs text-muted-foreground">
        {fmtRelative(op.created_at)}
      </td>
      <td className="px-3 py-1.5 text-xs font-mono">{op.op_type}</td>
      <td className="px-3 py-1.5">
        <span
          className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${
            stateCls[op.status] ?? "bg-muted text-muted-foreground"
          }`}
        >
          {op.status}
        </span>
      </td>
      <td className="px-3 py-1.5 text-right text-xs tabular-nums">
        {op.attempts}
      </td>
      <td className="px-3 py-1.5 text-xs text-muted-foreground">
        {fmtRelative(op.acked_at)}
      </td>
    </tr>
  );
}

// ── Events tab ────────────────────────────────────────────────────────────

function EventsTab({ serverId }: { serverId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dhcp-server-recent-events", serverId],
    queryFn: () => dhcpApi.getServerRecentEvents(serverId),
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

function EventRow({ event }: { event: DHCPServerEventEntry }) {
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
  const [severity, setSeverity] = useState("");
  const [mac, setMac] = useState("");
  const [ip, setIp] = useState("");
  const filterKey = `${q}|${severity}|${mac}|${ip}`;

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["dhcp-server-activity", serverId, filterKey],
    queryFn: () =>
      logsApi.dhcpActivity({
        server_id: serverId,
        q: q || null,
        severity: severity || null,
        mac_address: mac || null,
        ip_address: ip || null,
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
          placeholder="Filter raw / code…"
          className="flex-1 min-w-[10rem] rounded border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        >
          <option value="">any sev</option>
          <option value="DEBUG">DEBUG</option>
          <option value="INFO">INFO</option>
          <option value="WARN">WARN</option>
          <option value="ERROR">ERROR</option>
        </select>
        <input
          type="text"
          value={mac}
          onChange={(e) => setMac(e.target.value)}
          placeholder="MAC"
          className="w-32 rounded border bg-background px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-ring"
        />
        <input
          type="text"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="IP"
          className="w-32 rounded border bg-background px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-ring"
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
          No activity log entries match — Kea agents ship file-output{" "}
          <code className="font-mono">/var/log/kea/kea-dhcp4.log</code> lines on
          a rolling window.
          {data?.truncated && " (older entries were truncated)"}
        </p>
      ) : (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-xs">
              <tr>
                <th className="px-3 py-2 text-left font-medium">When</th>
                <th className="px-3 py-2 text-left font-medium">Sev</th>
                <th className="px-3 py-2 text-left font-medium">Code</th>
                <th className="px-3 py-2 text-left font-medium">MAC</th>
                <th className="px-3 py-2 text-left font-medium">IP</th>
                <th className="px-3 py-2 text-left font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((row) => (
                <LogRow key={row.id} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data?.truncated && (
        <p className="text-[10px] text-amber-600">
          Older entries truncated — narrow the filter to find them.
        </p>
      )}
    </div>
  );
}

function LogRow({ row }: { row: DHCPActivityLogRow }) {
  const sev = row.severity ?? "";
  const sevCls: Record<string, string> = {
    DEBUG: "text-muted-foreground",
    INFO: "text-foreground",
    WARN: "text-amber-600",
    ERROR: "text-destructive",
  };
  return (
    <tr className="border-b last:border-0">
      <td
        className="px-3 py-1.5 text-xs text-muted-foreground"
        title={new Date(row.ts).toLocaleString()}
      >
        {fmtRelative(row.ts)}
      </td>
      <td
        className={`px-3 py-1.5 text-[11px] font-medium ${sevCls[sev] ?? ""}`}
      >
        {sev || "—"}
      </td>
      <td className="px-3 py-1.5 font-mono text-[11px]">{row.code ?? "—"}</td>
      <td className="px-3 py-1.5 font-mono text-[11px]">
        {row.mac_address ?? "—"}
      </td>
      <td className="px-3 py-1.5 font-mono text-[11px]">
        {row.ip_address ?? "—"}
      </td>
      <td className="px-3 py-1.5 truncate text-[11px] text-muted-foreground">
        {row.raw}
      </td>
    </tr>
  );
}

// ── Config tab ────────────────────────────────────────────────────────────

function ConfigTab({ serverId }: { serverId: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dhcp-server-rendered-config", serverId],
    queryFn: () => dhcpApi.getServerRenderedConfig(serverId),
    refetchInterval: 60_000,
  });
  const [copied, setCopied] = useState(false);

  if (isLoading) return <LoadingBlock />;
  if (isError || !data) return <ErrorBlock />;

  if (!data.config) {
    return (
      <p className="rounded-md border bg-card p-4 text-center text-sm text-muted-foreground">
        This driver doesn't render a config we can preview.
      </p>
    );
  }

  // Try to JSON-pretty the body. Kea drivers return JSON text already
  // but we re-format defensively so a future driver that emits a tighter
  // form still renders nicely.
  let pretty = data.config;
  try {
    pretty = JSON.stringify(JSON.parse(data.config), null, 2);
  } catch {
    // Leave raw if the driver returned something other than JSON.
  }

  return (
    <div className="rounded-md border bg-card">
      <div className="flex items-center justify-between border-b px-3 py-2">
        <div className="flex flex-col">
          <span className="font-mono text-xs">
            {data.driver} config (live preview)
          </span>
          <span className="text-[10px] text-muted-foreground">
            Generated {fmtRelative(data.rendered_at)} · etag{" "}
            <code className="font-mono">
              {data.etag ? data.etag.slice(0, 16) + "…" : "—"}
            </code>
          </span>
        </div>
        <button
          type="button"
          onClick={() => {
            navigator.clipboard.writeText(pretty).then(() => {
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
        {pretty}
      </pre>
    </div>
  );
}

// ── Stats tab ─────────────────────────────────────────────────────────────

// #195: one stacked-area series per DHCP message type. The four handshake
// types the dashboard DHCPTrafficCard also plots use that card's exact colours
// (DISCOVER purple, REQUEST blue, ACK green, NAK red) so an operator reads the
// same hue for the same message across both surfaces; OFFER / DECLINE / RELEASE
// (modal-only) get distinct non-colliding hues.
const STATS_SERIES: Array<{ key: string; name: string; color: string }> = [
  { key: "discover", name: "DISCOVER", color: "#8b5cf6" },
  { key: "offer", name: "OFFER", color: "#06b6d4" },
  { key: "request", name: "REQUEST", color: "#3b82f6" },
  { key: "ack", name: "ACK", color: "#10b981" },
  { key: "nak", name: "NAK", color: "#ef4444" },
  { key: "decline", name: "DECLINE", color: "#f59e0b" },
  { key: "release", name: "RELEASE", color: "#ec4899" },
];

function StatsTab({ serverId }: { serverId: string }) {
  const [range, setRange] = useState<DHCPStatsRange>("1h");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["dhcp-server-stats", serverId, range],
    queryFn: () => dhcpApi.serverStats(serverId, range),
    refetchInterval: 60_000,
  });

  // Multi-day windows need the month/day prefix on each tick: 24h crosses a
  // midnight and 7d spans a week (at 30-min buckets), so a bare HH:MM repeats
  // across days and can't be told apart. 1h/6h are intra-day — time alone.
  const withDate = range === "24h" || range === "7d";

  const points = useMemo(() => {
    if (!data) return [];
    return data.rate_buckets.map((b) => ({
      t: formatBucket(b.ts, withDate),
      discover: b.discover,
      offer: b.offer,
      request: b.request,
      ack: b.ack,
      nak: b.nak,
      decline: b.decline,
      release: b.release,
      // #980 — DROPPED is socket_drop ALONE, and an unmeasured bucket stays
      // null so Recharts breaks the line there: a gap where nobody looked,
      // not a zero. See lib/dhcp-loss.ts for why receive_drop is excluded
      // and why the coalesce matters.
      dropped: bucketLoss(b),
    }));
  }, [data, withDate]);

  // #980 — three states, not two: measured and lossy, measured and clean,
  // never measured. The third must not render as the second.
  const loss = useMemo(() => summariseLoss(data?.rate_buckets ?? []), [data]);

  // date_bin emits only non-empty buckets, so an idle server usually yields
  // points.length === 0. But a window can also hold rows whose seven plotted
  // counters are all zero (e.g. INFORM-only traffic, which the DB sums but the
  // chart contract excludes) — treat that as "no activity" too rather than
  // rendering a flat zero-height chart.
  const hasActivity = useMemo(
    () =>
      points.some(
        (p) =>
          p.discover +
            p.offer +
            p.request +
            p.ack +
            p.nak +
            p.decline +
            p.release +
            // #980 — loss counts as activity. A server starved badly enough
            // that nothing completes has zeros in every message column and
            // thousands of drops, and "No activity in the last 1h" is the
            // worst possible thing to tell an operator at that moment.
            (p.dropped ?? 0) >
          0,
      ),
    [points],
  );

  return (
    <div className="space-y-3">
      <div className="rounded-md border bg-card">
        <div className="flex items-center justify-between border-b px-3 py-2">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-3.5 w-3.5 text-blue-500" />
            <h4 className="text-xs font-semibold uppercase tracking-wider">
              DHCP traffic
            </h4>
            {data && (
              <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-600">
                {data.leases_active} active{" "}
                {data.leases_active === 1 ? "lease" : "leases"}
              </span>
            )}
            {data &&
              (!loss.measured ? (
                <span
                  className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"
                  title="This server's agent does not report kernel-side packet loss (it predates the counters, or cannot read /proc/net/udp). This is NOT the same as reporting no loss."
                >
                  loss not measured
                </span>
              ) : loss.total > 0 ? (
                <span
                  className="rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-medium text-rose-600"
                  title="Packets the kernel discarded before the server could read them — its receive buffer filled. Most often the node is short of CPU: Kea answers 100% of what it reads, so no other signal shows this. Does not count packets Kea read and dropped on purpose, such as a blocklisted MAC."
                >
                  {loss.total} dropped
                </span>
              ) : null)}
          </div>
          <select
            value={range}
            onChange={(e) => setRange(e.target.value as DHCPStatsRange)}
            className="rounded border bg-background px-2 py-0.5 text-[11px] focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value="1h">1h</option>
            <option value="6h">6h</option>
            <option value="24h">24h</option>
            <option value="7d">7d</option>
          </select>
        </div>
        <div className="h-72 p-3">
          {isLoading ? (
            <LoadingBlock />
          ) : isError ? (
            <ErrorBlock />
          ) : !hasActivity ? (
            <p className="flex h-full flex-col items-center justify-center gap-1 text-center text-xs text-muted-foreground">
              <span>No activity in the last {range}.</span>
              <span className="text-[11px]">
                Kea agents report pkt4 counter deltas every 60&nbsp;s.
              </span>
            </p>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart
                data={points}
                margin={{ top: 5, right: 12, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={32} />
                <YAxis
                  tick={{ fontSize: 10 }}
                  width={52}
                  allowDecimals={false}
                  label={{
                    value: "msgs / bucket",
                    angle: -90,
                    position: "insideLeft",
                    style: { fontSize: 10, textAnchor: "middle" },
                  }}
                />
                <Tooltip
                  contentStyle={{ fontSize: 11, borderRadius: 6 }}
                  labelStyle={{ fontWeight: 600 }}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                {STATS_SERIES.map((s) => (
                  <Area
                    key={s.key}
                    type="monotone"
                    dataKey={s.key}
                    name={s.name}
                    stackId="msg"
                    stroke={s.color}
                    fill={s.color}
                    fillOpacity={0.25}
                    strokeWidth={1.5}
                  />
                ))}
                {/* #980 — a LINE, not another stacked area: dropped packets
                    are not a message type and adding them to the stack would
                    inflate the traffic total by the traffic that never
                    arrived. Rendered only once something has been measured,
                    so an un-upgraded agent shows no misleading flat zero. */}
                {loss.measured && (
                  <Line
                    type="monotone"
                    dataKey="dropped"
                    name="DROPPED"
                    stroke="#e11d48"
                    strokeWidth={2}
                    strokeDasharray="4 2"
                    dot={false}
                    connectNulls={false}
                  />
                )}
              </ComposedChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
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
