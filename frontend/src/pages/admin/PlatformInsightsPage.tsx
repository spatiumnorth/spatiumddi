import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Box,
  Cpu,
  Database,
  HardDrive,
  MemoryStick,
  Network,
  RefreshCw,
  Server,
  Sparkles,
  Wrench,
  Zap,
} from "lucide-react";
import {
  aiApi,
  conformityApi,
  postgresApi,
  containersApi,
  redisApi,
  versionApi,
  type PostgresOverview,
  type PostgresTableSize,
  type PostgresConnection,
  type PostgresSlowQuery,
  type ContainerStat,
  type RedisOverview,
} from "@/lib/api";
import { ServicesPanel } from "@/components/ServicesPanel";
import { ListReadError } from "@/components/ui/list-read-error";
import { isRefused, pollUnlessRefused } from "@/lib/refusal";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

type TabKey =
  | "postgres"
  | "redis"
  | "containers"
  | "services"
  | "conformity"
  | "copilot";

function formatBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

function formatNumber(n: number | null | undefined): string {
  if (n == null) return "—";
  return n.toLocaleString();
}

function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  if (seconds < 3600)
    return `${Math.floor(seconds / 60)} m ${Math.round(seconds % 60)} s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h} h ${m} m`;
}

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = "default",
}: {
  label: string;
  value: string;
  sub?: string;
  icon: React.ElementType;
  tone?: "default" | "warn" | "bad";
}) {
  const toneCls =
    tone === "bad"
      ? "border-destructive/40 bg-destructive/5"
      : tone === "warn"
        ? "border-amber-400/40 bg-amber-400/5"
        : "";
  return (
    <div className={cn("rounded-md border bg-card p-4", toneCls)}>
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wide text-muted-foreground">
          {label}
        </span>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

/** What a panel says when the server refused its reads (#2528): once, in
 *  words, instead of cards of dashes. The polls stop on a refusal. */
function RefusedNotice({ errors, what }: { errors: unknown[]; what: string }) {
  const refused = errors.find((e) => isRefused(e));
  if (!refused) return null;
  return (
    <p role="alert" className="text-sm">
      <ListReadError error={refused} what={what} />
    </p>
  );
}

function PostgresPanel() {
  const overview = useQuery({
    queryKey: ["pg-overview"],
    queryFn: () => postgresApi.overview(),
    refetchInterval: pollUnlessRefused(30_000),
  });
  const tables = useQuery({
    queryKey: ["pg-tables"],
    queryFn: () => postgresApi.tables(50),
    refetchInterval: pollUnlessRefused(60_000),
  });
  const connections = useQuery({
    queryKey: ["pg-conns"],
    queryFn: () => postgresApi.connections(),
    refetchInterval: pollUnlessRefused(30_000),
  });
  const slow = useQuery({
    queryKey: ["pg-slow"],
    queryFn: () => postgresApi.slowQueries(20),
    refetchInterval: pollUnlessRefused(60_000),
  });
  // #272 follow-up — alembic schema-head divergence (cold-boot / rolling
  // upgrade visibility). Polls a touch faster than the rest so a pending
  // migration clears from the banner soon after the migrate Job runs.
  const schema = useQuery({
    queryKey: ["pg-schema-health"],
    queryFn: () => postgresApi.schemaHealth(),
    refetchInterval: pollUnlessRefused(15_000),
  });

  const ov: PostgresOverview | undefined = overview.data;
  const refusals = [
    overview.error,
    tables.error,
    connections.error,
    slow.error,
    schema.error,
  ];

  const cachePct =
    ov?.cache_hit_ratio == null ? null : ov.cache_hit_ratio * 100;
  const connTone =
    ov &&
    ov.max_connections > 0 &&
    ov.active_connections / ov.max_connections >= 0.8
      ? "bad"
      : ov &&
          ov.max_connections > 0 &&
          ov.active_connections / ov.max_connections >= 0.5
        ? "warn"
        : "default";
  const cacheTone = cachePct != null && cachePct < 90 ? "warn" : "default";

  return (
    <div className="space-y-6">
      <RefusedNotice errors={refusals} what="Postgres statistics" />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Database size"
          value={formatBytes(ov?.db_size_bytes)}
          sub={ov?.version.split(",")[0]}
          icon={Database}
        />
        <StatCard
          label="Cache hit ratio"
          value={cachePct == null ? "—" : `${cachePct.toFixed(1)}%`}
          sub="heap blocks hit / (hit + read)"
          icon={Activity}
          tone={cacheTone}
        />
        <StatCard
          label="Active connections"
          value={`${ov?.active_connections ?? "—"} / ${ov?.max_connections ?? "—"}`}
          sub="this database"
          icon={Network}
          tone={connTone}
        />
        <StatCard
          label="WAL position"
          value={formatBytes(ov?.wal_bytes)}
          sub={ov?.wal_bytes == null ? "replica or unavailable" : "current LSN"}
          icon={HardDrive}
        />
      </div>

      {/* #272 follow-up — alembic schema-head divergence. Compact OK row;
        prominent banner when behind / errored (the actionable cases). */}
      {schema.data &&
        (schema.data.status === "ok" ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
            Schema at alembic head{" "}
            <span className="font-mono">{schema.data.expected_head}</span>.
          </div>
        ) : (
          <div
            className={cn(
              "rounded-md border p-3",
              schema.data.status === "behind"
                ? "border-amber-500/40 bg-amber-500/5"
                : "border-rose-500/40 bg-rose-500/5",
            )}
          >
            <div
              className={cn(
                "flex items-center gap-2 text-sm font-medium",
                schema.data.status === "behind"
                  ? "text-amber-800 dark:text-amber-300"
                  : "text-rose-800 dark:text-rose-300",
              )}
            >
              <AlertTriangle className="h-4 w-4" />
              {schema.data.status === "behind"
                ? "Database schema is behind this image"
                : "Schema-head check failed"}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {schema.data.detail}
            </p>
            <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs">
              <div>
                <span className="text-muted-foreground">Image expects</span>{" "}
                <span className="font-mono">
                  {schema.data.expected_head ?? "—"}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">DB revision</span>{" "}
                <span className="font-mono">
                  {schema.data.db_revision ?? "—"}
                </span>
              </div>
            </div>
          </div>
        ))}

      {ov?.longest_transaction && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
          <div className="flex items-center gap-2 text-sm font-medium text-amber-800 dark:text-amber-300">
            <AlertTriangle className="h-4 w-4" />
            Longest running transaction
          </div>
          <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
            <div>
              <span className="text-muted-foreground">PID</span>
              <div className="font-mono">{ov.longest_transaction.pid}</div>
            </div>
            <div>
              <span className="text-muted-foreground">State</span>
              <div>{ov.longest_transaction.state ?? "—"}</div>
            </div>
            <div>
              <span className="text-muted-foreground">Age</span>
              <div className="font-mono">
                {formatDuration(ov.longest_transaction.age_seconds)}
              </div>
            </div>
            <div>
              <span className="text-muted-foreground">App / client</span>
              <div className="truncate">
                {ov.longest_transaction.application_name ?? "—"}
                {ov.longest_transaction.client_addr
                  ? ` @ ${ov.longest_transaction.client_addr}`
                  : ""}
              </div>
            </div>
          </div>
          {ov.longest_transaction.query && (
            <pre className="mt-2 max-h-24 overflow-auto rounded bg-background/50 p-2 text-[11px] font-mono">
              {ov.longest_transaction.query}
            </pre>
          )}
        </div>
      )}

      <section>
        <h3 className="mb-2 text-sm font-semibold">Connections by state</h3>
        <div className="overflow-hidden rounded border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs">
              <tr>
                <th className="px-3 py-2 text-left font-medium">State</th>
                <th className="px-3 py-2 text-right font-medium">Count</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {(connections.data ?? []).map((row: PostgresConnection) => (
                <tr key={row.state}>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium",
                        row.state === "idle in transaction" ||
                          row.state === "idle in transaction (aborted)"
                          ? "bg-amber-500/20 text-amber-700 dark:text-amber-400"
                          : row.state === "active"
                            ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-400"
                            : "bg-muted",
                      )}
                    >
                      {row.state}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono">
                    {row.count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h3 className="mb-2 text-sm font-semibold">
          Tables by total size{" "}
          <span className="font-normal text-muted-foreground">(top 50)</span>
        </h3>
        <div className="overflow-x-auto rounded border">
          <table className="w-full min-w-[800px] text-sm">
            <thead className="bg-muted/40 text-xs">
              <tr>
                <th className="px-3 py-2 text-left font-medium">Table</th>
                <th className="px-3 py-2 text-right font-medium">Total</th>
                <th className="px-3 py-2 text-right font-medium">Heap</th>
                <th className="px-3 py-2 text-right font-medium">Indexes</th>
                <th className="px-3 py-2 text-right font-medium">TOAST</th>
                <th className="px-3 py-2 text-right font-medium">Live rows</th>
                <th className="px-3 py-2 text-right font-medium">Dead rows</th>
                <th className="px-3 py-2 text-left font-medium">Last vacuum</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {(tables.data ?? []).map((t: PostgresTableSize) => {
                const deadRatio =
                  t.live_rows > 0
                    ? t.dead_rows / (t.live_rows + t.dead_rows)
                    : 0;
                return (
                  <tr key={`${t.schema_name}.${t.table_name}`}>
                    <td className="px-3 py-1.5 font-mono text-xs">
                      {t.schema_name === "public"
                        ? t.table_name
                        : `${t.schema_name}.${t.table_name}`}
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono">
                      {formatBytes(t.total_bytes)}
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono text-muted-foreground">
                      {formatBytes(t.table_bytes)}
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono text-muted-foreground">
                      {formatBytes(t.index_bytes)}
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono text-muted-foreground">
                      {formatBytes(t.toast_bytes)}
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono">
                      {formatNumber(t.live_rows)}
                    </td>
                    <td
                      className={cn(
                        "px-3 py-1.5 text-right font-mono",
                        deadRatio > 0.2 && "text-amber-600 dark:text-amber-400",
                      )}
                    >
                      {formatNumber(t.dead_rows)}
                    </td>
                    <td className="px-3 py-1.5 text-xs text-muted-foreground">
                      {t.last_autovacuum
                        ? new Date(t.last_autovacuum).toLocaleString()
                        : "never"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h3 className="mb-2 text-sm font-semibold">
          Slow queries{" "}
          <span className="font-normal text-muted-foreground">
            (top 20 by total time)
          </span>
        </h3>
        {slow.data && !slow.data.available && (
          <div className="rounded border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
            <div className="font-medium text-amber-800 dark:text-amber-300">
              pg_stat_statements not available
            </div>
            <p className="mt-1 text-muted-foreground">{slow.data.hint}</p>
          </div>
        )}
        {slow.data?.available && (
          <div className="overflow-x-auto rounded border">
            <table className="w-full min-w-[800px] text-sm">
              <thead className="bg-muted/40 text-xs">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Query</th>
                  <th className="px-3 py-2 text-right font-medium">Calls</th>
                  <th className="px-3 py-2 text-right font-medium">Mean</th>
                  <th className="px-3 py-2 text-right font-medium">Total</th>
                  <th className="px-3 py-2 text-right font-medium">Rows</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {slow.data.rows.map((r: PostgresSlowQuery, i: number) => (
                  <tr key={i}>
                    <td className="px-3 py-1.5">
                      <pre className="max-w-2xl truncate font-mono text-xs">
                        {r.query}
                      </pre>
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono">
                      {formatNumber(r.calls)}
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono">
                      {r.mean_time_ms.toFixed(1)} ms
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono">
                      {(r.total_time_ms / 1000).toFixed(1)} s
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono text-muted-foreground">
                      {formatNumber(r.rows)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function ContainersPanel() {
  const version = useQuery({ queryKey: ["version"], queryFn: versionApi.get });
  const isAppliance = !!version.data?.appliance_mode;
  const [prefix, setPrefix] = useState("spatiumddi-");
  const [includeStopped, setIncludeStopped] = useState(false);
  const stats = useQuery({
    queryKey: ["container-stats", prefix, includeStopped],
    queryFn: () =>
      containersApi.stats({ prefix, include_stopped: includeStopped }),
    refetchInterval: 5_000,
    // No operator-facing Docker socket on the k3s appliance — don't poll it;
    // we point at Appliance → Pods instead (below).
    enabled: !isAppliance,
  });

  // On a k3s appliance the control-plane workloads run as Kubernetes pods,
  // not Docker containers, so this docker-stats view is empty/irrelevant.
  // Send the operator to Appliance → Cluster → Pods (live logs + restart).
  if (isAppliance) {
    return (
      <div className="rounded border border-blue-500/40 bg-blue-500/5 p-4">
        <div className="flex items-center gap-2 text-sm font-medium text-blue-800 dark:text-blue-300">
          <Box className="h-4 w-4" />
          This appliance runs on k3s
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          Control-plane workloads run as Kubernetes pods, not Docker containers.
          View and manage them — with restart and live log streaming — under{" "}
          <Link
            to="/appliance?tab=cluster&section=pods"
            className="font-medium text-primary hover:underline"
          >
            Appliance → Cluster → Pods
          </Link>
          .
        </p>
      </div>
    );
  }

  if (stats.data && !stats.data.available) {
    return (
      <div className="rounded border border-amber-500/40 bg-amber-500/5 p-4">
        <div className="flex items-center gap-2 text-sm font-medium text-amber-800 dark:text-amber-300">
          <AlertTriangle className="h-4 w-4" />
          Docker socket not mounted
        </div>
        <p className="mt-2 text-xs text-muted-foreground">{stats.data.hint}</p>
      </div>
    );
  }

  const rows = stats.data?.rows ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <label className="text-xs text-muted-foreground">Name filter</label>
          <input
            value={prefix}
            onChange={(e) => setPrefix(e.target.value)}
            placeholder="(empty for all)"
            className="rounded-md border bg-background px-2 py-1 text-sm"
          />
        </div>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="checkbox"
            checked={includeStopped}
            onChange={(e) => setIncludeStopped(e.target.checked)}
            className="rounded"
          />
          Include stopped
        </label>
        <span className="text-xs text-muted-foreground">
          Auto-refresh every 5 s
        </span>
      </div>
      <div className="overflow-x-auto rounded border">
        <table className="w-full min-w-[900px] text-sm">
          <thead className="bg-muted/40 text-xs">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Container</th>
              <th className="px-3 py-2 text-left font-medium">State</th>
              <th className="px-3 py-2 text-right font-medium">CPU%</th>
              <th className="px-3 py-2 text-right font-medium">Memory</th>
              <th className="px-3 py-2 text-right font-medium">Mem%</th>
              <th className="px-3 py-2 text-right font-medium">Net RX</th>
              <th className="px-3 py-2 text-right font-medium">Net TX</th>
              <th className="px-3 py-2 text-right font-medium">Disk R</th>
              <th className="px-3 py-2 text-right font-medium">Disk W</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={9}
                  className="px-3 py-4 text-center text-xs text-muted-foreground"
                >
                  No containers match.
                </td>
              </tr>
            )}
            {rows.map((c: ContainerStat) => {
              const cpuTone =
                c.cpu_percent != null && c.cpu_percent > 80
                  ? "text-red-600 dark:text-red-400"
                  : c.cpu_percent != null && c.cpu_percent > 50
                    ? "text-amber-600 dark:text-amber-400"
                    : "";
              const memTone =
                c.memory_percent != null && c.memory_percent > 90
                  ? "text-red-600 dark:text-red-400"
                  : c.memory_percent != null && c.memory_percent > 75
                    ? "text-amber-600 dark:text-amber-400"
                    : "";
              return (
                <tr key={c.id}>
                  <td className="px-3 py-1.5">
                    <div className="font-medium">{c.name}</div>
                    <div className="text-[11px] text-muted-foreground">
                      {c.image}
                    </div>
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium",
                        c.state === "running"
                          ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-400"
                          : "bg-muted text-muted-foreground",
                      )}
                    >
                      {c.state}
                    </span>
                  </td>
                  <td
                    className={cn("px-3 py-1.5 text-right font-mono", cpuTone)}
                  >
                    {c.cpu_percent == null
                      ? "—"
                      : `${c.cpu_percent.toFixed(1)}%`}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-xs">
                    {formatBytes(c.memory_bytes)}
                    {c.memory_limit_bytes ? (
                      <span className="text-muted-foreground">
                        {" "}
                        / {formatBytes(c.memory_limit_bytes)}
                      </span>
                    ) : null}
                  </td>
                  <td
                    className={cn("px-3 py-1.5 text-right font-mono", memTone)}
                  >
                    {c.memory_percent == null
                      ? "—"
                      : `${c.memory_percent.toFixed(1)}%`}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-xs">
                    {formatBytes(c.network_rx_bytes)}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-xs">
                    {formatBytes(c.network_tx_bytes)}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-xs">
                    {formatBytes(c.block_read_bytes)}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono text-xs">
                    {formatBytes(c.block_write_bytes)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function PlatformInsightsPage() {
  const [tab, setTab] = useState<TabKey>("postgres");

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-7xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="flex items-center gap-2 text-xl font-semibold">
              <Cpu className="h-5 w-5" />
              Platform Insights
            </h1>
            <p className="text-sm text-muted-foreground">
              Read-only diagnostics for the SpatiumDDI control plane.
            </p>
          </div>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs hover:bg-muted"
            title="Force a fresh fetch"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Reload
          </button>
        </div>

        <div className="border-b">
          <div className="flex gap-1">
            <button
              onClick={() => setTab("postgres")}
              className={cn(
                "border-b-2 px-3 py-2 text-sm font-medium -mb-px transition-colors",
                tab === "postgres"
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Database className="mr-1 inline h-3.5 w-3.5" />
              Postgres
            </button>
            <button
              onClick={() => setTab("redis")}
              className={cn(
                "border-b-2 px-3 py-2 text-sm font-medium -mb-px transition-colors",
                tab === "redis"
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Server className="mr-1 inline h-3.5 w-3.5" />
              Redis
            </button>
            <button
              onClick={() => setTab("containers")}
              className={cn(
                "border-b-2 px-3 py-2 text-sm font-medium -mb-px transition-colors",
                tab === "containers"
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Box className="mr-1 inline h-3.5 w-3.5" />
              Containers
            </button>
            <button
              onClick={() => setTab("services")}
              className={cn(
                "border-b-2 px-3 py-2 text-sm font-medium -mb-px transition-colors",
                tab === "services"
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Wrench className="mr-1 inline h-3.5 w-3.5" />
              Services
            </button>
            <button
              onClick={() => setTab("conformity")}
              className={cn(
                "border-b-2 px-3 py-2 text-sm font-medium -mb-px transition-colors",
                tab === "conformity"
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <ShieldCheck className="mr-1 inline h-3.5 w-3.5" />
              Conformity
            </button>
            <button
              onClick={() => setTab("copilot")}
              className={cn(
                "border-b-2 px-3 py-2 text-sm font-medium -mb-px transition-colors",
                tab === "copilot"
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Sparkles className="mr-1 inline h-3.5 w-3.5" />
              Copilot Usage
            </button>
          </div>
        </div>

        {tab === "postgres" && <PostgresPanel />}
        {tab === "redis" && <RedisPanel />}
        {tab === "services" && <ServicesPanel />}
        {tab === "containers" && <ContainersPanel />}
        {tab === "conformity" && <ConformityPanel />}
        {tab === "copilot" && <AIUsagePanel />}
      </div>
    </div>
  );
}

function RedisPanel() {
  const overview = useQuery({
    queryKey: ["redis-overview"],
    queryFn: () => redisApi.overview(),
    refetchInterval: pollUnlessRefused(15_000),
  });
  const keyspace = useQuery({
    queryKey: ["redis-keyspace"],
    queryFn: () => redisApi.keyspace(),
    refetchInterval: pollUnlessRefused(30_000),
  });
  const wakeBus = useQuery({
    queryKey: ["redis-wake-bus"],
    queryFn: () => redisApi.wakeBus(),
    refetchInterval: pollUnlessRefused(10_000),
  });

  const ov: RedisOverview | undefined = overview.data;

  if (ov && !ov.available) {
    return (
      <div className="rounded-md border border-amber-400/40 bg-amber-400/5 p-4 text-sm">
        <div className="flex items-center gap-2 font-medium">
          <AlertTriangle className="h-4 w-4 text-amber-500" />
          Redis is unreachable
        </div>
        <p className="mt-1 text-muted-foreground">
          {ov.hint ??
            "The control plane could not connect to Redis. Agents fall back to the HTTP poll cadence while it's down."}
        </p>
      </div>
    );
  }

  const hits = ov?.keyspace_hits ?? 0;
  const misses = ov?.keyspace_misses ?? 0;
  const hitPct = hits + misses > 0 ? (hits / (hits + misses)) * 100 : null;
  const fragTone =
    ov?.mem_fragmentation_ratio != null && ov.mem_fragmentation_ratio >= 1.5
      ? "warn"
      : "default";

  const wb = wakeBus.data;

  return (
    <div className="space-y-6">
      <RefusedNotice
        errors={[overview.error, keyspace.error, wakeBus.error]}
        what="Redis statistics"
      />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Role"
          value={ov?.role ?? "—"}
          sub={
            ov?.sentinel
              ? `Sentinel HA · ${ov?.connected_replicas ?? 0} replica(s)`
              : ov?.redis_version
                ? `v${ov.redis_version}`
                : undefined
          }
          icon={Server}
        />
        <StatCard
          label="Used memory"
          value={formatBytes(ov?.used_memory_bytes)}
          sub={`peak ${formatBytes(ov?.used_memory_peak_bytes)}${
            ov?.mem_fragmentation_ratio != null
              ? ` · frag ${ov.mem_fragmentation_ratio.toFixed(2)}`
              : ""
          }`}
          icon={MemoryStick}
          tone={fragTone}
        />
        <StatCard
          label="Connected clients"
          value={formatNumber(ov?.connected_clients)}
          sub={`${formatNumber(ov?.instantaneous_ops_per_sec)} ops/sec`}
          icon={Network}
        />
        <StatCard
          label="Keyspace hit ratio"
          value={hitPct == null ? "—" : `${hitPct.toFixed(1)}%`}
          sub={`uptime ${formatDuration(ov?.uptime_seconds)}`}
          icon={Activity}
        />
      </div>

      {/* Config-wake bus (#358) */}
      <div className="rounded-md border bg-card">
        <div className="flex items-center justify-between border-b px-4 py-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Zap className="h-4 w-4" />
            Agent config-wake bus
          </h2>
          <span className="text-xs text-muted-foreground">
            {wb?.available
              ? `${wb.total_subscribers} subscriber(s) · ${wb.active_channels.length} channel(s)`
              : "unavailable"}
          </span>
        </div>
        <div className="p-4">
          <p className="mb-3 text-xs text-muted-foreground">
            Redis pub/sub channels that wake parked agent <code>/config</code>{" "}
            long-polls the instant a change commits. One subscriber per parked
            agent per channel; publishes are counted by resource class.
          </p>
          {wb?.available && Object.keys(wb.published_by_class).length > 0 && (
            <div className="mb-4 flex flex-wrap gap-2">
              {Object.entries(wb.published_by_class).map(([cls, n]) => (
                <span
                  key={cls}
                  className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs"
                >
                  <span className="font-medium">{cls}</span>
                  <span className="text-muted-foreground">
                    {formatNumber(n)} published
                  </span>
                </span>
              ))}
            </div>
          )}
          {wb?.available && wb.active_channels.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground">
                  <th className="pb-2 font-medium">Channel</th>
                  <th className="pb-2 text-right font-medium">Subscribers</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {wb.active_channels.map((c) => (
                  <tr key={c.channel}>
                    <td className="py-1.5 font-mono text-xs">{c.channel}</td>
                    <td className="py-1.5 text-right">{c.subscribers}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : wb && !wb.available ? (
            <p className="text-sm text-amber-600 dark:text-amber-400">
              Wake-bus metrics unavailable
              {wb.hint ? `: ${wb.hint}` : " (Redis unreachable)"}.
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">
              No agents are currently parked on a wake channel.
            </p>
          )}
        </div>
      </div>

      {/* Keyspace */}
      <div className="rounded-md border bg-card">
        <div className="border-b px-4 py-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Database className="h-4 w-4" />
            Keyspace
          </h2>
        </div>
        <div className="p-4">
          {keyspace.data?.dbs && keyspace.data.dbs.length > 0 ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground">
                  <th className="pb-2 font-medium">DB</th>
                  <th className="pb-2 text-right font-medium">Keys</th>
                  <th className="pb-2 text-right font-medium">Volatile</th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {keyspace.data.dbs.map((d) => (
                  <tr key={d.db}>
                    <td className="py-1.5 font-mono text-xs">{d.db}</td>
                    <td className="py-1.5 text-right">
                      {formatNumber(d.keys)}
                    </td>
                    <td className="py-1.5 text-right text-muted-foreground">
                      {formatNumber(d.expires)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : keyspace.data && !keyspace.data.available ? (
            <p className="text-sm text-amber-600 dark:text-amber-400">
              Keyspace unavailable
              {keyspace.data.hint
                ? `: ${keyspace.data.hint}`
                : " (Redis unreachable)"}
              .
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">No keys.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function ConformityPanel() {
  const summaryQ = useQuery({
    queryKey: ["conformity-summary"],
    queryFn: () => conformityApi.summary(),
    staleTime: 60 * 1000,
    refetchOnWindowFocus: false,
    retry: false,
  });

  if (summaryQ.isLoading) {
    return (
      <p className="text-sm text-muted-foreground">Loading conformity data…</p>
    );
  }
  if (!summaryQ.data) {
    return (
      <p className="text-sm text-muted-foreground">
        No conformity data available.
      </p>
    );
  }
  const summary = summaryQ.data;
  const total =
    summary.overall_pass +
    summary.overall_warn +
    summary.overall_fail +
    summary.overall_not_applicable;
  return (
    <section className="rounded-lg border bg-card p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold">
            <ShieldCheck className="h-4 w-4" />
            Conformity
          </h2>
          <p className="text-xs text-muted-foreground">
            Latest policy results aggregated by framework. Drill into{" "}
            <Link
              to="/admin/conformity"
              className="text-primary hover:underline"
            >
              Conformity admin
            </Link>{" "}
            to manage policies and pull the auditor PDF.
          </p>
        </div>
        <div className="text-right text-[11px] text-muted-foreground">
          {summary.last_evaluated_at ? (
            <>
              Last eval: {new Date(summary.last_evaluated_at).toLocaleString()}
            </>
          ) : (
            <>No policies evaluated yet.</>
          )}
        </div>
      </div>
      {summary.frameworks.length === 0 ? (
        <p className="mt-3 text-xs text-muted-foreground">
          No conformity policies are configured.
        </p>
      ) : (
        <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
          {summary.frameworks.map((fw) => {
            const fwTotal =
              fw.pass_count +
              fw.warn_count +
              fw.fail_count +
              fw.not_applicable_count;
            const passPct =
              fwTotal > 0 ? Math.round((fw.pass_count / fwTotal) * 100) : 0;
            return (
              <div
                key={fw.framework}
                className="rounded-md border bg-background p-3"
              >
                <p className="text-xs font-semibold">{fw.framework}</p>
                <p className="text-[11px] text-muted-foreground">
                  {fw.policies_enabled}/{fw.policies_total} policies enabled
                </p>
                <p className="mt-1 text-lg font-bold tabular-nums">
                  {passPct}%
                </p>
                <p className="text-[11px] text-muted-foreground">
                  <span className="text-emerald-600 dark:text-emerald-400">
                    {fw.pass_count} pass
                  </span>{" "}
                  ·{" "}
                  <span className="text-amber-600 dark:text-amber-400">
                    {fw.warn_count} warn
                  </span>{" "}
                  ·{" "}
                  <span className="text-red-600 dark:text-red-400">
                    {fw.fail_count} fail
                  </span>
                </p>
              </div>
            );
          })}
        </div>
      )}
      {total === 0 && (
        <p className="mt-3 rounded-md border bg-muted/20 p-2 text-[11px] text-muted-foreground">
          Built-in policies ship disabled. Toggle a policy on in{" "}
          <Link to="/admin/conformity" className="text-primary hover:underline">
            /admin/conformity
          </Link>{" "}
          to start collecting results.
        </p>
      )}
    </section>
  );
}

function AIUsagePanel() {
  const usageQ = useQuery({
    queryKey: ["ai-usage-admin"],
    queryFn: aiApi.adminUsage,
    staleTime: 60 * 1000,
    refetchOnWindowFocus: false,
    retry: false,
  });

  if (usageQ.isLoading) {
    return (
      <p className="text-sm text-muted-foreground">Loading copilot usage…</p>
    );
  }
  if (usageQ.error || !usageQ.data) {
    // Endpoint is SuperAdmin-only — non-superadmins 403 here. Before
    // moving this into its own tab the panel just hid itself; now that
    // it owns the tab content, explain why the table is empty rather
    // than rendering a blank page.
    return (
      <p className="text-sm text-muted-foreground">
        Operator Copilot usage data is only visible to superadmins.
      </p>
    );
  }
  const { today, last_7d, last_30d, top_users_today } = usageQ.data;

  return (
    <section>
      <div className="mb-2 flex items-center gap-2">
        <Sparkles className="h-4 w-4" />
        <h2 className="text-base font-semibold">Operator Copilot usage</h2>
      </div>
      <div className="rounded-lg border bg-card p-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <UsageWindowCard label="Today" snapshot={today} />
          <UsageWindowCard label="Last 7 days" snapshot={last_7d} />
          <UsageWindowCard label="Last 30 days" snapshot={last_30d} />
        </div>
        {top_users_today.length > 0 && (
          <div className="mt-5">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Top users today
            </div>
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full text-sm">
                <thead className="border-b bg-muted/30 text-left text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-1.5">User</th>
                    <th className="px-3 py-1.5 text-right">Messages</th>
                    <th className="px-3 py-1.5 text-right">Tokens</th>
                    <th className="px-3 py-1.5 text-right">Cost</th>
                  </tr>
                </thead>
                <tbody>
                  {top_users_today.map((u) => (
                    <tr key={u.user_id} className="border-b last:border-b-0">
                      <td className="px-3 py-1.5 font-medium">{u.username}</td>
                      <td className="px-3 py-1.5 text-right">{u.messages}</td>
                      <td className="px-3 py-1.5 text-right text-muted-foreground">
                        {(u.tokens_in + u.tokens_out).toLocaleString()}
                      </td>
                      <td className="px-3 py-1.5 text-right font-mono text-xs">
                        ${parseFloat(u.cost_usd).toFixed(4)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function UsageWindowCard({
  label,
  snapshot,
}: {
  label: string;
  snapshot: import("@/lib/api").AIUsageSnapshot;
}) {
  const tokens = snapshot.tokens_in + snapshot.tokens_out;
  const cost = parseFloat(snapshot.cost_usd);
  return (
    <div className="rounded-md border bg-muted/20 p-3">
      <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-2 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="text-2xl font-semibold">{snapshot.messages}</span>
        <span className="text-xs text-muted-foreground">
          message{snapshot.messages === 1 ? "" : "s"}
        </span>
      </div>
      <div className="mt-1 grid grid-cols-2 gap-x-4 gap-y-0.5 text-xs text-muted-foreground">
        <span>Tokens</span>
        <span className="text-right font-mono">{tokens.toLocaleString()}</span>
        <span>Cost</span>
        <span className="text-right font-mono">${cost.toFixed(4)}</span>
      </div>
    </div>
  );
}
