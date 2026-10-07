import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  HardDrive,
  Layers,
  MemoryStick,
  Network,
  Pause,
  Power,
  Globe,
  Radio,
  RotateCcw,
  ScrollText,
  Server,
  Tag,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  applianceApi,
  applianceSystemApi,
  streamApplianceWorkloadLogs,
  versionApi,
  type ClusterDns,
  type ClusterKubeletTransport,
  type ClusterNodeVitals,
  type ClusterPodSummary,
  type ClusterWorkloadHealth,
  type NodeStorage,
  type SelfApplianceInfo,
} from "@/lib/api";
import {
  formatEta,
  mdChipLabel,
  mpathChipLabel,
  storageChipClass,
} from "@/lib/storage-health";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { cn } from "@/lib/utils";
import {
  AMBER,
  EMERALD,
  ROSE,
  SKY,
  SLATE,
  VIOLET,
  fmtAge,
  fmtBytes,
  fmtCores,
  pct,
  usageColor,
  useClusterHealthStream,
  type HistPoint,
} from "./clusterShared";

/**
 * Cluster → Overview (#402 / #416) — one cohesive, near-real-time dashboard
 * for the k3s cluster underneath the appliance.
 *
 * Fed by an SSE stream (`/appliance/cluster/health/stream`) that pushes a
 * fresh snapshot every ~2s; each frame animates the gradient CPU/memory hero
 * chart, the per-node radial gauges, the KPI sparklines, and the top-pods
 * leaderboard. There's no metrics-server / Prometheus on the appliance — live
 * usage comes from the kubelet Summary API, the same source the TTY console
 * uses. The stream self-reconnects; a one-shot GET paints instantly on mount.
 *
 * The top identity header + live pod-log tail + reboot action fold in what was
 * a separate "Console" sub-view: identity / lifecycle come from
 * `applianceApi.getInfo()` (the `self_appliance` block) + the app version from
 * `versionApi.get()`. Degrades gracefully when `self_appliance` is null
 * (docker / k8s control plane or pre-registration) — slot / pairing chips drop
 * out, while hostname / version / cluster / log / actions stay.
 */

function shortPodName(p: { name: string }): string {
  return p.name
    .replace(/^spatium-control-spatiumddi-/, "")
    .replace(/^spatium-bootstrap-/, "")
    .replace(/^spatium-/, "");
}

// ── small relative-time helper (no shared util exists) ─────────────────────
function relTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ── small visual primitives ──────────────────────────────────────────────────

function RadialGauge({
  value,
  label,
  sub,
}: {
  value: number | null;
  label: string;
  sub?: string;
}) {
  const p = value == null ? 0 : Math.max(0, Math.min(100, value));
  const R = 32;
  const C = 2 * Math.PI * R;
  const off = C * (1 - p / 100);
  const color = usageColor(value);
  return (
    <div className="flex flex-col items-center">
      <div className="relative h-[76px] w-[76px]">
        <svg viewBox="0 0 80 80" className="h-[76px] w-[76px] -rotate-90">
          <circle
            cx="40"
            cy="40"
            r={R}
            fill="none"
            strokeWidth="7"
            className="stroke-muted/40"
          />
          <circle
            cx="40"
            cy="40"
            r={R}
            fill="none"
            stroke={color}
            strokeWidth="7"
            strokeLinecap="round"
            strokeDasharray={C}
            strokeDashoffset={off}
            style={{
              transition: "stroke-dashoffset 0.7s ease, stroke 0.7s ease",
            }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span
            className="text-base font-semibold tabular-nums"
            style={{ color }}
          >
            {value == null ? "—" : `${Math.round(value)}%`}
          </span>
        </div>
      </div>
      <span className="mt-1 text-[11px] font-medium text-muted-foreground">
        {label}
      </span>
      {sub && <span className="text-[10px] text-muted-foreground">{sub}</span>}
    </div>
  );
}

export function Sparkline({
  data,
  color,
  max,
}: {
  data: number[];
  color: string;
  max?: number;
}) {
  const w = 100;
  const h = 28;
  if (data.length < 2) {
    return (
      <svg
        viewBox={`0 0 ${w} ${h}`}
        className="h-7 w-full"
        preserveAspectRatio="none"
      />
    );
  }
  const hi = max ?? Math.max(...data, 1);
  const lo = 0;
  const range = hi - lo || 1;
  const x = (i: number) => (i / (data.length - 1)) * w;
  const y = (v: number) =>
    h - ((Math.max(lo, Math.min(hi, v)) - lo) / range) * h;
  const line = data.map((v, i) => `${x(i)},${y(v)}`).join(" ");
  const area = `0,${h} ${line} ${w},${h}`;
  const gid = `spark-${color.replace("#", "")}`;
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className="h-7 w-full"
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.35} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#${gid})`} />
      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

function Bar({ value, color }: { value: number; color: string }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-muted/40">
      <div
        className="h-full rounded-full"
        style={{
          width: `${Math.max(2, Math.min(100, value))}%`,
          background: color,
          transition: "width 0.7s ease, background 0.7s ease",
        }}
      />
    </div>
  );
}

// ── identity chip ──────────────────────────────────────────────────────────
function Chip({
  icon: Icon,
  children,
  color,
  title,
}: {
  icon?: typeof Cpu;
  children: React.ReactNode;
  color?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium"
      style={
        color
          ? { color, borderColor: `${color}55`, background: `${color}12` }
          : undefined
      }
    >
      {Icon && <Icon className="h-3 w-3" />}
      {children}
    </span>
  );
}

function upgradeStateColor(state: string | null | undefined): string {
  switch (state) {
    case "ready":
    case "done":
      return EMERALD;
    case "in-flight":
      return VIOLET;
    case "failed":
      return ROSE;
    default:
      return SLATE;
  }
}

// Derive the list of roles the box runs from the watchdog role_health keys
// (compose-service names → their reported ``role``), falling back to the
// deployment kind so a box with no watchdog rollup still labels itself.
function deriveRoles(self: SelfApplianceInfo | null): string[] {
  if (self) {
    const fromHealth = Object.entries(self.role_health)
      .map(([svc, v]) => v?.role || svc)
      .filter(Boolean);
    if (fromHealth.length) return [...new Set(fromHealth)];
    if (self.deployment_kind) return [self.deployment_kind];
  }
  return [];
}

export function KpiTile({
  icon: Icon,
  label,
  value,
  sub,
  accent,
  children,
}: {
  icon: typeof Cpu;
  label: string;
  value: string;
  sub?: string;
  accent: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border bg-card p-3 shadow-sm">
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-0.5"
        style={{ background: accent }}
      />
      <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3.5 w-3.5" style={{ color: accent }} />
        {label}
      </div>
      <div className="mt-1 flex items-baseline gap-1.5">
        <span className="text-2xl font-semibold tabular-nums">{value}</span>
        {sub && <span className="text-xs text-muted-foreground">{sub}</span>}
      </div>
      {children && <div className="mt-1">{children}</div>}
    </div>
  );
}

export function RoleBadge({ role }: { role: string }) {
  const color =
    role === "control-plane" || role === "master"
      ? VIOLET
      : role === "etcd"
        ? AMBER
        : SLATE;
  return (
    <span
      className="rounded px-1.5 py-0.5 text-[10px] font-medium"
      style={{ color, background: `${color}1f` }}
    >
      {role}
    </span>
  );
}

export function StatusChip({ status }: { status: string }) {
  const map: Record<string, [string, string]> = {
    healthy: [EMERALD, "Healthy"],
    degraded: [AMBER, "Degraded"],
    down: [ROSE, "Down"],
  };
  const [color, text] = map[status] ?? [SLATE, status];
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium"
      style={{ color, background: `${color}1f` }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: color }}
      />
      {text}
    </span>
  );
}

// ── node card ────────────────────────────────────────────────────────────────

/**
 * #983 Phase 2 — the share of the last 5 minutes something spent STALLED on a
 * resource, which is the reading utilisation cannot give you: a node at 70%
 * CPU with a run queue and one without look identical by usage, and only the
 * first drops traffic (#980).
 *
 * `null` is rendered as "not reported", never as 0%. A kubelet below 1.36
 * reports no PSI at all, and a panel that draws that as a quiet green bar is
 * worse than one that admits it does not know.
 */
function PressureRow({ node }: { node: ClusterNodeVitals }) {
  const rows: { label: string; some: number | null; full: number | null }[] = [
    {
      label: "CPU",
      some: node.psi_cpu?.some?.avg300 ?? null,
      // Deliberately not shown: the kernel reports CPU `full` as 0 at node
      // level by definition, so a column for it would always read 0.0%.
      full: null,
    },
    {
      label: "Mem",
      some: node.psi_memory?.some?.avg300 ?? null,
      full: node.psi_memory?.full?.avg300 ?? null,
    },
    {
      label: "I/O",
      some: node.psi_io?.some?.avg300 ?? null,
      full: null,
    },
  ];
  const reported = rows.some((r) => r.some !== null || r.full !== null);
  if (!reported) {
    return (
      <div
        className="mt-2 text-[10px] italic text-muted-foreground"
        title="Pressure Stall Information is reported by kubelet 1.36 and later. This node reported none, which is not the same as no pressure."
      >
        pressure: not reported
      </div>
    );
  }
  const tone = (v: number | null) =>
    v === null
      ? "text-muted-foreground"
      : v >= 50
        ? "text-rose-600 dark:text-rose-400"
        : v >= 20
          ? "text-amber-600 dark:text-amber-400"
          : "text-muted-foreground";
  return (
    <div
      className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px]"
      title="Share of the last 5 minutes spent stalled waiting on the resource (PSI avg300). 'some' = at least one task blocked; 'full' = every runnable task blocked."
    >
      <span className="text-muted-foreground">stalled 5m</span>
      {rows.map((r) => (
        <span key={r.label} className="font-mono">
          <span className="text-muted-foreground">{r.label} </span>
          <span className={tone(r.some)}>
            {r.some === null ? "—" : `${r.some.toFixed(1)}%`}
          </span>
          {r.full !== null && (
            <span className={tone(r.full)} title="every runnable task blocked">
              {" "}
              (full {r.full.toFixed(1)}%)
            </span>
          )}
        </span>
      ))}
    </div>
  );
}

/**
 * #983 Phase 2 item 6 — kubelet Summary API transport.
 *
 * `direct` reaches the kubelet on :10250 under `nodes/stats`, which
 * authorizes that one page. `proxy` goes through the apiserver under
 * `nodes/proxy`, which authorizes read GETs to EVERY kubelet endpoint. The
 * chip is green only when EVERY node went direct, because that is the
 * condition for dropping the broad grant — one node on the proxy means the
 * grant is still load-bearing.
 */
function KubeletTransportChip({
  transport,
}: {
  transport: ClusterKubeletTransport | null;
}) {
  if (!transport || transport.direct_nodes + transport.proxy_nodes === 0) {
    return null;
  }
  const reasons = Object.entries(transport.blocked_reasons);
  const title = transport.all_direct
    ? "Every node served by the direct kubelet transport (nodes/stats). Safe to set api.upgradeOrchestratorRBAC.kubeletProxyFallback=false, which drops the broad nodes/proxy grant."
    : [
        `${transport.proxy_nodes} node(s) fell back to the apiserver proxy (nodes/proxy), which authorizes read GETs to every kubelet endpoint.`,
        ...reasons.map(([node, why]) => `${node}: ${why}`),
      ].join("\n\n");
  return (
    <Chip color={transport.all_direct ? EMERALD : AMBER} title={title}>
      kubelet:{" "}
      {transport.all_direct
        ? "direct"
        : `${transport.direct_nodes} direct / ${transport.proxy_nodes} proxy`}
    </Chip>
  );
}

function ClusterDnsCard({ dns }: { dns: ClusterDns | null }) {
  if (!dns) return null;
  const probe = dns.resolve_probe;
  const ready = dns.replicas_ready;
  const expected = dns.expected_replicas;

  // Red beats amber, and a failed probe beats everything: replica counts
  // say the pods exist, the probe says the path actually works.
  const probeFailed = probe != null && !probe.ok;
  const noReplicas = ready === 0;
  const thin =
    ready != null && expected != null && ready < expected && ready > 0;
  const coLocated = dns.spread_ok === false && !thin && (ready ?? 0) > 1;
  // `null` is UNKNOWN and must never render green. Without this branch,
  // a block where every count is null — a 403 on the cluster-wide pod
  // list, or an unreadable snapshot — failed every test above (`ready ===
  // 0` is false for null; `spread_ok === false` is false for null) and
  // fell through to EMERALD, putting a green chip on the one panel whose
  // job is to say cluster DNS state could not be read.
  const unknown = !dns.available && !probeFailed;
  const color =
    probeFailed || noReplicas
      ? ROSE
      : thin || coLocated
        ? AMBER
        : unknown
          ? SLATE
          : EMERALD;

  const verdict = probeFailed
    ? "not answering"
    : noReplicas
      ? "no ready replicas"
      : thin
        ? `${ready} of ${expected} replicas`
        : coLocated
          ? "replicas share a node"
          : unknown
            ? "unknown"
            : "healthy";

  return (
    <div className="rounded-xl border bg-card p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <Globe className="h-4 w-4 text-muted-foreground" />
          Cluster DNS
        </h3>
        <Chip
          color={color}
          title={
            "Every pod resolves *.svc.cluster.local through CoreDNS — the api " +
            "reaches Postgres and Redis that way — so a failure here shows up " +
            "later as unrelated components failing to start."
          }
        >
          {verdict}
        </Chip>
      </div>

      <dl className="mt-3 space-y-1.5 text-xs">
        <div className="flex justify-between gap-3">
          <dt className="text-muted-foreground">Ready replicas</dt>
          {/* `null` is UNKNOWN, never 0 — see the ClusterDns docs. */}
          <dd className="font-medium">
            {ready == null
              ? "unknown"
              : expected == null
                ? ready
                : `${ready} / ${expected}`}
            {dns.replicas_total != null &&
              ready != null &&
              dns.replicas_total > ready && (
                <span className="ml-1 font-normal text-muted-foreground">
                  ({dns.replicas_total - ready} not ready)
                </span>
              )}
          </dd>
        </div>
        {dns.nodes.length > 0 && (
          <div className="flex justify-between gap-3">
            <dt className="text-muted-foreground">On nodes</dt>
            <dd className="text-right font-medium">{dns.nodes.join(", ")}</dd>
          </div>
        )}
        <div className="flex justify-between gap-3">
          <dt className="text-muted-foreground">Spread</dt>
          <dd className="font-medium">
            {dns.spread_ok == null
              ? "unknown"
              : dns.spread_ok
                ? "one replica per node"
                : "not spread across nodes"}
          </dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="text-muted-foreground">Resolver</dt>
          <dd className="font-mono text-[11px]">
            {dns.resolver_ip ?? "unknown"}
          </dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="text-muted-foreground">
            Resolve probe
            {probe?.from_node && (
              <span className="ml-1 font-normal">from {probe.from_node}</span>
            )}
          </dt>
          <dd className="font-medium">
            {probe == null
              ? "not run"
              : probe.ok
                ? `ok${probe.latency_ms != null ? ` · ${probe.latency_ms} ms` : ""}`
                : "failed"}
          </dd>
        </div>
      </dl>

      {/* A probe failure alongside healthy replicas is its own diagnosis —
          kube-proxy or the CNI, not CoreDNS — so it is not collapsed into
          the replica verdict. */}
      {probeFailed && (
        <p className="mt-2 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1.5 text-[11px] text-rose-700 dark:text-rose-300">
          {probe?.error}
          {!noReplicas && ready != null && ready > 0 && (
            <span className="mt-1 block">
              CoreDNS replicas look healthy, so the fault is more likely in
              kube-proxy or the pod network than in CoreDNS itself.
            </span>
          )}
        </p>
      )}
      {!dns.available && dns.detail && (
        <p className="mt-2 text-[11px] text-muted-foreground">{dns.detail}</p>
      )}
    </div>
  );
}

/**
 * Storage-redundancy chips for one node (#999 Part A).
 *
 * Renders NOTHING on an ordinary single-disk appliance — the common
 * case must gain no clutter — and nothing at all when the supervisor
 * has never reported storage, because that is UNKNOWN and a green
 * "no problems" chip would be a claim we cannot support.
 */
function StorageRow({ storage }: { storage: NodeStorage | null }) {
  if (!storage) return null;
  const arrays = storage.md_arrays ?? [];
  const maps = storage.multipath_maps ?? [];
  if (arrays.length === 0 && maps.length === 0) return null;

  // Severity comes from the server (see lib/storage-health.ts on why it
  // is not recomputed here). Findings are keyed by array / map name so a
  // healthy array beside a degraded one still renders green.
  const sevByName = new Map<string, string>();
  for (const f of storage.findings ?? []) {
    const prev = sevByName.get(f.name);
    if (prev == null || (prev !== "critical" && f.severity === "critical")) {
      sevByName.set(f.name, f.severity);
    }
  }

  return (
    <div className="flex flex-wrap gap-1">
      {arrays.map((a) => {
        const finding = (storage.findings ?? []).find(
          (f) => f.kind === "md" && f.name === a.name,
        );
        return (
          <span
            key={a.name}
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
              storageChipClass(sevByName.get(a.name) ?? null, "md"),
            )}
            title={
              finding?.detail ??
              `${a.name}: ${a.members_in_sync} of ${a.members_expected} members in sync.`
            }
          >
            <HardDrive className="h-2.5 w-2.5" />
            {mdChipLabel(a)}
            {a.sync?.eta_seconds != null && (
              <span className="opacity-70">
                · {formatEta(a.sync.eta_seconds)} left
              </span>
            )}
          </span>
        );
      })}
      {maps.map((m) => {
        const finding = (storage.findings ?? []).find(
          (f) => f.kind === "multipath" && f.name === m.name,
        );
        return (
          <span
            key={m.dm_device}
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
              storageChipClass(sevByName.get(m.name) ?? null, "multipath"),
            )}
            title={
              finding?.detail ??
              `${m.name}: ${m.paths_total} path(s) present. dm's own per-path state needs multipathd, which this image does not ship — so this is not a clean bill of health, only an absence of complaints.`
            }
          >
            <Network className="h-2.5 w-2.5" />
            {m.name} · {mpathChipLabel(m)}
          </span>
        );
      })}
    </div>
  );
}

function NodeCard({ node }: { node: ClusterNodeVitals }) {
  const cpuPct = pct(node.cpu_usage_cores, node.cpu_capacity_cores);
  const memPct = pct(node.memory_working_set_bytes, node.memory_capacity_bytes);
  const diskPct = pct(node.fs_used_bytes, node.fs_capacity_bytes);
  const parts = node.host_disk_partitions ?? [];
  const pressure =
    node.memory_pressure || node.disk_pressure || node.pid_pressure;
  return (
    <div className="rounded-xl border bg-card p-4 shadow-sm">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={`h-2.5 w-2.5 shrink-0 rounded-full ${node.ready ? "animate-pulse" : ""}`}
              style={{ background: node.ready ? EMERALD : ROSE }}
              title={node.ready ? "Ready" : "Not Ready"}
            />
            <span className="truncate font-semibold">{node.name}</span>
            {!node.schedulable && (
              <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                cordoned
              </span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {node.roles.map((r) => (
              <RoleBadge key={r} role={r} />
            ))}
          </div>
        </div>
        <div className="shrink-0 text-right text-[10px] text-muted-foreground">
          <div className="font-mono">{node.internal_ip ?? "—"}</div>
          <div>up {fmtAge(node.age_seconds)}</div>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-4">
        <RadialGauge
          value={cpuPct}
          label="CPU"
          sub={`${fmtCores(node.cpu_usage_cores)} / ${fmtCores(node.cpu_capacity_cores)}`}
        />
        <RadialGauge
          value={memPct}
          label="Memory"
          sub={`${fmtBytes(node.memory_working_set_bytes)} / ${fmtBytes(node.memory_capacity_bytes)}`}
        />
        <div className="min-w-0 flex-1 space-y-2 text-[11px]">
          {parts.length > 0 ? (
            // #402 — full host-partition breakdown from the supervisor
            // (root slot / var / ESP). statvfs'd host-side; the api pod
            // can't see host partitions itself.
            <div
              className="space-y-1.5"
              title="Host partitions reported by the supervisor (statvfs of the node's mounted filesystems)."
            >
              {parts.map((p) => {
                const pp = pct(p.used_bytes, p.total_bytes);
                return (
                  <div key={p.mount}>
                    <div className="flex justify-between text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <HardDrive className="h-3 w-3" /> {p.label}
                        <span className="font-mono text-[9px] opacity-70">
                          {p.mount}
                        </span>
                      </span>
                      <span className="tabular-nums">
                        {fmtBytes(p.used_bytes)} / {fmtBytes(p.total_bytes)}
                        {pp != null && (
                          <span className="ml-1 text-foreground">
                            · {Math.round(pp)}%
                          </span>
                        )}
                      </span>
                    </div>
                    <div className="mt-1">
                      <Bar value={pp ?? 0} color={usageColor(pp)} />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            // Fallback before the supervisor reports: the kubelet node
            // filesystem (the appliance's /var data partition).
            <div
              title={
                "Kubelet node filesystem — container images, pod volumes, and " +
                "ephemeral storage on the appliance's /var data partition. This " +
                "is the disk-pressure signal the kubelet evicts on. The OS slot " +
                "partitions (root A/B) and the ESP are managed separately."
              }
            >
              <div className="flex justify-between text-muted-foreground">
                <span className="flex items-center gap-1">
                  <HardDrive className="h-3 w-3" /> Disk
                  <span className="rounded bg-muted px-1 text-[9px] font-medium uppercase tracking-wide">
                    node /var
                  </span>
                </span>
                <span className="tabular-nums">
                  {fmtBytes(node.fs_used_bytes)} /{" "}
                  {fmtBytes(node.fs_capacity_bytes)}
                  {diskPct != null && (
                    <span className="ml-1 text-foreground">
                      · {Math.round(diskPct)}%
                    </span>
                  )}
                </span>
              </div>
              <div className="mt-1">
                <Bar value={diskPct ?? 0} color={usageColor(diskPct)} />
              </div>
            </div>
          )}
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="flex items-center gap-1">
              <Boxes className="h-3 w-3" /> Pods
            </span>
            <span className="tabular-nums text-foreground">
              {node.pods_running}
              {node.pods_capacity ? ` / ${node.pods_capacity}` : ""}
            </span>
          </div>
          <div
            className="truncate text-muted-foreground"
            title={node.os_image ?? ""}
          >
            {node.kubelet_version ?? "—"} · {node.architecture ?? "—"}
          </div>
          {pressure && (
            <div className="flex items-center gap-1 text-rose-500">
              <AlertTriangle className="h-3 w-3" />
              {[
                node.memory_pressure && "memory",
                node.disk_pressure && "disk",
                node.pid_pressure && "pid",
              ]
                .filter(Boolean)
                .join(" / ")}{" "}
              pressure
            </div>
          )}
          {/*
            The badge above is the kubelet's node CONDITION — a binary that
            flips only once eviction thresholds are already crossed. PSI below
            is the continuous signal that gets there first, and is what #980
            had no way to see.
          */}
          <PressureRow node={node} />
          {/*
            #999 Part A — md / multipath redundancy. Silent on a node
            with neither, so a single-disk appliance is unchanged.
          */}
          <StorageRow storage={node.host_storage ?? null} />
        </div>
      </div>
    </div>
  );
}

// ── top-pods leaderboard ──────────────────────────────────────────────────────

function TopPods({
  cpu,
  mem,
}: {
  cpu: ClusterPodSummary[];
  mem: ClusterPodSummary[];
}) {
  const [mode, setMode] = useState<"cpu" | "mem">("cpu");
  const rows = mode === "cpu" ? cpu : mem;
  const peak = Math.max(
    1e-9,
    ...rows.map((p) =>
      mode === "cpu"
        ? (p.cpu_usage_cores ?? 0)
        : (p.memory_working_set_bytes ?? 0),
    ),
  );
  return (
    <div className="rounded-xl border bg-card p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <Activity className="h-4 w-4 text-muted-foreground" />
          Top pods
        </h3>
        <div className="flex overflow-hidden rounded-md border text-[11px]">
          {(["cpu", "mem"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`px-2 py-1 ${
                mode === m
                  ? "bg-accent text-foreground"
                  : "text-muted-foreground hover:bg-accent/50"
              }`}
            >
              {m === "cpu" ? "CPU" : "Memory"}
            </button>
          ))}
        </div>
      </div>
      {rows.length === 0 ? (
        <p className="mt-4 text-xs text-muted-foreground">
          No live pod usage yet (waiting for the kubelet Summary API).
        </p>
      ) : (
        <div className="mt-3 space-y-2">
          {rows.map((p) => {
            const v =
              mode === "cpu"
                ? (p.cpu_usage_cores ?? 0)
                : (p.memory_working_set_bytes ?? 0);
            return (
              <div key={`${p.namespace}/${p.name}`}>
                <div className="flex items-baseline justify-between gap-2 text-[11px]">
                  <span className="truncate font-mono">{shortPodName(p)}</span>
                  <span className="shrink-0 tabular-nums text-muted-foreground">
                    {mode === "cpu" ? `${fmtCores(v)} c` : fmtBytes(v)}
                  </span>
                </div>
                <div className="mt-0.5">
                  <Bar
                    value={(v / peak) * 100}
                    color={mode === "cpu" ? EMERALD : SKY}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── hero live chart ───────────────────────────────────────────────────────────

export function HeroChart({
  history,
  cpuPct,
  memPct,
}: {
  history: HistPoint[];
  cpuPct: number | null;
  memPct: number | null;
}) {
  return (
    <div className="rounded-xl border bg-card p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold">
          <Activity className="h-4 w-4 text-muted-foreground" />
          Cluster load
          <span className="text-xs font-normal text-muted-foreground">
            · last ~3 min
          </span>
        </h3>
        <div className="flex items-center gap-4 text-xs">
          <span className="flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full"
              style={{ background: EMERALD }}
            />
            CPU{" "}
            <span
              className="font-semibold tabular-nums"
              style={{ color: EMERALD }}
            >
              {cpuPct == null ? "—" : `${Math.round(cpuPct)}%`}
            </span>
          </span>
          <span className="flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full"
              style={{ background: SKY }}
            />
            Mem{" "}
            <span className="font-semibold tabular-nums" style={{ color: SKY }}>
              {memPct == null ? "—" : `${Math.round(memPct)}%`}
            </span>
          </span>
        </div>
      </div>
      <div className="mt-3 h-56">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={history}
            margin={{ top: 6, right: 6, bottom: 0, left: -18 }}
          >
            <defs>
              <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={EMERALD} stopOpacity={0.45} />
                <stop offset="100%" stopColor={EMERALD} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="memGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={SKY} stopOpacity={0.4} />
                <stop offset="100%" stopColor={SKY} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#94a3b8"
              strokeOpacity={0.18}
              vertical={false}
            />
            <XAxis dataKey="i" hide />
            <YAxis
              domain={[0, 100]}
              width={42}
              tick={{ fill: "#94a3b8", fontSize: 10 }}
              tickFormatter={(v: number) => `${v}%`}
              stroke="#94a3b8"
              strokeOpacity={0.3}
            />
            <Tooltip
              isAnimationActive={false}
              formatter={(v) => `${Math.round(Number(v))}%`}
              labelFormatter={() => ""}
              contentStyle={{
                background: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: 8,
                fontSize: 12,
              }}
            />
            <Area
              type="monotone"
              dataKey="mem"
              name="Memory"
              stroke={SKY}
              strokeWidth={2}
              fill="url(#memGrad)"
              isAnimationActive={false}
              dot={false}
              connectNulls
              style={{ filter: "drop-shadow(0 1px 4px rgba(14,165,233,0.4))" }}
            />
            <Area
              type="monotone"
              dataKey="cpu"
              name="CPU"
              stroke={EMERALD}
              strokeWidth={2}
              fill="url(#cpuGrad)"
              isAnimationActive={false}
              dot={false}
              connectNulls
              style={{ filter: "drop-shadow(0 1px 4px rgba(16,185,129,0.45))" }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ── workload health ───────────────────────────────────────────────────────────

export function WorkloadHealth({
  workloads,
}: {
  workloads: ClusterWorkloadHealth[];
}) {
  return (
    <div className="rounded-xl border bg-card p-4 shadow-sm">
      <h3 className="flex items-center gap-1.5 text-sm font-semibold">
        <Layers className="h-4 w-4 text-muted-foreground" />
        Workloads
      </h3>
      {workloads.length === 0 ? (
        <p className="mt-4 text-xs text-muted-foreground">
          No workloads reported.
        </p>
      ) : (
        <div className="mt-3 space-y-1.5">
          {workloads.map((w) => (
            <div
              key={w.component}
              className="flex items-center justify-between gap-2 rounded-md px-1 py-1 text-xs"
            >
              <div className="flex min-w-0 items-center gap-2">
                <StatusChip status={w.status} />
                <span className="truncate font-medium">{w.component}</span>
                {w.kind && (
                  <span className="hidden text-[10px] text-muted-foreground sm:inline">
                    {w.kind}
                  </span>
                )}
              </div>
              <div className="flex shrink-0 items-center gap-3 text-muted-foreground">
                {w.restarts > 0 && (
                  <span
                    className="flex items-center gap-0.5 text-amber-600 dark:text-amber-400"
                    title={`${w.restarts} restarts`}
                  >
                    <RotateCcw className="h-3 w-3" />
                    {w.restarts}
                  </span>
                )}
                {w.jobs_running > 0 && (
                  <span
                    className="text-amber-600 dark:text-amber-400"
                    title={`${w.jobs_running} job${w.jobs_running === 1 ? "" : "s"} still running (e.g. a database replica joining) — not counted in ready / total`}
                  >
                    +{w.jobs_running} job{w.jobs_running === 1 ? "" : "s"}
                  </span>
                )}
                <span
                  className="tabular-nums text-foreground"
                  title={
                    w.source === "cnpg"
                      ? `ready ${w.ready} of ${w.total} wanted (from the CNPG Cluster)`
                      : w.source === "pods"
                        ? "pod count: the CNPG Cluster could not be read"
                        : undefined
                  }
                >
                  {w.ready}/{w.total}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── service roles (supervisor watchdog rollup) ─────────────────────────────────

function ServiceRoles({
  rows,
}: {
  rows: { service: string; status: string; since: string | null }[];
}) {
  return (
    <div className="rounded-xl border bg-card p-4 shadow-sm">
      <h3 className="flex items-center gap-1.5 text-sm font-semibold">
        <Layers className="h-4 w-4 text-muted-foreground" />
        Service roles
      </h3>
      <div className="mt-3 space-y-1.5">
        {rows.map((r) => (
          <div
            key={r.service}
            className="flex items-center justify-between gap-2 rounded-md px-1 py-1 text-xs"
          >
            <div className="flex min-w-0 items-center gap-2">
              <StatusChip status={r.status} />
              <span className="truncate font-medium">{r.service}</span>
            </div>
            {r.since && (
              <span className="shrink-0 text-[10px] text-muted-foreground">
                since {relTime(r.since)}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── live log pane ──────────────────────────────────────────────────────────
function LiveLogPane({ workload }: { workload: string }) {
  const [lines, setLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setLines([]);
    setError(null);
    setPaused(false);
    const ctrl = new AbortController();
    (async () => {
      try {
        for await (const line of streamApplianceWorkloadLogs(
          workload,
          ctrl.signal,
          200,
        )) {
          setLines((prev) => {
            const next = [...prev, line];
            // Cap at 2000 lines so a chatty pod doesn't blow up memory / DOM.
            if (next.length > 2000) next.splice(0, next.length - 2000);
            return next;
          });
        }
      } catch (e) {
        if (!ctrl.signal.aborted) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    return () => ctrl.abort();
  }, [workload]);

  // Auto-scroll to bottom unless the operator scrolled up (pause).
  useEffect(() => {
    if (paused) return;
    const el = boxRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines, paused]);

  const onScroll = () => {
    const el = boxRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 50;
    setPaused(!atBottom);
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
        <Activity className="h-3 w-3 text-emerald-500" />
        Live · {lines.length} line{lines.length === 1 ? "" : "s"}
        {paused && (
          <button
            type="button"
            onClick={() => setPaused(false)}
            className="ml-auto inline-flex items-center gap-1 rounded-md border bg-background px-2 py-0.5 text-[11px] hover:bg-accent"
            title="Jump to bottom + resume auto-scroll"
          >
            <Pause className="h-3 w-3" />
            Paused — click to resume
          </button>
        )}
      </div>
      {error && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      <div
        ref={boxRef}
        onScroll={onScroll}
        className="h-80 overflow-auto rounded-md border bg-muted/30 px-3 py-2 font-mono text-[11px] leading-tight"
      >
        {lines.length === 0 && !error ? (
          <span className="text-muted-foreground">Waiting for logs…</span>
        ) : (
          lines.map((line, i) => (
            <div key={i} className="whitespace-pre-wrap">
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ── main ──────────────────────────────────────────────────────────────────────

export function ClusterOverview({
  onViewPods,
}: { onViewPods?: () => void } = {}) {
  const { snapshot, history, connected } = useClusterHealthStream();

  // Identity + lifecycle for the header / reboot action (folds in the former
  // Console view). These hooks run unconditionally — the early returns below
  // come after them, so no hooks-rule violation.
  const { data: info } = useQuery({
    queryKey: ["appliance", "info"],
    queryFn: applianceApi.getInfo,
    staleTime: 20_000,
    refetchInterval: 30_000,
  });
  const { data: version } = useQuery({
    queryKey: ["version"],
    queryFn: versionApi.get,
    staleTime: 30_000,
  });

  const self = info?.self_appliance ?? null;
  const isApplianceHost = self?.deployment_kind === "appliance";

  const [confirmReboot, setConfirmReboot] = useState(false);
  const [rebooting, setRebooting] = useState(false);

  // ── log workload picker — tail a deployment/daemonset by its component ──
  // The operator picks a stable workload (api / worker / frontend / …) and
  // the backend resolves it to the current pod, so the stream survives pod
  // rolls and never exposes churny pod names (#416).
  const workloadNames = (snapshot?.workloads ?? []).map((w) => w.component);
  const defaultWorkload =
    workloadNames.find((n) => /api|control/i.test(n)) ?? workloadNames[0] ?? "";
  const [selectedWorkload, setSelectedWorkload] = useState<string>("");
  // Honor the explicit pick only while it's still a known workload; else fall
  // back to the default (deriving avoids a stale picker without an effect).
  const effectiveWorkload =
    selectedWorkload && workloadNames.includes(selectedWorkload)
      ? selectedWorkload
      : defaultWorkload;

  const doReboot = async () => {
    setRebooting(true);
    try {
      await applianceSystemApi.reboot();
      setConfirmReboot(false);
    } finally {
      setRebooting(false);
    }
  };

  if (snapshot === null) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
        <Radio className="mr-2 h-4 w-4 animate-pulse" />
        Connecting to the cluster…
      </div>
    );
  }

  if (!snapshot.available) {
    return (
      <div className="mx-auto max-w-2xl rounded-xl border border-dashed bg-muted/30 px-6 py-12 text-center">
        <Server className="mx-auto h-8 w-8 text-muted-foreground" />
        <p className="mt-3 text-sm font-medium">Cluster metrics unavailable</p>
        <p className="mt-1 text-xs text-muted-foreground">
          {snapshot.detail ??
            "The api ServiceAccount can't read the cluster yet."}
        </p>
      </div>
    );
  }

  const s = snapshot;
  const cpuPct = pct(s.cpu_usage_cores, s.cpu_capacity_cores);
  const memPct = pct(s.memory_working_set_bytes, s.memory_capacity_bytes);
  const healthyWorkloads = s.workloads.filter(
    (w) => w.status === "healthy",
  ).length;
  const cpuSpark = history.map((h) => h.cpu ?? 0);
  const memSpark = history.map((h) => h.mem ?? 0);

  // Pods KPI — exclude completed Jobs (Succeeded phase: migrate / helm-install
  // / CNPG bootstrap) from the denominator so a healthy box reads "10/10"
  // instead of an alarming "10/14". Finished Jobs still surface as a small
  // "N completed" sub-line; any pending / failed pods are noted too.
  const succeeded = s.pods_by_phase?.["Succeeded"] ?? 0;
  const pending = s.pods_by_phase?.["Pending"] ?? 0;
  const failed = s.pods_by_phase?.["Failed"] ?? 0;
  const activePods = Math.max(0, s.pods_total - succeeded);
  const podsSub = [
    succeeded > 0 ? `${succeeded} completed` : null,
    pending > 0 ? `${pending} pending` : null,
    failed > 0 ? `${failed} failed` : null,
  ]
    .filter(Boolean)
    .join(" · ");

  // ── derived identity values ─────────────────────────────────────────────
  const roles = deriveRoles(self);
  const hostIp =
    self?.node_ip ?? s.nodes.find((n) => n.internal_ip)?.internal_ip ?? null;

  // role_health → flat list of {service, status, since}; rendered only when
  // non-empty (a control-plane appliance reports none — no empty placeholder).
  const roleHealthRows = self
    ? Object.entries(self.role_health).map(([service, v]) => ({
        service,
        status: (v?.status as string | undefined) ?? "unknown",
        since: (v?.since as string | undefined) ?? null,
      }))
    : [];

  return (
    <div className="space-y-4">
      {/* Identity header */}
      <div className="rounded-xl border bg-card p-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="flex items-center gap-2 text-base font-semibold">
            <Boxes className="h-4 w-4 text-muted-foreground" />
            Cluster
          </h2>
          <Chip
            icon={Radio}
            color={connected ? EMERALD : AMBER}
            title={connected ? "Streaming live" : "Reconnecting"}
          >
            {connected ? "LIVE" : "reconnecting…"}
          </Chip>
          {self?.last_seen_at && (
            <span className="ml-auto flex items-center gap-1 text-[11px] text-muted-foreground">
              <Clock className="h-3 w-3" />
              supervisor seen {relTime(self.last_seen_at)}
            </span>
          )}
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          {roles.map((r) => (
            <Chip key={r} icon={Layers} color={VIOLET}>
              {r}
            </Chip>
          ))}
          <Chip icon={Server}>
            {info?.appliance_hostname ?? s.nodes[0]?.name ?? "unknown"}
          </Chip>
          {hostIp && (
            <Chip icon={Network} title="Host IP">
              <span className="font-mono">{hostIp}</span>
            </Chip>
          )}
          {(self?.installed_appliance_version ?? info?.appliance_version) && (
            <Chip icon={Tag} title="Appliance OS version">
              OS {self?.installed_appliance_version ?? info?.appliance_version}
            </Chip>
          )}
          {version?.version && (
            <Chip icon={Tag} title="SpatiumDDI app version">
              app {version.version}
            </Chip>
          )}

          {/* A/B slot — appliance only */}
          {self?.current_slot && (
            <Chip
              icon={HardDrive}
              color={self.is_trial_boot ? AMBER : EMERALD}
              title={`Running slot ${self.current_slot}; durable default ${self.durable_default ?? "?"}`}
            >
              slot {self.current_slot}
              {self.durable_default && (
                <span className="opacity-70">
                  · default {self.durable_default}
                </span>
              )}
            </Chip>
          )}
          {self?.is_trial_boot && (
            <Chip
              color={AMBER}
              title="Running slot differs from durable default"
            >
              TRIAL BOOT
            </Chip>
          )}
          {self?.last_upgrade_state && (
            <Chip
              color={upgradeStateColor(self.last_upgrade_state)}
              title="Last A/B slot upgrade state"
            >
              upgrade: {self.last_upgrade_state}
            </Chip>
          )}

          {/* Cluster status */}
          <Chip
            color={s.nodes_ready === s.nodes_total ? EMERALD : ROSE}
            title="Nodes ready / total"
          >
            {s.nodes_ready}/{s.nodes_total} nodes
            {s.is_ha && <span className="opacity-70">· HA</span>}
          </Chip>
          {s.kubelet_version && (
            <Chip title="Kubelet version">
              <span className="font-mono">{s.kubelet_version}</span>
            </Chip>
          )}
          {!s.metrics_available && (
            <Chip color={AMBER} title="kubelet Summary API not reporting yet">
              live usage unavailable
            </Chip>
          )}
          {/*
            #983 Phase 2 item 6 — which transport served the kubelet Summary
            API. This chip is the whole reason the fallback exists: without it
            an operator has no way to know whether the narrow ``nodes/stats``
            grant works on their cluster, and the broad ``nodes/proxy`` grant
            stays forever because nothing ever said it could go.
          */}
          <KubeletTransportChip transport={s.kubelet_transport} />
          {self?.state && (
            <Chip
              color={self.state === "approved" ? EMERALD : AMBER}
              title="Supervisor approval / pairing lifecycle"
            >
              {self.state}
            </Chip>
          )}
        </div>

        {!self && (
          <p className="mt-3 text-[11px] text-muted-foreground">
            No local supervisor registered — showing cluster health only. Slot,
            lifecycle, and per-role chips appear once the local appliance's
            supervisor is approved.
          </p>
        )}
      </div>

      {/* KPI ribbon */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <KpiTile
          icon={Cpu}
          label="CPU"
          value={cpuPct == null ? "—" : `${Math.round(cpuPct)}%`}
          sub={`${fmtCores(s.cpu_usage_cores)} / ${fmtCores(s.cpu_capacity_cores)} c`}
          accent={EMERALD}
        >
          <Sparkline data={cpuSpark} color={EMERALD} max={100} />
        </KpiTile>
        <KpiTile
          icon={MemoryStick}
          label="Memory"
          value={memPct == null ? "—" : `${Math.round(memPct)}%`}
          sub={`${fmtBytes(s.memory_working_set_bytes)} / ${fmtBytes(s.memory_capacity_bytes)}`}
          accent={SKY}
        >
          <Sparkline data={memSpark} color={SKY} max={100} />
        </KpiTile>
        <KpiTile
          icon={Server}
          label="Nodes ready"
          value={`${s.nodes_ready}/${s.nodes_total}`}
          accent={s.nodes_ready === s.nodes_total ? EMERALD : ROSE}
        >
          <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
            <CheckCircle2 className="h-3 w-3" style={{ color: EMERALD }} />
            {s.control_plane_nodes} control-plane
          </div>
        </KpiTile>
        <KpiTile
          icon={Boxes}
          label="Pods running"
          value={`${s.pods_running}/${activePods}`}
          accent={s.pods_running >= activePods ? EMERALD : ROSE}
        >
          <div
            className="truncate text-[11px] text-muted-foreground"
            title={Object.entries(s.pods_by_phase)
              .map(([k, v]) => `${k} ${v}`)
              .join(" · ")}
          >
            {podsSub || "all running"}
          </div>
        </KpiTile>
        <KpiTile
          icon={Database}
          label="Workloads"
          value={`${healthyWorkloads}/${s.workloads.length}`}
          sub="healthy"
          accent={healthyWorkloads === s.workloads.length ? EMERALD : AMBER}
        >
          <div className="flex flex-wrap gap-0.5">
            {s.workloads.slice(0, 14).map((w) => (
              <span
                key={w.component}
                className="h-1.5 w-1.5 rounded-full"
                title={`${w.component}: ${w.status}`}
                style={{
                  background:
                    w.status === "healthy"
                      ? EMERALD
                      : w.status === "degraded"
                        ? AMBER
                        : ROSE,
                }}
              />
            ))}
          </div>
        </KpiTile>
      </div>

      {/* Hero live chart */}
      <HeroChart history={history} cpuPct={cpuPct} memPct={memPct} />

      {/* Nodes + cluster DNS (#985) */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {s.nodes.map((n) => (
          <NodeCard key={n.name} node={n} />
        ))}
        <ClusterDnsCard dns={s.cluster_dns} />
      </div>

      {/* Workloads + top pods (+ service roles when the supervisor reports them) */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <WorkloadHealth workloads={s.workloads} />
        <TopPods cpu={s.top_pods_cpu} mem={s.top_pods_mem} />
        {roleHealthRows.length > 0 && <ServiceRoles rows={roleHealthRows} />}
      </div>

      {/* Live log pane */}
      <div className="rounded-xl border bg-card p-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="flex items-center gap-1.5 text-sm font-semibold">
            <ScrollText className="h-4 w-4 text-muted-foreground" />
            Live log
          </h3>
          {workloadNames.length > 0 && (
            <select
              value={effectiveWorkload}
              onChange={(e) => setSelectedWorkload(e.target.value)}
              className="rounded-md border bg-background px-2 py-1 text-xs"
            >
              {workloadNames.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="mt-3">
          {effectiveWorkload ? (
            <LiveLogPane key={effectiveWorkload} workload={effectiveWorkload} />
          ) : (
            <p className="text-xs text-muted-foreground">
              No workloads to tail yet.
            </p>
          )}
        </div>
      </div>

      {/* Action bar */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setConfirmReboot(true)}
          disabled={!isApplianceHost}
          title={
            isApplianceHost
              ? "Reboot the appliance host OS"
              : "Reboot is only available on appliance hosts"
          }
          className="inline-flex items-center gap-1.5 rounded-md border border-destructive/40 bg-background px-3 py-1.5 text-sm font-medium text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Power className="h-3.5 w-3.5" />
          Reboot host
        </button>
        {onViewPods && (
          <button
            type="button"
            onClick={onViewPods}
            className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-accent"
          >
            <Boxes className="h-3.5 w-3.5" />
            View all pods →
          </button>
        )}
      </div>

      <ConfirmModal
        open={confirmReboot}
        title="Reboot appliance?"
        message={
          <span>
            The host will power-cycle in ~10 seconds. Existing DHCP leases keep
            their state (DB-backed); DNS zones reload from the served config;
            the web UI will be unreachable for ~1 minute.
          </span>
        }
        confirmLabel="Reboot now"
        tone="destructive"
        requireCheckboxLabel="I understand the appliance will go offline for ~1 minute."
        onClose={() => !rebooting && setConfirmReboot(false)}
        onConfirm={() => void doReboot()}
        loading={rebooting}
      />
    </div>
  );
}
