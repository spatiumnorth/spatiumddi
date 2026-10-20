/**
 * Built-in dashboard charts for DNS queries and DHCP traffic.
 *
 * Data comes from the agent-driven `metric_sample` tables via
 * `metricsApi.{dnsTimeseries,dhcpTimeseries}`. The cards render empty
 * states that explain where data comes from when there is none — new
 * installs will land on the dashboard before any agent has reported,
 * and we don't want "no data" to look like a bug.
 *
 * Selectors:
 *   - window picker (1h / 6h / 24h / 7d)
 *   - server picker ("All servers" default, or scope to one)
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Activity, Network } from "lucide-react";

import {
  metricsApi,
  type DHCPServer,
  type DNSServer,
  type MetricsWindow,
} from "@/lib/api";

const WINDOWS: { key: MetricsWindow; label: string }[] = [
  { key: "1h", label: "1h" },
  { key: "6h", label: "6h" },
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
];

const ALL_SERVERS = "__all__";

// Tick labels key off the WINDOW, not the bucket size: a 24 h window
// aggregated into 5 min buckets is still one day of data, and stamping
// the date on every tick there is noise. Only the multi-day window
// needs it to disambiguate.
function formatT(iso: string, win: MetricsWindow): string {
  const d = new Date(iso);
  if (win === "7d") {
    return d.toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// Rates divide by the seconds a point ACTUALLY covers, not by the nominal
// bucket width (#942). The newest 5-minute bucket has only had one or two
// 60 s samples reported into it, so dividing its partial sum by a full 300
// drew a 70%+ phantom dip at the right-hand edge of every chart — the
// leading bucket is partial for the same reason, and so is any bucket an
// agent was down for. Falls back to the nominal width for a server too old
// to report the field.
function perSecond(value: number, coveredSeconds: number): number {
  if (coveredSeconds <= 0) return 0;
  return +(value / coveredSeconds).toFixed(2);
}

function WindowPicker({
  value,
  onChange,
}: {
  value: MetricsWindow;
  onChange: (w: MetricsWindow) => void;
}) {
  return (
    <div className="flex items-center gap-0.5 rounded-md border bg-muted/40 p-0.5 text-[11px]">
      {WINDOWS.map((w) => (
        <button
          key={w.key}
          type="button"
          onClick={() => onChange(w.key)}
          className={
            "rounded px-2 py-0.5 transition-colors " +
            (value === w.key
              ? "bg-background font-semibold shadow-sm"
              : "text-muted-foreground hover:bg-background/60")
          }
        >
          {w.label}
        </button>
      ))}
    </div>
  );
}

function ServerPicker({
  value,
  onChange,
  servers,
}: {
  value: string;
  onChange: (id: string) => void;
  servers: { id: string; name: string }[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-md border bg-background px-2 py-0.5 text-[11px] hover:bg-accent/40 focus:outline-none focus:ring-1 focus:ring-ring"
    >
      <option value={ALL_SERVERS}>All servers</option>
      {servers.map((s) => (
        <option key={s.id} value={s.id}>
          {s.name}
        </option>
      ))}
    </select>
  );
}

export function DNSQueryRateCard({
  dnsServers = [],
}: {
  dnsServers?: DNSServer[];
}) {
  const [win, setWin] = useState<MetricsWindow>("24h");
  const [serverId, setServerId] = useState<string>(ALL_SERVERS);
  const scopedId = serverId === ALL_SERVERS ? undefined : serverId;
  const { data, isLoading, isError } = useQuery({
    queryKey: ["metrics", "dns", win, scopedId ?? ""],
    queryFn: () =>
      metricsApi.dnsTimeseries({ window: win, server_id: scopedId }),
    refetchInterval: 60_000,
  });

  const points = (data?.points ?? []).map((p) => ({
    t: formatT(p.t, win),
    queries: perSecond(
      p.queries_total,
      p.covered_seconds || (data?.bucket_seconds ?? 60),
    ),
    noerror: perSecond(
      p.noerror,
      p.covered_seconds || (data?.bucket_seconds ?? 60),
    ),
    nxdomain: perSecond(
      p.nxdomain,
      p.covered_seconds || (data?.bucket_seconds ?? 60),
    ),
    servfail: perSecond(
      p.servfail,
      p.covered_seconds || (data?.bucket_seconds ?? 60),
    ),
  }));

  // The API returns one zero-filled sample per bucket even when no
  // agent has reported, so ``points.length`` is non-zero on a fresh
  // install. Fall through to the empty state unless something is
  // actually plotted — an all-zero series renders a degenerate flat
  // line that reads as a bug.
  const hasData = points.some(
    (p) =>
      (p.queries || 0) +
        (p.noerror || 0) +
        (p.nxdomain || 0) +
        (p.servfail || 0) >
      0,
  );

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-blue-500" />
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            DNS Query Rate
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <ServerPicker
            value={serverId}
            onChange={setServerId}
            servers={dnsServers}
          />
          <WindowPicker value={win} onChange={setWin} />
        </div>
      </div>
      {/* Collapse to a slim strip when there is nothing to plot (#942).
          A full 256 px of empty state pushed the panels that DO have
          something to say below the fold — and on a fresh install, or any
          deployment with no agent reporting counters, that is the normal
          case rather than the exception. */}
      <div className={hasData || isLoading ? "h-64 p-3" : "px-4 py-3"}>
        {isLoading ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            Loading…
          </div>
        ) : isError ? (
          <div className="text-xs text-muted-foreground">
            DNS query rate is unavailable. Your role may not include read access
            to DNS.
          </div>
        ) : !hasData ? (
          <div className="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
            <span>No query data yet.</span>
            <span className="text-[11px]">
              BIND9 agents report counters every 60&nbsp;s.
            </span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={points}
              margin={{ top: 5, right: 12, left: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
              <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={32} />
              <YAxis
                tick={{ fontSize: 10 }}
                width={44}
                label={{
                  value: "qps",
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
              <Line
                type="monotone"
                dataKey="queries"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
                name="Total"
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
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

export function DHCPTrafficCard({
  dhcpServers = [],
  pinnedServerId,
}: {
  dhcpServers?: DHCPServer[];
  // #195 — when set (e.g. from the DHCP server detail modal's Stats tab),
  // the card is scoped to this one server and the server picker is hidden.
  pinnedServerId?: string;
}) {
  const [win, setWin] = useState<MetricsWindow>("24h");
  const [serverId, setServerId] = useState<string>(ALL_SERVERS);
  const scopedId =
    pinnedServerId ?? (serverId === ALL_SERVERS ? undefined : serverId);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["metrics", "dhcp", win, scopedId ?? ""],
    queryFn: () =>
      metricsApi.dhcpTimeseries({ window: win, server_id: scopedId }),
    refetchInterval: 60_000,
  });

  const points = (data?.points ?? []).map((p) => ({
    t: formatT(p.t, win),
    discover: perSecond(
      p.discover,
      p.covered_seconds || (data?.bucket_seconds ?? 60),
    ),
    request: perSecond(
      p.request,
      p.covered_seconds || (data?.bucket_seconds ?? 60),
    ),
    ack: perSecond(p.ack, p.covered_seconds || (data?.bucket_seconds ?? 60)),
    nak: perSecond(p.nak, p.covered_seconds || (data?.bucket_seconds ?? 60)),
  }));

  // The API returns one zero-filled sample per bucket even when no
  // agent has reported, so ``points.length`` is non-zero on a fresh
  // install. Fall through to the empty state unless something is
  // actually plotted — an all-zero series renders a degenerate flat
  // plot that reads as a bug.
  const hasData = points.some(
    (p) =>
      (p.discover || 0) + (p.request || 0) + (p.ack || 0) + (p.nak || 0) > 0,
  );

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Network className="h-3.5 w-3.5 text-violet-500" />
          <h3 className="text-xs font-semibold uppercase tracking-wider">
            DHCP Traffic
          </h3>
        </div>
        <div className="flex items-center gap-2">
          {!pinnedServerId && (
            <ServerPicker
              value={serverId}
              onChange={setServerId}
              servers={dhcpServers}
            />
          )}
          <WindowPicker value={win} onChange={setWin} />
        </div>
      </div>
      {/* Collapse to a slim strip when there is nothing to plot (#942).
          A full 256 px of empty state pushed the panels that DO have
          something to say below the fold — and on a fresh install, or any
          deployment with no agent reporting counters, that is the normal
          case rather than the exception. */}
      <div className={hasData || isLoading ? "h-64 p-3" : "px-4 py-3"}>
        {isLoading ? (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            Loading…
          </div>
        ) : isError ? (
          <div className="text-xs text-muted-foreground">
            DHCP traffic is unavailable. Your role may not include read access
            to DHCP servers.
          </div>
        ) : !hasData ? (
          <div className="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
            <span>No DHCP traffic yet.</span>
            <span className="text-[11px]">
              Kea agents report packet counters every 60&nbsp;s.
            </span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={points}
              margin={{ top: 5, right: 12, left: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
              <XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={32} />
              <YAxis
                tick={{ fontSize: 10 }}
                width={44}
                label={{
                  value: "pkt/s",
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
              <Area
                type="monotone"
                dataKey="discover"
                stackId="1"
                stroke="#8b5cf6"
                fill="#8b5cf6"
                fillOpacity={0.35}
                name="DISCOVER"
              />
              <Area
                type="monotone"
                dataKey="request"
                stackId="1"
                stroke="#3b82f6"
                fill="#3b82f6"
                fillOpacity={0.35}
                name="REQUEST"
              />
              <Area
                type="monotone"
                dataKey="ack"
                stackId="1"
                stroke="#10b981"
                fill="#10b981"
                fillOpacity={0.35}
                name="ACK"
              />
              <Area
                type="monotone"
                dataKey="nak"
                stackId="1"
                stroke="#ef4444"
                fill="#ef4444"
                fillOpacity={0.35}
                name="NAK"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
