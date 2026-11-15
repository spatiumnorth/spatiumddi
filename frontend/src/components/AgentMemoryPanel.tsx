import { useQuery } from "@tanstack/react-query";
import type { AgentMemoryHistory, AgentMemoryStatus } from "@/lib/api";
import { bytesOrDash, memoryUsage } from "@/lib/agent-memory";

/** A small inline-SVG line of the container's used memory (#4193). Draws
 *  nothing for fewer than two points. */
export function MemorySparkline({
  values,
  limit,
}: {
  values: number[];
  limit?: number | null;
}) {
  if (values.length < 2) return null;
  const W = 240;
  const H = 36;
  const top = Math.max(limit ?? 0, ...values) || 1;
  const pts = values
    .map(
      (v, i) =>
        `${((i / (values.length - 1)) * W).toFixed(1)},${(H - (v / top) * (H - 2) - 1).toFixed(1)}`,
    )
    .join(" ");
  return (
    <svg
      role="img"
      aria-label="Container memory over the last hours"
      data-testid="memory-sparkline"
      viewBox={`0 0 ${W} ${H}`}
      className="h-9 w-full text-primary"
      preserveAspectRatio="none"
    >
      <polyline
        points={pts}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

/**
 * The server modal's memory block (#4193): container used / peak / limit,
 * the daemon's and the agent's own RSS, and a sparkline from the metric
 * samples. `fetchHistory` is the DNS or DHCP client call.
 */
export function AgentMemoryPanel({
  serverId,
  status,
  daemonLabel,
  fetchHistory,
  queryKeyPrefix,
}: {
  serverId: string;
  status: AgentMemoryStatus | null | undefined;
  /** "named", "Kea", … — what the daemon RSS row is called. */
  daemonLabel: string;
  fetchHistory: (serverId: string) => Promise<AgentMemoryHistory>;
  queryKeyPrefix: string;
}) {
  const { data } = useQuery({
    queryKey: [queryKeyPrefix, "memory-history", serverId],
    queryFn: () => fetchHistory(serverId),
    refetchInterval: 60_000,
  });
  const m = memoryUsage(status);
  const values = (data?.points ?? [])
    .map((p) => p.used_bytes)
    .filter((v): v is number => v != null);
  return (
    <div className="rounded-md border p-3" data-testid="agent-memory-panel">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Memory
        </span>
        {m.percent != null && (
          <span
            className={`text-xs tabular-nums ${m.warn ? "font-medium text-amber-700 dark:text-amber-400" : "text-muted-foreground"}`}
          >
            {Math.round(m.percent)}% of limit
          </span>
        )}
      </div>
      {!status ? (
        <p className="text-xs text-muted-foreground">
          Not reported by this agent. An agent older than this feature, or an
          agentless driver, sends no memory figures.
        </p>
      ) : (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm sm:grid-cols-3">
          <MemRow
            label="Container used"
            value={bytesOrDash(status.used_bytes)}
          />
          <MemRow
            label="Container peak"
            value={bytesOrDash(status.peak_bytes)}
          />
          <MemRow
            label="Container limit"
            value={
              status.limit_bytes ? bytesOrDash(status.limit_bytes) : "no limit"
            }
          />
          <MemRow
            label={`${daemonLabel} RSS`}
            value={bytesOrDash(status.daemon_rss_bytes)}
          />
          <MemRow
            label="Agent RSS"
            value={bytesOrDash(status.agent_rss_bytes)}
          />
        </dl>
      )}
      {/* No current report means no sparkline: the history rows outlive the
          report (a replaced or wedged agent), and a line drawn under "Not
          reported" reads as live data. */}
      {status && (
        <div className="mt-2">
          <MemorySparkline values={values} limit={status.limit_bytes} />
        </div>
      )}
    </div>
  );
}

function MemRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] text-muted-foreground">{label}</dt>
      <dd className="tabular-nums">{value}</dd>
    </div>
  );
}
