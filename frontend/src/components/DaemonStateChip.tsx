import type { DaemonStateFields } from "@/lib/api";

/**
 * Chip surfacing the daemon state an agent reports on its heartbeat (#1067).
 *
 * Every other signal on a server row reads healthy while the daemon is not
 * running. A DNS agent that is waiting for its first bundle registers,
 * heartbeats every 30 s and never starts `named`, so `status` is `active`,
 * `last_seen_at` is seconds old and the config-apply verdict is whatever it
 * was last time — the agent SAYS so on every heartbeat
 * (`daemon: {status: "degraded", reason: "start deferred, no bundle yet"}`),
 * and before #1067 the control plane dropped the field. This chip is where
 * that state shows.
 *
 * Renders nothing on `ok` and nothing on `null`. `null` means the agent has
 * never reported a daemon state — a pre-#1061 agent, or an agentless driver
 * with no daemon of its own — and that is unknown, not healthy (the #882
 * posture). Anything that is not `ok` renders as not serving: the vocabulary
 * is the agent's, and a word this UI has not seen is still a state the agent
 * chose to report.
 */

function sinceLabel(since: Date): string {
  const mins = Math.max(0, Math.round((Date.now() - since.getTime()) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min`;
  const hours = Math.floor(mins / 60);
  return `${hours} h ${mins % 60} min`;
}

function explain(server: Partial<DaemonStateFields>): string {
  const status = server.daemon_status ?? "";
  const since = server.daemon_status_since
    ? new Date(server.daemon_status_since)
    : null;
  return [
    `The agent reports its daemon is ${status.replace(/_/g, " ")}: it is heartbeating, but not serving.`,
    server.daemon_reason ? `\n\nAgent reported: ${server.daemon_reason}` : "",
    since
      ? `\n\nSince: ${since.toLocaleString()} (${sinceLabel(since)})`
      : "",
  ].join("");
}

export function DaemonStateChip({
  server,
  className = "",
}: {
  server: Partial<DaemonStateFields>;
  className?: string;
}) {
  const status = server.daemon_status;
  if (!status || status === "ok") return null;

  return (
    <span
      className={`inline-flex items-center rounded bg-rose-500/15 px-1.5 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-400 ${className}`}
      title={explain(server)}
    >
      Daemon {status.replace(/_/g, " ")}
    </span>
  );
}

/**
 * Full-width version for a server-detail view, above the status grid: every
 * field below it reports healthy while the daemon is down, so this has to be
 * the first thing read (the same reason the config-apply banner sits there).
 */
export function DaemonStateBanner({
  server,
}: {
  server: Partial<DaemonStateFields>;
}) {
  const status = server.daemon_status;
  if (!status || status === "ok") return null;
  const since = server.daemon_status_since
    ? new Date(server.daemon_status_since)
    : null;

  return (
    <div className="rounded border border-rose-600/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-800 dark:text-rose-300">
      <div className="font-medium">Daemon {status.replace(/_/g, " ")}</div>
      <p className="mt-0.5 opacity-90">
        The agent is heartbeating, but reports that its daemon is not
        serving. Reachability, the health check and the last-seen stamp all
        read normal in this state; only this report says otherwise.
      </p>
      {server.daemon_reason && (
        <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-black/5 p-2 font-mono text-[11px] dark:bg-white/5">
          {server.daemon_reason}
        </pre>
      )}
      {since && (
        <div className="mt-1.5 opacity-75">
          since {since.toLocaleString()} ({sinceLabel(since)})
        </div>
      )}
    </div>
  );
}
