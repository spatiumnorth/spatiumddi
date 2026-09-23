import type { AgentSpoolStatus } from "@/lib/api";
import { formatAge, formatBytes, spoolState } from "@/lib/spool-status";

/**
 * Chip surfacing an agent's durable push spool (#1077).
 *
 * During a control-plane outage the DNS / DHCP agents queue their query
 * logs, activity logs, metrics and Kea lease events on disk and replay them
 * in order on reconnect. Without this chip the dashboard just shows a hole
 * that silently fills in later — or, if the spool hit its size cap, a hole
 * that never will.
 *
 * Renders nothing when the spool is empty and nothing when `spool_status` is
 * `null` (the agent has never reported one — pre-#1077, or agentless):
 * unknown is not the same as healthy, and a green badge would claim the
 * latter.
 */
export function SpoolChip({
  server,
  className = "",
}: {
  server: { spool_status?: AgentSpoolStatus | null };
  className?: string;
}) {
  const status = server.spool_status ?? null;
  const state = spoolState(status);
  if (state.kind === "none" || !status) return null;

  const perStream = Object.entries(status.streams ?? {})
    .filter(([, s]) => s.bytes > 0 || s.trimmed_entries_total > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, s]) => {
      const age = formatAge(s.oldest_at);
      const bits = [`${formatBytes(s.bytes)} queued`];
      if (age) bits.push(`oldest ${age} ago`);
      if (s.trimmed_entries_total > 0)
        bits.push(
          `${s.trimmed_entries_total} batches / ${formatBytes(s.trimmed_bytes_total)} trimmed since agent state was created`,
        );
      return `• ${name}: ${bits.join(", ")}`;
    });

  if (state.kind === "trimmed") {
    const leases = state.streams.includes("lease_events");
    const title = [
      "This agent's push spool discarded queued batches in the last 24 h — either it reached its size cap while the control plane was unreachable, or the control plane kept refusing a batch. That data will never arrive.",
      leases
        ? "\n\nKea lease events were trimmed: those leases have no IPAM mirror row and no DDNS record until the clients renew."
        : "",
      state.streams.length
        ? `\n\nTrimmed in the last 24 h: ${state.streams.join(", ")}`
        : "",
      `\nLast trim: ${new Date(state.lastTrimAt).toLocaleString()}`,
      perStream.length ? `\n\n${perStream.join("\n")}` : "",
    ].join("");
    return (
      <span
        className={`inline-flex items-center rounded bg-rose-500/15 px-1.5 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-400 ${className}`}
        title={title}
      >
        Spool trimmed
      </span>
    );
  }

  const age = formatAge(state.oldestAt);
  const title = [
    "The control plane was unreachable and this agent queued what it could not deliver. It is replaying the backlog in order, with the original timestamps, so charts and logs for the gap will fill in.",
    `\n\n${state.entries} batches, ${formatBytes(state.bytes)} of ${formatBytes(status.cap_bytes)} cap`,
    age ? `, oldest queued ${age} ago` : "",
    perStream.length ? `\n\n${perStream.join("\n")}` : "",
  ].join("");
  return (
    <span
      className={`inline-flex items-center rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400 ${className}`}
      title={title}
    >
      Replaying {formatBytes(state.bytes)} backlog
    </span>
  );
}
