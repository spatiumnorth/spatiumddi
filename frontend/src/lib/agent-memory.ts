/** #4193 — how an agent's reported memory reads on the server list and in the
 *  server modal. Kept apart from the components so it can be tested on its own. */
import type { AgentMemoryStatus } from "@/lib/api";
import { formatBytes } from "@/lib/spool-status";

/** Above this share of the container limit the figure turns amber. */
export const MEMORY_WARN_PERCENT = 80;

export interface MemoryUsage {
  /** Text for the list cell: "612.0 MB / 1.0 GB", "612.0 MB" with no limit,
   *  "—" when the agent has not reported usage. */
  text: string;
  /** Percent of the limit, or null when either figure is unknown. */
  percent: number | null;
  warn: boolean;
}

export function memoryUsage(
  status: AgentMemoryStatus | null | undefined,
): MemoryUsage {
  const used = status?.used_bytes;
  if (used == null) return { text: "—", percent: null, warn: false };
  const limit = status?.limit_bytes;
  if (!limit) return { text: formatBytes(used), percent: null, warn: false };
  const percent = (used / limit) * 100;
  return {
    text: `${formatBytes(used)} / ${formatBytes(limit)}`,
    percent,
    warn: percent > MEMORY_WARN_PERCENT,
  };
}

/** A byte count, or "—" for a figure the agent did not report. */
export function bytesOrDash(n: number | null | undefined): string {
  return n == null ? "—" : formatBytes(n);
}
