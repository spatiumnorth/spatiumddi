import type { AgentSpoolStatus } from "@/lib/api";

/**
 * Reading of an agent's push spool (#1077), shared by the chip and its test.
 *
 * Mirrors `recently_trimmed_streams` in
 * `backend/app/services/agents/spool_status.py`: a trim is "recent" for 24 h,
 * which is also the window the `agent_spool_trimmed` alert fires for, so the
 * chip and the alert cannot disagree about whether a server lost data.
 */

export const TRIM_RECENT_MS = 24 * 60 * 60 * 1000;

export type SpoolState =
  /** Unknown (never reported) or healthy — render nothing. */
  | { kind: "none" }
  /** Queued pushes the control plane has not received yet. */
  | { kind: "backlog"; bytes: number; entries: number; oldestAt: string | null }
  /** The spool hit its cap and dropped data within the last 24 h. */
  | {
      kind: "trimmed";
      streams: string[];
      bytes: number;
      lastTrimAt: string;
    };

function isRecent(ts: string | null | undefined, now: number): boolean {
  if (!ts) return false;
  const t = Date.parse(ts);
  return Number.isFinite(t) && now - t <= TRIM_RECENT_MS;
}

export function spoolState(
  status: AgentSpoolStatus | null | undefined,
  now: number = Date.now(),
): SpoolState {
  if (!status) return { kind: "none" };
  // A trim outranks a backlog: data is gone, and "still replaying" would read
  // as "nothing lost, just wait".
  if (isRecent(status.last_trim_at, now)) {
    const streams = Object.entries(status.streams ?? {})
      .filter(([, s]) => isRecent(s.last_trim_at, now))
      .map(([name]) => name)
      .sort();
    return {
      kind: "trimmed",
      streams,
      bytes: status.bytes ?? 0,
      lastTrimAt: status.last_trim_at as string,
    };
  }
  if ((status.bytes ?? 0) > 0) {
    return {
      kind: "backlog",
      bytes: status.bytes,
      entries: status.entries ?? 0,
      oldestAt: status.oldest_at,
    };
  }
  return { kind: "none" };
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function formatAge(fromIso: string | null, now: number = Date.now()) {
  if (!fromIso) return null;
  const t = Date.parse(fromIso);
  if (!Number.isFinite(t)) return null;
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 90) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}
