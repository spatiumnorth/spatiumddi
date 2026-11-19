// Supervisor heartbeat freshness (#2259). Everything Fleet shows about an
// appliance's roles, service health, firewall and storage is the LAST
// report; once the supervisor stops heartbeating that report is history,
// not state. The supervisor beats every 30 s (HEARTBEAT_INTERVAL_SECONDS),
// and the backend treats 90 s as "online" (agent_cmd.ONLINE_STALE_SECONDS),
// so ~3 missed beats is the shared bound.
export const HEARTBEAT_INTERVAL_MS = 30_000;
export const HEARTBEAT_STALE_AFTER_MS = 3 * HEARTBEAT_INTERVAL_MS;

/** True when the node last reported long enough ago that its reported
 *  state should no longer read as current. A node that never heartbeated
 *  (null) is not "stale" — there is no report to be out of date. */
export function isHeartbeatStale(
  lastSeenAt: string | null | undefined,
  now: number = Date.now(),
): boolean {
  if (!lastSeenAt) return false;
  const seen = new Date(lastSeenAt).getTime();
  if (Number.isNaN(seen)) return false;
  return now - seen > HEARTBEAT_STALE_AFTER_MS;
}

/** "4m", "3h", "2d" — how long the node has been silent. */
export function silenceLabel(
  lastSeenAt: string,
  now: number = Date.now(),
): string {
  const ms = Math.max(0, now - new Date(lastSeenAt).getTime());
  if (ms < 3_600_000) return `${Math.max(1, Math.floor(ms / 60_000))}m`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h`;
  return `${Math.floor(ms / 86_400_000)}d`;
}
