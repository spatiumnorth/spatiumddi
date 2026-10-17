/** #2021 — can a per-box slot upgrade still be cancelled?
 *
 *  Mirrors the backend's ``host_upgrade_activity``
 *  (``api/v1/appliance/supervisor.py``); keep the two in step. A cancel
 *  cannot stop an apply the runner has claimed (the host never aborts a
 *  running apply) and cannot un-stage a written slot (clearing does not
 *  disarm next-boot), so the console must not offer one. */
export const UPGRADE_INFLIGHT_STALE_MS = 300_000;

/** Progress steps that are not the runner working on the current apply:
 *  the runner writes ``queued`` the instant it claims the trigger, so an
 *  in-flight state with one of these (or none) is an unclaimed trigger,
 *  which the clear's host command does remove. */
const NOT_LIVE_STEPS = new Set(["", "failed", "reboot-pending"]);

export type HostUpgradeActivity = "applying" | "staged";

type UpgradeRowFields = {
  current_slot?: string | null;
  last_upgrade_state?: string | null;
  last_upgrade_state_at?: string | null;
  last_upgrade_progress?: {
    step?: string | null;
    staged_slot?: string | null;
    staged_boot_id?: string | null;
  } | null;
};

export function hostUpgradeActivity(
  row: UpgradeRowFields,
  now: number = Date.now(),
): HostUpgradeActivity | null {
  const progress = row.last_upgrade_progress ?? null;
  const step = typeof progress?.step === "string" ? progress.step : "";
  if (row.last_upgrade_state === "in-flight") {
    if (NOT_LIVE_STEPS.has(step)) return null;
    if (!row.last_upgrade_state_at) return "applying";
    const at = new Date(row.last_upgrade_state_at).getTime();
    if (Number.isNaN(at)) return "applying";
    return now - at <= UPGRADE_INFLIGHT_STALE_MS ? "applying" : null;
  }
  if (
    row.last_upgrade_state === "done" &&
    step === "reboot-pending" &&
    !!progress?.staged_boot_id
  ) {
    // Already running the staged slot: a trial boot of it stays ``done``
    // until firstboot commits, and is not a pending upgrade.
    if (progress.staged_slot && row.current_slot === progress.staged_slot)
      return null;
    return "staged";
  }
  return null;
}

/** True when a cancel can no longer stop this node's upgrade. */
export function upgradeStartedOnHost(
  row: UpgradeRowFields,
  now: number = Date.now(),
): boolean {
  return hostUpgradeActivity(row, now) !== null;
}

/** The 409 clear-upgrade answers once the apply has started, or null. */
export function upgradeAlreadyStartedRefusal(err: unknown): string | null {
  const res = (
    err as { response?: { status?: number; data?: { detail?: unknown } } }
  )?.response;
  if (res?.status !== 409) return null;
  const d = res.data?.detail as
    | { code?: unknown; message?: unknown }
    | undefined;
  return d && typeof d === "object" && d.code === "upgrade_already_started"
    ? String(d.message ?? "The upgrade has already started.")
    : null;
}
