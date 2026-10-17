/** #2021 — can a per-box slot upgrade still be cancelled?
 *
 *  Mirrors the backend's ``upgrade_started_on_host``: once the host reports
 *  ``in-flight`` (it has the trigger, or is downloading / writing) a cancel
 *  cannot stop it — the host deliberately never aborts a running apply — so
 *  the console must not offer one. A stamp older than the stale window is a
 *  dead runner, which the "cancel and re-apply" recovery has to keep. */
export const UPGRADE_INFLIGHT_STALE_MS = 300_000;

export function upgradeStartedOnHost(
  row: {
    last_upgrade_state?: string | null;
    last_upgrade_state_at?: string | null;
  },
  now: number = Date.now(),
): boolean {
  if (row.last_upgrade_state !== "in-flight") return false;
  if (!row.last_upgrade_state_at) return true;
  const at = new Date(row.last_upgrade_state_at).getTime();
  if (Number.isNaN(at)) return true;
  return now - at <= UPGRADE_INFLIGHT_STALE_MS;
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
