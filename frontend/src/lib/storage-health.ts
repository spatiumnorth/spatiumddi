import { countNoun } from "./count-noun";
/**
 * Presentation helpers for storage redundancy (#999 Part A).
 *
 * Deliberately contains **no classification**. Whether an array is in
 * trouble, and how badly, is decided once in
 * `backend/app/services/appliance/storage_health.py` and shipped as
 * `findings` / `worst_severity` — the same function the
 * `appliance_storage_degraded` alert rule and the
 * `find_appliance_storage` copilot tool call. Re-deriving that here
 * would be a second copy of the one subtle rule in the feature
 * (severity comes from redundancy remaining, not from the state
 * string), and the failure mode of a drifted copy is a green chip over
 * a red alert.
 *
 * What lives here is only how to render the verdict: colours, and the
 * short labels a chip has room for.
 */

/**
 * The severities the server can actually emit. `info` is deliberately
 * absent: a routine scrub is shown with its progress and is not a
 * finding at all (see `storage_health.py`), so nothing produces one.
 */
export type StorageSeverity = "critical" | "warning";

/** Chip classes per severity, plus the healthy case (no findings). */
export const STORAGE_SEVERITY_CLASSES: Record<string, string> = {
  critical:
    "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300",
  warning:
    "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300",
  ok: "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  /** Present and not complaining, but not verified healthy either. */
  unknown: "border-border bg-muted text-muted-foreground",
};

export function storageSeverityClass(severity: string | null): string {
  // `null` means "no finding", which for an md array is a real
  // statement and earns green. Anything else UNRECOGNISED does not:
  // falling back to green would render a severity we do not understand
  // as healthy — the same trap as treating a missing reading as a clean
  // bill of health, and the one this whole feature exists to avoid. A
  // reintroduced `info` severity would otherwise have gone green
  // silently.
  if (severity == null) return STORAGE_SEVERITY_CLASSES.ok;
  return STORAGE_SEVERITY_CLASSES[severity] ?? STORAGE_SEVERITY_CLASSES.unknown;
}

/**
 * Chip classes for one array or map, given its worst finding (or none).
 *
 * **No finding on a multipath map is not a clean bill of health**, so it
 * gets the neutral style, never the green one. The only per-path signal
 * readable without `multipathd` is the path's SCSI device state, and
 * that stays `running` for the commonest dm path failure — a map that
 * has quietly lost half its paths produces no finding at all. An md
 * array's state, by contrast, IS known, so green there is earned.
 */
export function storageChipClass(
  severity: string | null,
  kind: "md" | "multipath",
): string {
  if (severity == null && kind === "multipath") {
    return STORAGE_SEVERITY_CLASSES.unknown;
  }
  return storageSeverityClass(severity);
}

/** `1h 12m` / `4m 30s` / `12s`. Null in, empty string out. */
export function formatEta(seconds: number | null | undefined): string {
  if (seconds == null || seconds < 0) return "";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m ${Math.round(seconds % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function formatMdLevel(level: string): string {
  return /^raid\d+$/.test(level) ? level.toUpperCase() : level;
}

/**
 * Short label for one array: `RAID1 clean`, `RAID1 rebuilding 43%`,
 * `RAID1 DEGRADED — 1 of 2`, `RAID1 FAILED`.
 *
 * The member counts are in the degraded/failed labels because "degraded"
 * on its own does not tell an operator whether they have hours or
 * minutes.
 */
export function mdChipLabel(array: {
  level: string;
  state: string;
  members_in_sync: number;
  members_expected: number | null;
  sync?: { action: string; percent: number | null } | null;
}): string {
  const level = formatMdLevel(array.level);
  const counts = `${array.members_in_sync} of ${array.members_expected}`;
  // The array is assembled but its member count could not be read, so no
  // redundancy claim can be made — and "clean" would be a claim.
  if (array.state === "unknown") return `${level} state unknown`;
  if (array.state === "failed") return `${level} FAILED — ${counts}`;
  if (array.state === "degraded") {
    const pct = array.sync?.percent;
    // A degraded array that is rebuilding is still degraded — say both,
    // because "rebuilding" alone reads as recovery already achieved.
    const rebuilding = pct != null ? ` · rebuilding ${pct}%` : "";
    return `${level} DEGRADED — ${counts}${rebuilding}`;
  }
  if (array.state === "syncing") {
    const action = array.sync?.action ?? "sync";
    const pct = array.sync?.percent;
    return `${level} ${action}${pct != null ? ` ${pct}%` : ""}`;
  }
  return `${level} clean`;
}

/** `mpath 4/4` / `mpath 2/4 faulted`. */
export function mpathChipLabel(map: {
  paths_total: number;
  paths_faulted: number;
}): string {
  const healthy = map.paths_total - map.paths_faulted;
  return map.paths_faulted > 0
    ? `mpath ${healthy}/${countNoun(map.paths_total, "path")}`
    : `mpath ${map.paths_total}/${countNoun(map.paths_total, "path")}`;
}
