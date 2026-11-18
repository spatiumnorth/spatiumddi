/** Small helpers shared by the Copilot Watch tabs (#4405). */

export function severityCls(severity: string): string {
  if (severity === "critical")
    return "bg-red-500/15 text-red-700 dark:text-red-400";
  if (severity === "warning")
    return "bg-amber-500/15 text-amber-700 dark:text-amber-400";
  return "bg-sky-500/15 text-sky-700 dark:text-sky-400";
}

/** A timestamp in the viewer's locale, or a dash for none. */
export function fmtWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** Why a run did not happen, in words. Keys are `ai_watch_run.skip_reason`. */
export const SKIP_REASONS: Record<string, string> = {
  budget_exhausted: "The daily budget was used up",
  no_provider: "No enabled AI provider was available",
  hosted_not_allowed:
    "No provider is marked on-prem and hosted providers are not allowed",
  rate_limited: "The runs-per-hour limit was reached",
  maintenance: "Maintenance mode was on",
  principal_disabled: "The copilot-watch service identity is disabled",
  principal_not_read_only:
    "The Copilot Watch group holds a role that grants more than read",
};

export function skipReason(reason: string | null): string {
  if (!reason) return "";
  return SKIP_REASONS[reason] ?? reason;
}

export const PAUSE_REASONS: Record<string, string> = {
  manual: "Paused by an operator",
  budget: "Paused: the daily budget was reached",
  failures: "Paused: several runs in a row failed",
};

export const TRIGGERS: Record<string, string> = {
  manual: "Run now",
  event: "Alert change",
  sweep: "Scheduled sweep",
};
