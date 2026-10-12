import type { ConfigApplyStatus } from "@/lib/api";

/**
 * An agent that applied a bundle but had some zones refused by its daemon
 * (PowerDNS takes zones one at a time, #1280) reports `reverted` with an error
 * starting with this prefix: there is no "partial" status. Nothing was rolled
 * back and every other zone is served, so the UI must not say it was.
 * Mirrors the DNS agent's `sync.PARTIAL_APPLY_PREFIX` and the backend's
 * `config_apply.PARTIAL_APPLY_PREFIX`.
 */
export const PARTIAL_APPLY_PREFIX = "partial apply: ";

export function isPartialApply(
  status: ConfigApplyStatus | null | undefined,
  error: string | null | undefined,
): boolean {
  return (
    status === "reverted" && (error ?? "").startsWith(PARTIAL_APPLY_PREFIX)
  );
}

/** The agent's error without the marker prefix, for display. */
export function partialApplyDetail(error: string | null | undefined): string {
  const e = error ?? "";
  return e.startsWith(PARTIAL_APPLY_PREFIX)
    ? e.slice(PARTIAL_APPLY_PREFIX.length)
    : e;
}

export const PARTIAL_APPLY_LABEL = "Zones refused";

export const PARTIAL_APPLY_EXPLAIN =
  "This agent applied the saved configuration, but its daemon refused the zones named below. Every other zone is served as saved, and nothing was rolled back. Fix the refused zones' data.";
