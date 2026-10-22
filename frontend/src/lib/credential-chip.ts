import type { CredentialState } from "@/lib/api";

/**
 * View model for an integration credential chip (#2138). Kept out of the
 * component file so Vite fast-refresh sees a components-only module.
 *
 * Red once the credential is dead (expired, or the last sync got HTTP 401)
 * or within a week of it; amber inside the 30-day warning window. `ok` and
 * `unknown` render nothing unless asked for: `unknown` is not healthy, so it
 * is never drawn green.
 */

export const CREDENTIAL_CRITICAL_DAYS = 7;

export type CredentialChipView = {
  label: string;
  tone: "red" | "amber" | "muted";
  title: string;
};

export function credentialChipView(
  state: CredentialState | null | undefined,
  daysLeft: number | null | undefined,
  expiresAt: string | null | undefined,
  opts: { showOk?: boolean; showUnknown?: boolean } = {},
): CredentialChipView | null {
  const when = expiresAt ? new Date(expiresAt).toLocaleDateString() : null;
  switch (state) {
    case "rejected":
      return {
        label: "Token rejected",
        tone: "red",
        title:
          "The last sync was refused with HTTP 401: the API token has expired or been revoked, and the mirror has stopped updating. Generate a new token and replace it.",
      };
    case "expired":
      return {
        label: "Token expired",
        tone: "red",
        title: `The API token expired${when ? ` on ${when}` : ""}. Generate a new token and replace it.`,
      };
    case "expiring": {
      const d = daysLeft ?? 0;
      return {
        label:
          d <= 0
            ? "Token expires today"
            : `Token expires in ${d} day${d === 1 ? "" : "s"}`,
        tone: d <= CREDENTIAL_CRITICAL_DAYS ? "red" : "amber",
        title: `The API token expires${when ? ` on ${when}` : " soon"}. Generate a new token and replace it before then, or syncing stops.`,
      };
    }
    case "ok":
      if (!opts.showOk) return null;
      return {
        label: when ? `Token expires ${when}` : "Token valid",
        tone: "muted",
        title: "The API token is not close to expiry.",
      };
    case "unknown":
      if (!opts.showUnknown) return null;
      return {
        label: "Token expiry unknown",
        tone: "muted",
        title:
          "SpatiumDDI could not read when this token expires. Enter the date in the tenant form so it can warn you before it lapses.",
      };
    case "disabled":
      // The tenant is off: nothing syncs, so there is no live credential
      // problem. The page's own enabled/disabled badge says so (#2191).
      return null;
    default:
      return null;
  }
}

/** A target that needs an operator: a credential problem or a sync error. */
export function hasTargetProblem(t: {
  credential_state?: CredentialState | null;
  last_sync_error?: string | null;
}): boolean {
  return (
    t.credential_state === "rejected" ||
    t.credential_state === "expired" ||
    t.credential_state === "expiring" ||
    !!t.last_sync_error
  );
}

/**
 * Order the rows of a capped integration card (#2192): targets with a
 * credential problem or a sync error first, so the cap can never hide the
 * tenant that needs a new key ahead of a healthy one. Problem rows are kept
 * past `base`, up to `maxProblems` (so 200 failing nodes do not become a
 * 200-row card); healthy rows only fill what `base` leaves. Stable within
 * groups.
 *
 * `total` / `problemTotal` are the true counts when `targets` is itself a
 * capped list (the dashboard API trims it); the hidden counts are taken
 * against them. `hiddenProblems` is how many problem targets are not named,
 * `hidden` how many healthy ones.
 */
export function cardTargets<
  T extends {
    credential_state?: CredentialState | null;
    last_sync_error?: string | null;
  },
>(
  targets: T[],
  base = 3,
  opts: { maxProblems?: number; total?: number; problemTotal?: number } = {},
): { shown: T[]; hidden: number; hiddenProblems: number } {
  const maxProblems = opts.maxProblems ?? 8;
  const problems = targets.filter(hasTargetProblem);
  const rest = targets.filter((t) => !hasTargetProblem(t));
  const shownProblems = problems.slice(0, Math.max(0, maxProblems));
  const shownRest = rest.slice(0, Math.max(0, base - shownProblems.length));
  const shown = [...shownProblems, ...shownRest];
  const problemTotal = Math.max(
    opts.problemTotal ?? problems.length,
    problems.length,
  );
  const total = Math.max(opts.total ?? targets.length, targets.length);
  const hiddenProblems = problemTotal - shownProblems.length;
  const hidden = Math.max(0, total - problemTotal - shownRest.length);
  return { shown, hidden, hiddenProblems };
}
