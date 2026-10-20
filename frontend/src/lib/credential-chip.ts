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
    default:
      return null;
  }
}
