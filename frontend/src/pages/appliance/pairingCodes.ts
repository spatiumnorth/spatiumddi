import type { PairingAttemptRow, PairingCodeCreate } from "@/lib/api";

/**
 * Map "how many appliances will join?" onto the API's persistent +
 * max_claims shape (#2225). One appliance is a single-use code; more
 * is a persistent code capped at that many; unlimited has no cap.
 */
export function codeRequestFor(
  count: number | "unlimited",
): Pick<PairingCodeCreate, "persistent" | "max_claims"> {
  if (count === "unlimited") return { persistent: true, max_claims: null };
  if (count <= 1) return { persistent: false, max_claims: null };
  return { persistent: true, max_claims: count };
}

/** Plain-words reason for a refused join, for the Refused attempts panel. */
export function attemptReasonText(a: PairingAttemptRow): string {
  switch (a.reason) {
    case "already_used":
      return a.used_by.length
        ? `code already used by ${a.used_by.join(", ")}`
        : "code already used";
    case "exhausted":
      return a.used_by.length
        ? `code is full (used by ${a.used_by.join(", ")})`
        : "code is full";
    case "expired":
      return "code expired";
    case "revoked":
      return "code was revoked";
    case "disabled":
      return "code is paused";
    default:
      return "unknown code";
  }
}
