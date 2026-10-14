export type ActivityTone = "default" | "good" | "warn" | "bad" | "info";

/**
 * Colour family + label for a Live Activity row. The audit log writes
 * `failed` for most failures but `failure` for every rejected sign-in
 * (#1874), so both read as a failure; `forbidden` is a refused request
 * under another name, so it reads as DENY.
 */
export function activityTone(
  action: string,
  result: string,
): { tone: ActivityTone; label: string } {
  if (result === "failed" || result === "failure") {
    return { tone: "bad", label: "FAIL" };
  }
  if (result === "denied" || result === "forbidden") {
    return { tone: "warn", label: "DENY" };
  }
  const label = action.toUpperCase();
  if (action === "create") return { tone: "good", label };
  if (action === "delete") return { tone: "bad", label };
  return { tone: "info", label };
}
