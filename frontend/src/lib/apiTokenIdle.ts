import type { ApiToken } from "@/lib/api";

export const IDLE_DAYS = 90;

/** True when the token has not been used in ``days`` days; a token never
 * used counts from its creation date (#4491). */
export function isIdleToken(
  t: Pick<ApiToken, "last_used_at" | "created_at">,
  days: number = IDLE_DAYS,
  now: number = Date.now(),
): boolean {
  const ref = Date.parse(t.last_used_at ?? t.created_at);
  return now - ref > days * 86_400_000;
}
