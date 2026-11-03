/**
 * Format an address count. IPv6 sizes pass 2^53, which a JavaScript number
 * cannot hold exactly, and the API's int fields saturate at 2^63 - 1 so a
 * generated int64 client can decode them. Each such field has a sibling
 * `*_exact` decimal string; pass that first and it is printed digit for
 * digit through BigInt (#3322). A number is the fallback for a server that
 * predates the string.
 */
export function formatCount(
  exact: string | null | undefined,
  fallback?: number | null,
): string {
  if (exact !== null && exact !== undefined && /^\d+$/.test(exact)) {
    return BigInt(exact).toLocaleString();
  }
  if (fallback === null || fallback === undefined) return "—";
  return fallback.toLocaleString();
}
