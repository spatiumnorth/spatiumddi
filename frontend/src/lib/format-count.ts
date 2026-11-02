/**
 * Format an address count. IPv6 sizes pass 2^53, so `Number#toLocaleString`
 * prints digits the number never held (2^64 as 18,446,744,073,709,552,000).
 * Every size the API sends is a whole number that a double holds exactly (a
 * power of two past 2^53), so `BigInt` recovers the exact figure (#3322).
 */
export function formatCount(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (Number.isSafeInteger(n) || !Number.isInteger(n)) {
    return n.toLocaleString();
  }
  return BigInt(n).toLocaleString();
}
