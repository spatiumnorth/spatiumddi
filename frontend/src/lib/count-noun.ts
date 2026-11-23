/**
 * "1 space" / "2 spaces": a count glued to its noun, with the noun in the
 * singular when the count is exactly one (#4612). Pass `plural` for a noun
 * that does not just add an "s" (`countNoun(n, "entry", "entries")`).
 */
export function countNoun(
  n: number,
  singular: string,
  plural = `${singular}s`,
): string {
  return `${n} ${pluralize(n, singular, plural)}`;
}

/**
 * Just the noun, for a count the caller formats itself (`toLocaleString()`,
 * a "3/5" ratio): `${n.toLocaleString()} ${pluralize(n, "route")}` (#4780).
 */
export function pluralize(
  n: number,
  singular: string,
  plural = `${singular}s`,
): string {
  return n === 1 ? singular : plural;
}
