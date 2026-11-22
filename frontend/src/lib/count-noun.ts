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
  return `${n} ${n === 1 ? singular : plural}`;
}
