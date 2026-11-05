import type { DNSBlockList, DNSBlockListFeedSkipped } from "@/lib/api";

/** Rules the last adblock refresh could not enforce (#2123); 0 when the
 *  counts were never recorded. */
export function feedSkippedTotal(l: DNSBlockList): number {
  const s = l.feed_parse_skipped;
  return s ? s.regex + s.modifier + s.badfilter + s.malformed : 0;
}

const MALFORMED_REASONS: [keyof DNSBlockListFeedSkipped, string][] = [
  ["star_in_name", "with a * inside the name"],
  ["no_anchor", "with no || anchor (substring match)"],
  ["trailing_dot", "ending in a dot (prefix match)"],
  ["start_anchor", "with a | start anchor"],
  ["bare_star", "starting with * and no ||"],
  ["dotless", "naming a single label"],
  ["other", "of some other shape"],
];

export function feedSkippedTitle(l: DNSBlockList): string {
  const s = l.feed_parse_skipped;
  if (!s) return "";
  const reasons: string[] = [];
  let named = 0;
  for (const [key, label] of MALFORMED_REASONS) {
    const n = s[key] ?? 0;
    named += n;
    if (n > 0) reasons.push(`${n} ${label}`);
  }
  // Rows written before the split carry only the total.
  if (named > 0 && s.malformed > named)
    reasons.push(`${s.malformed - named} of an unrecorded shape`);
  return (
    `The last refresh skipped ${feedSkippedTotal(l)} feed rule(s) DNS cannot ` +
    `enforce: ${s.regex} regex, ${s.modifier} with unsupported modifiers ` +
    `($domain=, $third-party, …), ${s.badfilter} $badfilter, ` +
    `${s.malformed} not a plain ||name^ rule` +
    (reasons.length > 0 && s.malformed > 0 ? ` (${reasons.join(", ")})` : "") +
    "."
  );
}
