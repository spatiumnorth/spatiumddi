import type { DNSBlockList, DNSBlockListFeedSkipped } from "@/lib/api";

/** Rules the last refresh could not enforce (#2123, #3531); 0 when the
 *  counts were never recorded. */
export function feedSkippedTotal(l: DNSBlockList): number {
  const s = l.feed_parse_skipped;
  return s
    ? s.regex + s.modifier + s.badfilter + s.malformed + (s.invalid_name ?? 0)
    : 0;
}

const MALFORMED_REASONS: [keyof DNSBlockListFeedSkipped, string][] = [
  ["star_in_name", "with a wildcard (*) inside a name"],
  ["no_anchor", "that match part of a URL rather than a domain"],
  ["trailing_dot", "that match any top-level domain or name prefix"],
  ["start_anchor", "anchored to the start of a URL, not a whole domain"],
  ["bare_star", "with a wildcard (*) and no || anchor"],
  ["dotless", "naming a single label, not a hostname"],
  ["other", "of some other shape (a path, or a character a name cannot carry)"],
];

/** What the refresh enforced and what it set aside, in plain words (#4037).
 *  Leads with the list's entry count (all that the row carries; it includes
 *  any entries added by hand), then the skipped total and why. Information,
 *  not a fault: a skipped rule is one only a browser ad blocker can apply. */
export function feedSkippedTitle(l: DNSBlockList): string {
  const s = l.feed_parse_skipped;
  if (!s) return "";
  const enforced =
    typeof l.entry_count === "number"
      ? `${l.entry_count.toLocaleString("en-US")} entries enforced. `
      : "";
  if (!s.regex && !s.modifier && !s.badfilter && !s.malformed && s.invalid_name)
    return (
      `${enforced}${s.invalid_name} feed line(s) were set aside because they ` +
      "are not valid DNS names (adblock rules, paths or other characters a name cannot carry)."
    );
  const reasons: string[] = [];
  if (s.regex) reasons.push(`${s.regex} regular expression(s)`);
  if (s.badfilter) reasons.push(`${s.badfilter} $badfilter`);
  if (s.modifier)
    reasons.push(
      `${s.modifier} with browser-only modifiers ($domain=, $third-party, …)`,
    );
  let named = 0;
  for (const [key, label] of MALFORMED_REASONS) {
    const n = s[key] ?? 0;
    named += n;
    if (n > 0) reasons.push(`${n} ${label}`);
  }
  // Rows written before the split carry only the total.
  if (named === 0 && s.malformed > 0)
    reasons.push(`${s.malformed} that are not a plain ||name^ rule`);
  else if (s.malformed > named)
    reasons.push(`${s.malformed - named} of an unrecorded shape`);
  return (
    `${enforced}${feedSkippedTotal(l)} rule(s) in the feed were set aside ` +
    "because only a browser ad blocker can apply them, not DNS" +
    (reasons.length > 0 ? `: ${reasons.join("; ")}` : "") +
    "."
  );
}
