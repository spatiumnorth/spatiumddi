/**
 * @vitest-environment jsdom
 *
 * The adblock skip banner names why each rule was skipped (#3519).
 */

import { describe, expect, it } from "vitest";
import type { DNSBlockList } from "@/lib/api";
import { feedSkippedTitle, feedSkippedTotal } from "@/lib/blocklistFeedSkipped";

const list = (skipped: Record<string, number>) =>
  ({ feed_parse_skipped: skipped }) as unknown as DNSBlockList;

describe("feedSkippedTitle", () => {
  it("names each non-zero malformed reason and no zero ones", () => {
    const t = feedSkippedTitle(
      list({
        regex: 0,
        modifier: 0,
        badfilter: 0,
        malformed: 12,
        star_in_name: 10,
        no_anchor: 2,
        trailing_dot: 0,
      }),
    );
    expect(t).toContain("10 with a wildcard (*) inside a name");
    expect(t).toContain("2 that match part of a URL");
    expect(t).not.toContain("top-level domain");
  });

  it("falls back to the total for rows written before the split", () => {
    const t = feedSkippedTitle(
      list({ regex: 0, modifier: 0, badfilter: 0, malformed: 4 }),
    );
    expect(t).toContain("4 that are not a plain ||name^ rule");
  });

  it("reports a hosts / domains feed's invalid names on their own (#3531)", () => {
    const l = list({
      regex: 0,
      modifier: 0,
      badfilter: 0,
      malformed: 0,
      invalid_name: 3,
    });
    expect(feedSkippedTotal(l)).toBe(3);
    expect(feedSkippedTitle(l)).toContain("3 feed line(s) were set aside");
    expect(feedSkippedTitle(l)).toContain("not valid DNS names");
  });

  it("counts an adblock row without invalid_name exactly once (#3531)", () => {
    const l = list({
      regex: 1,
      modifier: 2,
      badfilter: 0,
      malformed: 4,
      star_in_name: 4,
    });
    expect(feedSkippedTotal(l)).toBe(7);
  });

  // #4037: the AdGuard DNS Filter's real counts (13 Nov 2026).
  it("leads with what was enforced and reads as information (#4037)", () => {
    const l = {
      entry_count: 190144,
      feed_parse_skipped: {
        regex: 22,
        modifier: 0,
        badfilter: 5,
        malformed: 555,
        star_in_name: 390,
        no_anchor: 89,
        trailing_dot: 35,
        start_anchor: 27,
        bare_star: 13,
        dotless: 1,
        other: 0,
      },
    } as unknown as DNSBlockList;
    const t = feedSkippedTitle(l);
    expect(t.startsWith("190,144 entries enforced. 582 rule(s)")).toBe(true);
    expect(t).toContain("22 regular expression(s)");
    expect(t).toContain("5 $badfilter");
    expect(t).toContain("390 with a wildcard (*) inside a name");
    expect(t).toContain("35 that match any top-level domain");
    expect(t).not.toContain("0 with browser-only modifiers");
    expect(t).not.toMatch(/cannot enforce|error|failed/i);
  });

  it("omits the enforced count rather than inventing one (#4037)", () => {
    const t = feedSkippedTitle(
      list({ regex: 2, modifier: 0, badfilter: 0, malformed: 0 }),
    );
    expect(t).not.toContain("enforced");
    expect(t).toContain("2 rule(s) in the feed were set aside");
  });
});
