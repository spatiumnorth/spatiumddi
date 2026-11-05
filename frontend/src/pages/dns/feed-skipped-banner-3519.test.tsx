/**
 * @vitest-environment jsdom
 *
 * The adblock skip banner names why each rule was skipped (#3519).
 */

import { describe, expect, it } from "vitest";
import type { DNSBlockList } from "@/lib/api";
import { feedSkippedTitle } from "@/lib/blocklistFeedSkipped";

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
    expect(t).toContain("10 with a * inside the name");
    expect(t).toContain("2 with no || anchor");
    expect(t).not.toContain("ending in a dot");
  });

  it("falls back to the total for rows written before the split", () => {
    const t = feedSkippedTitle(
      list({ regex: 0, modifier: 0, badfilter: 0, malformed: 4 }),
    );
    expect(t).toContain("4 not a plain ||name^ rule");
    expect(t).not.toContain("rule (");
  });
});
