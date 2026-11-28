import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// #4888: counts of one that the #4780 guard cannot see: a count closed in its
// own tag (`<span>{n}</span> hosts`) or a plural off its word list.
const SITES: [string, RegExp][] = [
  ["pages/tools/WakeSchedulesPage.tsx", /<\/span> hosts/],
  ["pages/admin/DHCPImportPage.tsx", /<\/strong> (pools|reservations|classes)/],
  ["pages/logs/DNSThreatTab.tsx", /\} (windows|subdomains|samples)/],
  ["pages/logs/DNSThreatTab.tsx", /\bclients scored/],
];

describe("count of one in the singular (#4888)", () => {
  it.each(SITES)("%s has no fixed plural %s", (file, re) => {
    const text = readFileSync(resolve(__dirname, "..", file), "utf8");
    expect(text).not.toMatch(re);
  });
});
