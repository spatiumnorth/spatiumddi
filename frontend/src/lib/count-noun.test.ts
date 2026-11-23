import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { countNoun, pluralize } from "./count-noun";

describe("countNoun", () => {
  it("uses the singular for exactly one", () => {
    expect(countNoun(1, "space")).toBe("1 space");
    expect(countNoun(1, "entry", "entries")).toBe("1 entry");
  });
  it("uses the plural otherwise, including zero", () => {
    expect(countNoun(0, "space")).toBe("0 spaces");
    expect(countNoun(2, "entry", "entries")).toBe("2 entries");
  });
});

describe("pluralize", () => {
  it("returns only the noun", () => {
    expect(pluralize(1, "route")).toBe("route");
    expect(pluralize(0, "route")).toBe("routes");
    expect(pluralize(2, "entry", "entries")).toBe("entries");
  });
});

// Guard (#4780): a count glued to a fixed plural ("of 1 subnets"). Scans
// every console .ts/.tsx for `${...} <plural>` and `{...} <plural>`, and
// fails on a hit that is not exempted below with the reason it can never be
// one. Fix a new hit with countNoun / pluralize.
const WORDS =
  "servers|batches|tokens|addrs|entries|characters|passwords|paths|nodes|" +
  "containers|subnets|policies|records|ops|rows|instances|aliases|images|" +
  "scopes|addresses|zones|rules|resolvers|queries|items|matches|chars|" +
  "errors|interfaces|prefixes|routes|routers|events|hosts|speakers";
// `}` (optionally `{" "}` split onto the next line) then a plural word.
const SHAPE = new RegExp(
  `(?:\\}[ \\t]+|\\{" "\\}[ \\t]*\\n[ \\t]*)(${WORDS})\\b(?!\\s*=)`,
  "g",
);

// A hit is exempt only when its own line contains `line` (per site, so a new
// hit in the same file is still caught). `why` says why the count can never
// be one.
const EXEMPT: { file: string; word: string; line: string; why: string }[] = [
  {
    file: "pages/ipam/IPAMPage.tsx",
    word: "subnets",
    line: "/{prefixLen} subnets",
    why: "prefixLen is a prefix length, not a count",
  },
  {
    file: "pages/LogsPage.tsx",
    word: "servers",
    line: "{kind} servers",
    why: "a kind label, not a count",
  },
  {
    file: "pages/appliance/UpgradeImagesTable.tsx",
    word: "images",
    line: "`Delete ${rows.length} images?`",
    why: "title sits in the single ? ... : branch, so not one",
  },
  {
    file: "pages/appliance/UpgradeImagesTable.tsx",
    word: "images",
    line: "`these ${rows.length} images`",
    why: "the rows.length === 1 branch returns the singular first",
  },
  {
    file: "pages/dns/ZoneDeleteDialogs.tsx",
    word: "zones",
    line: "The ${count} zones",
    why: "the count === 1 branch returns the singular text first",
  },
  {
    file: "pages/dns/DNSPage.tsx",
    word: "zones",
    line: '"Stub" : "Secondary"',
    why: "a zone-type label, not a count",
  },
  {
    file: "pages/dns/DNSPage.tsx",
    word: "zones",
    line: "of ${ids.length} zones: ${APPROVAL_QUEUED_MESSAGE}",
    why: "reached only when queued !== ids.length with queued > 0, so 2 or more",
  },
  {
    file: "pages/dns/DNSPage.tsx",
    word: "zones",
    line: "of ${ids.length} zones were not deleted",
    why: "reached only when failed.length < ids.length, so 2 or more",
  },
  {
    file: "pages/dns/DNSPage.tsx",
    word: "zones",
    line: "None of the ${ids.length} zones",
    why: "the ids.length === 1 branch returns the singular text first",
  },
  {
    file: "pages/dns/DNSPage.tsx",
    word: "batches",
    line: "split into ${Math.ceil(",
    why: "shown only when records exceed one chunk, so 2 or more batches",
  },
  {
    file: "pages/admin/PlatformInsightsPage.tsx",
    word: "ops",
    line: "ops/sec",
    why: "a unit in ops/sec, not a count of things",
  },
  {
    file: "lib/dnsNames.ts",
    word: "characters",
    line: "characters`",
    why: "fixed protocol limits (63 / 253)",
  },
  {
    file: "pages/opnsense/OpnsensePage.tsx",
    word: "rows",
    line: "rows.",
    why: "the word names what a setting creates (reserved rows), no count",
  },
  {
    file: "lib/password-policy.ts",
    word: "passwords",
    line: "`${policy.history_count} passwords`",
    why: "already in the history_count === 1 else-branch",
  },
];

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name))
      out.push(full);
  }
  return out;
}

type Hit = { file: string; word: string; line: string };

function findFixedPlurals(root: string): Hit[] {
  const hits: Hit[] = [];
  for (const full of walk(root, [])) {
    const file = relative(root, full);
    const text = readFileSync(full, "utf8");
    const lines = text.split("\n");
    for (const m of text.matchAll(SHAPE)) {
      const wordAt = m.index! + m[0].length - m[1].length;
      const lineNo = text.slice(0, wordAt).split("\n").length - 1;
      const line = lines[lineNo];
      const t = line.trim();
      if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*"))
        continue;
      hits.push({ file, word: m[1], line });
    }
  }
  return hits;
}

const isExempt = (h: Hit) =>
  EXEMPT.some(
    (e) => e.file === h.file && e.word === h.word && h.line.includes(e.line),
  );

describe("console copy: a count of one", () => {
  const hits = findFixedPlurals(resolve(__dirname, ".."));
  it("has no count glued to a fixed plural word", () => {
    expect(
      hits
        .filter((h) => !isExempt(h))
        .map((h) => `${h.file}: ${h.line.trim()}`)
        .sort(),
    ).toEqual([]);
  });
  it("keeps no stale exemption", () => {
    const stale = EXEMPT.filter(
      (e) =>
        !hits.some(
          (h) =>
            e.file === h.file && e.word === h.word && h.line.includes(e.line),
        ),
    ).map((e) => `${e.file}: ${e.line}`);
    expect(stale).toEqual([]);
  });
});
