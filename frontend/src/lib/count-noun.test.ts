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
const SHAPE = new RegExp(`\\}\\s+(${WORDS})\\b(?!\\s*=)`, "g");

// "<file>::<matched text>" -> why the count cannot be one.
const EXEMPT: Record<string, string> = {
  "pages/ipam/IPAMPage.tsx::} subnets":
    "/{prefixLen} subnets: prefixLen is a prefix length, not a count",
  "pages/LogsPage.tsx::} servers": "a kind label, not a count",
  "pages/appliance/UpgradeImagesTable.tsx::} images":
    "both sites sit in the not-single branch (rows.length !== 1)",
  "pages/dns/ZoneDeleteDialogs.tsx::} zones":
    "the count === 1 branch returns the singular text first",
  "pages/dns/DNSPage.tsx::} zones":
    "bulk-delete messages: a queued/failed subset or the not-one branch implies 2 or more",
  "pages/dns/DNSPage.tsx::} batches":
    "only shown when records exceed one chunk, so 2 or more batches",
  "pages/admin/PlatformInsightsPage.tsx::} ops":
    "a unit in ops/sec, not a count of things",
  "lib/dnsNames.ts::} characters": "fixed protocol limits (63 / 253)",
  "lib/password-policy.ts::} passwords":
    "already in the history_count !== 1 branch",
};

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name))
      out.push(full);
  }
  return out;
}

function findFixedPlurals(root: string): Set<string> {
  const hits = new Set<string>();
  for (const file of walk(root, [])) {
    const rel = relative(root, file);
    for (const line of readFileSync(file, "utf8").split("\n")) {
      const t = line.trim();
      if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*"))
        continue;
      for (const m of line.matchAll(SHAPE)) {
        hits.add(`${rel}::} ${m[1]}`);
      }
    }
  }
  return hits;
}

describe("console copy: a count of one", () => {
  const hits = findFixedPlurals(resolve(__dirname, ".."));
  it("has no count glued to a fixed plural word", () => {
    expect([...hits].filter((k) => !(k in EXEMPT)).sort()).toEqual([]);
  });
  it("keeps no stale exemption", () => {
    const stale = Object.keys(EXEMPT).filter((e) => !hits.has(e));
    expect(stale).toEqual([]);
  });
});
