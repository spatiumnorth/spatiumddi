import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

import {
  CORE_ICON_NAMES,
  iconLabel,
  iconName,
  iconValue,
  loadIconMeta,
  loadIconPath,
  searchIcons,
} from "./catalog";

describe("icon values (#5022)", () => {
  it("round-trips the namespaced form", () => {
    expect(iconValue("printer")).toBe("mdi:printer");
    expect(iconName("mdi:printer")).toBe("printer");
    expect(iconName("custom:1")).toBeNull();
    expect(iconName(null)).toBeNull();
    expect(iconLabel("mdi:access-point")).toBe("Access point");
  });
});

describe("the set (#5022)", () => {
  it("keeps the core set small and free of deprecated (brand) icons", async () => {
    expect(CORE_ICON_NAMES.length).toBeGreaterThanOrEqual(60);
    expect(CORE_ICON_NAMES.length).toBeLessThanOrEqual(90);
    const rows = await loadIconMeta();
    const names = new Set(rows.map((r) => r.name));
    for (const n of CORE_ICON_NAMES) expect(names.has(n), n).toBe(true);
    // 'github' is a deprecated brand logo in the set's metadata.
    expect(names.has("github")).toBe(false);
  });

  it("searches names, aliases and tags, best prefix first", async () => {
    const rows = await loadIconMeta();
    const hits = searchIcons(rows, "printer");
    expect(hits[0]).toBe("printer");
    expect(searchIcons(rows, "")).toEqual([]);
    expect(searchIcons(rows, "zzzzqqqq")).toEqual([]);
  });

  it("loads a path from its lazy bucket", async () => {
    expect(await loadIconPath("account-network")).toMatch(/^M/);
    expect(await loadIconPath("no-such-icon-xyz")).toBeNull();
  });
});

// The full set is ~6 MB of path strings. It reaches the browser only through
// the virtual lazy modules; a static import of the package (or its namespace)
// anywhere else would put all of it in the main bundle.
describe("bundle guard (#5022)", () => {
  function walk(dir: string, out: string[] = []): string[] {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      if (statSync(p).isDirectory()) walk(p, out);
      else if (/\.(ts|tsx)$/.test(f) && !/\.test\./.test(f)) out.push(p);
    }
    return out;
  }
  it("imports @mdi/js only by name, and only from lib/icons/core.ts", () => {
    const root = join(__dirname, "..", "..");
    const offenders: string[] = [];
    for (const file of walk(root)) {
      const src = readFileSync(file, "utf8");
      if (!/@mdi\/js/.test(src)) continue;
      const rel = relative(root, file);
      if (rel !== join("lib", "icons", "core.ts")) offenders.push(rel);
      else
        expect(src).not.toMatch(/import\s+\*\s+as\s+\w+\s+from\s+["']@mdi\/js/);
    }
    expect(offenders).toEqual([]);
  });
});
