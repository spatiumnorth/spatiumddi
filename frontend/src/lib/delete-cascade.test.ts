import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import registry from "./delete-cascade.json";
import { cascadeList, cascadePhrases, joinList } from "./delete-cascade";

describe("delete-cascade registry (#4143, #4144, #4145)", () => {
  it("joins lists the way the dialogs read", () => {
    expect(joinList([])).toBe("");
    expect(joinList(["a"])).toBe("a");
    expect(joinList(["a", "b"])).toBe("a and b");
    expect(joinList(["a", "b", "c"])).toBe("a, b and c");
  });

  it("gives every table a dialog names a phrase, and exempts no named table", () => {
    for (const [name, d] of Object.entries(registry.dialogs)) {
      for (const t of d.tables) {
        expect(
          (registry.tables as Record<string, string>)[t],
          `${name} names ${t}`,
        ).toBeTruthy();
        expect(Object.keys(registry.exempt)).not.toContain(t);
      }
      for (const inc of d.includes) {
        expect(Object.keys(registry.dialogs)).toContain(inc);
      }
    }
  });

  it("names the rows the three reported dialogs left out", () => {
    expect(cascadeList("multicast_group")).toMatch(/AV flow/);
    expect(cascadeList("ip_address")).toMatch(/OT devices/);
    expect(cascadeList("ip_address")).toMatch(/BACnet\/IP devices/);
    expect(cascadeList("subnet")).toMatch(/address sets/);
    expect(cascadeList("subnet")).toMatch(/OT zones/);
    expect(cascadePhrases("ip_space")).toContain("VLAN mappings");
  });

  it("is what the dialogs actually read", () => {
    const src = (f: string) =>
      readFileSync(new URL(f, import.meta.url), "utf8");
    expect(src("../pages/network/MulticastGroupsPage.tsx")).toMatch(
      /cascadeList\("multicast_group"\)/,
    );
    expect(src("../pages/ipam/IPAMPage.tsx")).toMatch(
      /cascadeList\("ip_address"\)/,
    );
    const trash = src("../pages/admin/TrashPage.tsx");
    expect(trash).toMatch(/cascadeList\("subnet"\)/);
    expect(trash).toMatch(/cascadeList\("ip_space"\)/);
  });
});
