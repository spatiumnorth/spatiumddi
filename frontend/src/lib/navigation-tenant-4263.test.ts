import { describe, expect, it } from "vitest";

import { ALL_NAV_DESTINATIONS, filterNav, navEntryVisible } from "./navigation";

const allOn = () => true;

describe("tenant users' navigation (#4263)", () => {
  it("offers a tenant user only the IPAM pages", () => {
    const shown = ALL_NAV_DESTINATIONS.filter((d) =>
      navEntryVisible(d, allOn, true),
    ).map((d) => d.to);
    expect(shown.sort()).toEqual(["/ipam", "/ipam/plans", "/ipam/stale"]);
  });

  it("leaves everyone else's navigation unchanged", () => {
    const all = ALL_NAV_DESTINATIONS.filter((d) => navEntryVisible(d, allOn));
    expect(all.length).toBe(ALL_NAV_DESTINATIONS.length);
    expect(filterNav(ALL_NAV_DESTINATIONS, allOn, false)).toHaveLength(
      ALL_NAV_DESTINATIONS.length,
    );
  });

  it("gates the Tenants page on its feature module", () => {
    const tenants = ALL_NAV_DESTINATIONS.find((d) => d.to === "/admin/tenants");
    expect(tenants?.module).toBe("ipam.tenants");
    expect(navEntryVisible(tenants!, () => false)).toBe(false);
    expect(navEntryVisible(tenants!, allOn)).toBe(true);
  });
});
