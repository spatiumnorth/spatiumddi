import { describe, expect, it } from "vitest";

import { viewsUnsupportedDrivers, viewsUnsupportedReason } from "./dns-views";

describe("views support by driver (#4565)", () => {
  it("lets a BIND9 group and an empty group take views", () => {
    expect(viewsUnsupportedReason(["bind9"])).toBeNull();
    expect(viewsUnsupportedReason([])).toBeNull();
  });

  it("refuses every other driver, naming it", () => {
    for (const d of ["powerdns", "technitium", "windows_dns", "route53"]) {
      expect(viewsUnsupportedReason([d])).toContain(d);
    }
  });

  it("names each unable driver once, sorted", () => {
    expect(
      viewsUnsupportedDrivers(["powerdns", "bind9", "powerdns", "azure_dns"]),
    ).toEqual(["azure_dns", "powerdns"]);
  });
});
