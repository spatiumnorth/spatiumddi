import { describe, expect, it } from "vitest";

import { summarizeZoneNames } from "./dnsNames";

describe("summarizeZoneNames (#1840)", () => {
  it("joins a short list whole", () => {
    expect(
      summarizeZoneNames(["2.55.10.in-addr.arpa.", "3.55.10.in-addr.arpa."]),
    ).toBe("2.55.10.in-addr.arpa., 3.55.10.in-addr.arpa.");
  });

  it("cuts a /17's 128 zones to the first four and a count", () => {
    const names = Array.from(
      { length: 128 },
      (_, i) => `${128 + i}.60.10.in-addr.arpa.`,
    );
    expect(summarizeZoneNames(names)).toBe(
      "128.60.10.in-addr.arpa., 129.60.10.in-addr.arpa., 130.60.10.in-addr.arpa., " +
        "131.60.10.in-addr.arpa. + 124 more",
    );
  });

  it("is empty for no zones", () => {
    expect(summarizeZoneNames([])).toBe("");
  });
});
