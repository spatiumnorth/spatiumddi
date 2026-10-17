import { describe, expect, it } from "vitest";

import { parseTtlInput, summarizeZoneNames } from "./dnsNames";

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

describe("parseTtlInput (#2073 / #2074)", () => {
  it.each([
    ["3600", 3600],
    [" 0 ", 0],
    ["2147483647", 2147483647],
    ["1e3", 1000],
  ])("reads %j as %d", (text, n) => {
    expect(parseTtlInput(text)).toBe(n);
  });

  it("reads blank as null (inherit)", () => {
    expect(parseTtlInput("  ")).toBeNull();
  });

  it.each([["1h"], ["-1"], ["1.5"], ["2147483648"], ["abc"]])(
    "refuses %j with a reason",
    (text) => {
      expect(typeof parseTtlInput(text)).toBe("string");
    },
  );
});
