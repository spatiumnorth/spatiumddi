import { describe, expect, it } from "vitest";

import {
  nameInZoneError,
  parseTtlInput,
  reversePointerName,
  summarizeZoneNames,
  zoneKindForName,
} from "./dnsNames";

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

describe("nameInZoneError (#2072)", () => {
  const host = ["a", "b", "c", "d"].map((c) => c.repeat(60)).join(".");

  it("refuses a valid hostname whose name in the zone passes 253", () => {
    expect(host.length).toBe(243);
    expect(nameInZoneError(host, "example-zone.test.")).toContain("261");
  });

  it("accepts a name that fits, with or without the root dot", () => {
    expect(nameInZoneError("web01", "example.test")).toBeNull();
    expect(nameInZoneError("web01", "example.test.")).toBeNull();
    expect(
      nameInZoneError("x".repeat(40), "y".repeat(63) + ".test"),
    ).toBeNull();
  });

  // Same boundary vectors as test_name_in_zone_length_2072.py.
  it("puts the boundary at 253 characters, root dot ignored", () => {
    const zone = "z".repeat(60) + ".test"; // 65
    const fits = "h".repeat(63) + "." + "i".repeat(63) + "." + "j".repeat(59); // 187
    expect(`${fits}.${zone}`.length).toBe(253);
    expect(nameInZoneError(fits, zone)).toBeNull();
    expect(nameInZoneError(fits, zone + ".")).toBeNull();
    expect(nameInZoneError(fits + ".", zone + "..")).toBeNull();
    expect(nameInZoneError(fits + "j", zone)).toContain("254");
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

describe("zoneKindForName: a name that merely contains arpa is forward (#3079)", () => {
  it.each([
    ["arpa-corp.example.", "forward"],
    ["myarpa.lan.", "forward"],
    ["harpa.example.", "forward"],
    ["1.168.192.in-addr.arpa.", "reverse"],
    ["8.b.d.0.1.0.0.2.ip6.arpa.", "reverse"],
  ])("%s is %s", (name, kind) => {
    expect(zoneKindForName(name)).toBe(kind);
  });
});

describe("reversePointerName (#3210)", () => {
  it("builds the in-addr.arpa owner for IPv4", () => {
    expect(reversePointerName("192.168.0.22")).toBe(
      "22.0.168.192.in-addr.arpa",
    );
  });
  it("builds the nibble ip6.arpa owner for IPv6", () => {
    expect(reversePointerName("2001:db8::1")).toBe(
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
    );
  });
  it("returns null for something that is not an address", () => {
    expect(reversePointerName("not-an-ip")).toBeNull();
    expect(reversePointerName("300.1.1.1")).toBeNull();
    expect(reversePointerName("::ffff:1.2.3.4")).toBeNull();
  });
});
