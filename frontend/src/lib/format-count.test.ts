import { describe, expect, it } from "vitest";
import { cidrAddressCountExact, formatCount } from "./format-count";

describe("formatCount (#3322)", () => {
  it("prints a /64 and a /63 exactly and apart", () => {
    const a = formatCount("18446744073709551616", 2 ** 63);
    const b = formatCount("36893488147419103232", 2 ** 63);
    expect(a.replace(/\D/g, "")).toBe("18446744073709551616");
    expect(b.replace(/\D/g, "")).toBe("36893488147419103232");
  });
  it("prints a count that is not a power of two exactly", () => {
    // 2^64 - 2: past 2^53, so a number would round it.
    const s = formatCount("18446744073709551614");
    expect(s.replace(/\D/g, "")).toBe("18446744073709551614");
  });
  it("falls back to the number, and to a dash with neither", () => {
    expect(formatCount(undefined, 254)).toBe("254");
    expect(formatCount(null, null)).toBe("—");
    expect(formatCount("not-a-number", 7)).toBe("7");
  });
});

describe("cidrAddressCountExact (#3708)", () => {
  it("computes an IPv6 block's size exactly", () => {
    expect(cidrAddressCountExact("fd00::/56")).toBe("4722366482869645213696");
    expect(cidrAddressCountExact("fd00::/50")).toBe("302231454903657293676544");
  });
  it("computes an IPv4 size and refuses a non-CIDR", () => {
    expect(cidrAddressCountExact("10.0.0.0/24")).toBe("256");
    expect(cidrAddressCountExact("10.0.0.1")).toBeNull();
    expect(cidrAddressCountExact("10.0.0.0/33")).toBeNull();
  });
});
