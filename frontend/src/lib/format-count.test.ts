import { describe, expect, it } from "vitest";
import { formatCount } from "./format-count";

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
