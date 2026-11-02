import { describe, expect, it } from "vitest";
import { formatCount } from "./format-count";

describe("formatCount (#3322)", () => {
  it("prints a /64 and a /63 exactly and apart", () => {
    const a = formatCount(2 ** 64);
    const b = formatCount(2 ** 65);
    expect(a.replace(/\D/g, "")).toBe("18446744073709551616");
    expect(b.replace(/\D/g, "")).toBe("36893488147419103232");
  });
  it("leaves small counts and nulls alone", () => {
    expect(formatCount(254)).toBe("254");
    expect(formatCount(null)).toBe("—");
  });
});
