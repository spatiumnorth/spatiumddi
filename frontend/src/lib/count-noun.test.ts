import { describe, expect, it } from "vitest";
import { countNoun } from "./count-noun";

describe("countNoun", () => {
  it("uses the singular for exactly one", () => {
    expect(countNoun(1, "space")).toBe("1 space");
    expect(countNoun(1, "entry", "entries")).toBe("1 entry");
  });
  it("uses the plural otherwise, including zero", () => {
    expect(countNoun(0, "space")).toBe("0 spaces");
    expect(countNoun(2, "entry", "entries")).toBe("2 entries");
  });
});
