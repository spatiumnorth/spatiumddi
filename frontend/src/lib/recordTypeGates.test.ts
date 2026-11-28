import { describe, expect, it } from "vitest";
import { recordTypeServable } from "./recordTypeGates";

describe("recordTypeServable (#1778)", () => {
  it("hides LOC on both Technitium drivers", () => {
    expect(recordTypeServable("LOC", ["technitium"])).toBe(false);
    expect(recordTypeServable("LOC", ["technitium_api"])).toBe(false);
  });
  it("keeps LOC on bind9 and powerdns", () => {
    expect(recordTypeServable("LOC", ["bind9"])).toBe(true);
    expect(recordTypeServable("LOC", ["powerdns"])).toBe(true);
  });
  it("hides a type when any driver in the group cannot serve it", () => {
    expect(recordTypeServable("LOC", ["bind9", "technitium"])).toBe(false);
  });
  it("offers everything for an empty or unknown group and ungated types", () => {
    expect(recordTypeServable("LOC", [])).toBe(true);
    expect(recordTypeServable("A", ["technitium"])).toBe(true);
  });
});
