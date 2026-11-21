import { describe, expect, it } from "vitest";
import { HOST_TZ_ALIASES, canonicalHostTimezone } from "./hostTimezones";

describe("hostTimezones (#4416)", () => {
  it("canonicalises legacy aliases and leaves real names alone", () => {
    expect(canonicalHostTimezone("US/Pacific")).toBe("America/Los_Angeles");
    expect(canonicalHostTimezone("Asia/Calcutta")).toBe("Asia/Kolkata");
    expect(canonicalHostTimezone("Europe/Berlin")).toBe("Europe/Berlin");
    expect(canonicalHostTimezone("constructor")).toBe("constructor");
  });
  it("never maps to another alias", () => {
    for (const v of Object.values(HOST_TZ_ALIASES)) {
      expect(v in HOST_TZ_ALIASES).toBe(false);
    }
  });
});
