import { describe, expect, it } from "vitest";
import {
  parseSecondsInput,
  secondsFieldError,
  SYNC_INTERVAL_BOUNDS,
} from "./seconds";
import { parseTtlInput } from "./dnsNames";

describe("parseSecondsInput (#2110)", () => {
  it.each(["1h", "30s", "1.5", "-1", "abc", "29", "Infinity"])(
    "refuses %j with a reason",
    (text) => {
      expect(typeof parseSecondsInput(text, SYNC_INTERVAL_BOUNDS)).toBe(
        "string",
      );
    },
  );

  it("reads 1e3 as 1000 and trims", () => {
    expect(parseSecondsInput("1e3", SYNC_INTERVAL_BOUNDS)).toBe(1000);
    expect(parseSecondsInput(" 45 ", SYNC_INTERVAL_BOUNDS)).toBe(45);
  });

  it("returns null for an empty field", () => {
    expect(parseSecondsInput("", SYNC_INTERVAL_BOUNDS)).toBeNull();
    expect(parseSecondsInput("  ", SYNC_INTERVAL_BOUNDS)).toBeNull();
  });

  it("enforces both ends when a max is given", () => {
    const b = { min: 10, max: 3600 };
    expect(parseSecondsInput("10", b)).toBe(10);
    expect(parseSecondsInput("3600", b)).toBe(3600);
    expect(parseSecondsInput("9", b)).toMatch(/from 10 to 3600/);
    expect(parseSecondsInput("3601", b)).toMatch(/from 10 to 3600/);
  });

  it("has no upper bound beyond the integer column when none is given", () => {
    expect(parseSecondsInput("86400", SYNC_INTERVAL_BOUNDS)).toBe(86400);
    expect(parseSecondsInput("2147483648", SYNC_INTERVAL_BOUNDS)).toMatch(
      /at least 30/,
    );
  });

  it("is the reader parseTtlInput delegates to", () => {
    expect(parseTtlInput("1h")).toBe(parseSecondsInput("1h", { min: 0 }));
  });
});

describe("secondsFieldError", () => {
  it("names the field and calls an empty one required", () => {
    expect(secondsFieldError("Sync interval", "", SYNC_INTERVAL_BOUNDS)).toBe(
      "Sync interval is required.",
    );
    expect(secondsFieldError("Sync interval", "1h", SYNC_INTERVAL_BOUNDS)).toBe(
      "Sync interval must be a whole number of seconds, at least 30.",
    );
    expect(
      secondsFieldError("Sync interval", "60", SYNC_INTERVAL_BOUNDS),
    ).toBeNull();
  });
});
