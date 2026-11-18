import { afterEach, describe, expect, it, vi } from "vitest";
import { isValidTimeZone, timeZoneSuggestions } from "./timezones";

/** Chromium-like Intl: the zone list has no "UTC". */
function stubZones(list: string[]) {
  vi.stubGlobal(
    "Intl",
    Object.assign(Object.create(Intl), { supportedValuesOf: () => list }),
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("isValidTimeZone (#4409)", () => {
  it("accepts UTC and aliases even when supportedValuesOf omits them", () => {
    stubZones(["Europe/Paris"]);
    for (const z of ["UTC", "Etc/UTC", "US/Pacific", "Europe/Paris"]) {
      expect(isValidTimeZone(z), z).toBe(true);
    }
  });

  it("refuses what the API's zoneinfo would", () => {
    for (const z of ["", "  ", "Mars/Base", "garbage", "+01:00", "utc"]) {
      expect(isValidTimeZone(z), z).toBe(false);
    }
  });

  it("suggests UTC first, once", () => {
    stubZones(["Africa/Cairo", "UTC"]);
    expect(timeZoneSuggestions()).toEqual(["UTC", "Africa/Cairo"]);
  });
});
