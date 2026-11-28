import { IANA_TIME_ZONES } from "./tzNames";

/**
 * Time-zone validation shared by the wake-schedule dialog and the platform
 * time-zone field (#4409).
 *
 * ``Intl.supportedValuesOf("timeZone")`` is a list of *canonical* names:
 * Chromium leaves out "UTC" and "Etc/UTC", and every alias ("US/Pacific").
 * Checking membership of that list alone refuses zones the API accepts,
 * UTC being the API's own default.
 *
 * The API validates with ``zoneinfo.ZoneInfo``: case-sensitive, no offsets.
 * ``Intl`` folds case ("etc/utc", "us/pacific") and takes offsets
 * ("+01:00"), so a name is accepted only when the engine knows it AND its
 * exact spelling is one zoneinfo knows: the bundled tzdata name set, or the
 * engine's own canonical list (zones newer than the bundle).
 */

export function isValidTimeZone(name: string): boolean {
  const n = name.trim();
  if (n === "" || /^[+-]/.test(n)) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: n });
  } catch {
    return false;
  }
  return IANA_TIME_ZONES.has(n) || timeZoneSuggestions().includes(n);
}

/** Autocomplete suggestions: the engine's list plus "UTC", UTC first. */
export function timeZoneSuggestions(): string[] {
  let list: string[] = [];
  try {
    const I = Intl as typeof Intl & {
      supportedValuesOf?: (key: "timeZone") => string[];
    };
    if (typeof I.supportedValuesOf === "function") {
      list = I.supportedValuesOf("timeZone");
    }
  } catch {
    list = [];
  }
  return ["UTC", ...list.filter((z) => z !== "UTC")];
}
