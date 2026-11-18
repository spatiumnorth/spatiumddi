/**
 * Time-zone validation shared by the wake-schedule dialog and the platform
 * time-zone field (#4409).
 *
 * ``Intl.supportedValuesOf("timeZone")`` is a list of *canonical* names:
 * Chromium leaves out "UTC" and "Etc/UTC", and every alias ("US/Pacific").
 * Checking membership of that list therefore refuses zones the API accepts,
 * UTC being the API's own default. Validity is asked of the engine instead,
 * through ``Intl.DateTimeFormat``, which resolves aliases too.
 *
 * The API validates with ``zoneinfo.ZoneInfo``, which is case-sensitive and
 * has no offsets. ``Intl`` accepts both ("utc", "+01:00"), so those two are
 * refused here to keep the form from accepting what the API then 422s.
 */

export function isValidTimeZone(name: string): boolean {
  const n = name.trim();
  if (n === "" || /^[+-]/.test(n)) return false;
  try {
    const resolved = new Intl.DateTimeFormat("en-US", {
      timeZone: n,
    }).resolvedOptions().timeZone;
    // Same name apart from case: Intl folds it, zoneinfo does not.
    if (resolved.toLowerCase() === n.toLowerCase() && resolved !== n) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
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
