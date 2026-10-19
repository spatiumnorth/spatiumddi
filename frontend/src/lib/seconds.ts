/**
 * Reading a number of seconds out of a text field (#2110).
 *
 * `parseInt("1h")` is 1, `parseInt("")` is NaN and `|| 60` turns that into a
 * value the operator never typed, so every interval field that read itself
 * that way saved a different number than the one on screen. This is the one
 * reader: a whole number inside the API's own bounds, refused with a reason
 * otherwise, and `null` for an empty field so the caller decides what empty
 * means (here: required, never "the default").
 */

/** Postgres `integer` ceiling: the cap where the API itself states none. */
export const INT32_MAX = 2147483647;

export interface SecondsBounds {
  min: number;
  max?: number;
}

/**
 * The number in `text`, `null` when it is empty, or a reason string when it is
 * not a whole number in `min..max`. Never `parseInt`: it reads `"1h"` as 1 and
 * `"1e3"` (a number input accepts it) as 1.
 */
export function parseSecondsInput(
  text: string,
  bounds: SecondsBounds,
): number | null | string {
  const t = text.trim();
  if (t === "") return null;
  const max = bounds.max ?? INT32_MAX;
  const n = Number(t);
  if (!Number.isInteger(n) || n < bounds.min || n > max) {
    return max >= INT32_MAX
      ? `must be a whole number of seconds, at least ${bounds.min}`
      : `must be a whole number of seconds from ${bounds.min} to ${max}`;
  }
  return n;
}

/**
 * A form-level message for a seconds field that cannot be submitted, or `null`
 * when it can. An empty field is "required": on update, omitting the field
 * means "unchanged", so substituting a default would silently rewrite it.
 */
export function secondsFieldError(
  label: string,
  text: string,
  bounds: SecondsBounds,
): string | null {
  const parsed = parseSecondsInput(text, bounds);
  if (parsed === null) return `${label} is required.`;
  if (typeof parsed === "string") return `${label} ${parsed}.`;
  return null;
}

/** Integration sync intervals: the API's `sync_interval_seconds >= 30` floor. */
export const SYNC_INTERVAL_BOUNDS: SecondsBounds = { min: 30 };

/** Cloud connectors floor at 60 (`api/v1/cloud`). */
export const CLOUD_SYNC_INTERVAL_BOUNDS: SecondsBounds = { min: 60 };

/** Network device polling / SNMP timeout: the API only requires `>= 0`. */
export const DEVICE_SECONDS_BOUNDS: SecondsBounds = { min: 0 };

/** DNS pool health check: `hc_interval_seconds` ge=10, le=3600. */
export const POOL_HC_INTERVAL_BOUNDS: SecondsBounds = { min: 10, max: 3600 };

/** DNS pool health check: `hc_timeout_seconds` ge=1, le=60. */
export const POOL_HC_TIMEOUT_BOUNDS: SecondsBounds = { min: 1, max: 60 };
