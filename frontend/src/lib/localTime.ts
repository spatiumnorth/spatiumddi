/**
 * Local-time <-> UTC helpers for form inputs and date-only values (#2260).
 *
 * Two bug classes live here, both silent and both a function of the browser's
 * UTC offset (#500 fixed the first for one field; #2260 swept the rest):
 *
 * 1. A UTC ISO instant sliced to 16 chars and fed to a ``datetime-local``
 *    input shows the UTC wall clock as if it were local; the save then
 *    re-parses it as local, so every open -> save shifts the instant by the
 *    offset. Use ``toLocalInputValue`` / ``fromLocalInputValue``.
 * 2. ``new Date("YYYY-MM-DD")`` parses as UTC midnight, so west of UTC the
 *    date renders a day early and a day counter is off by one. Use
 *    ``parseDateOnly`` (local midnight).
 *
 * ``localTime.test.ts`` scans the sources and fails on either shape.
 */

/** UTC ISO instant -> ``YYYY-MM-DDTHH:MM`` in the browser's local zone. */
export function toLocalInputValue(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
}

/** ``datetime-local`` value (local wall clock) -> UTC ISO instant, or null. */
export function fromLocalInputValue(value: string): string | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** ``YYYY-MM-DD`` -> that calendar day at local midnight. */
export function parseDateOnly(value: string): Date {
  return new Date(`${value.slice(0, 10)}T00:00:00`);
}

/** A date-only value rendered as its own calendar day, in any zone. */
export function formatDateOnly(value: string): string {
  return parseDateOnly(value).toLocaleDateString();
}

/**
 * Whole days from today to a term's end date. The end date is INCLUSIVE: on
 * the last day this is 0 (still in term), and it goes negative only the day
 * after.
 */
export function termDaysLeft(termEnd: string, now: Date = new Date()): number {
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  // round, not floor: a DST change makes a local day 23 or 25 hours.
  return Math.round(
    (parseDateOnly(termEnd).getTime() - today.getTime()) / 86_400_000,
  );
}
