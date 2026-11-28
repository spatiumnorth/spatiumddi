/** Which DNS drivers serve split-horizon views (#4565).
 *
 *  Mirrors the backend's `capabilities()["views"]`: BIND9 alone answers by
 *  client address. The API refuses a view on any other group; this keeps the
 *  form from offering what it would refuse. */
export const VIEWS_DRIVERS: readonly string[] = ["bind9"];

/** The drivers among `drivers` that cannot serve views, sorted and distinct.
 *  Empty for a group with no servers: nothing there says otherwise yet. */
export function viewsUnsupportedDrivers(drivers: readonly string[]): string[] {
  return Array.from(
    new Set(drivers.filter((d) => d && !VIEWS_DRIVERS.includes(d))),
  ).sort();
}

/** Why a group on `drivers` cannot take a new view, or null when it can. */
export function viewsUnsupportedReason(
  drivers: readonly string[],
): string | null {
  const bad = viewsUnsupportedDrivers(drivers);
  if (bad.length === 0) return null;
  return `Views are not supported on ${bad.join(" / ")}: only BIND9 answers by client address. Use a BIND9 group for views.`;
}
