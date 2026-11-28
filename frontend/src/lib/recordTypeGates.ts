// Record types only some DNS drivers can serve. Mirrors
// `_DRIVER_GATED_RECORD_TYPES` in backend/app/api/v1/dns/router.py: the API
// answers 422 for a type a group's drivers can't serve (#1778 added LOC), so
// the picker doesn't offer it. Keep the two in step.
const GATED_RECORD_TYPES: Record<string, readonly string[]> = {
  ALIAS: ["powerdns"],
  LUA: ["powerdns"],
  LOC: ["bind9", "powerdns"],
  SVCB: ["bind9", "powerdns", "technitium", "technitium_api"],
  HTTPS: ["bind9", "powerdns", "technitium", "technitium_api"],
  DNAME: ["bind9", "powerdns", "technitium", "technitium_api"],
};

/** True when every driver in the group can serve `type`. An empty group
 * (driver list unknown or no servers yet) offers everything, as the API does. */
export function recordTypeServable(
  type: string,
  groupDrivers: readonly string[],
): boolean {
  const allowed = GATED_RECORD_TYPES[type.toUpperCase()];
  if (!allowed || groupDrivers.length === 0) return true;
  return groupDrivers.every((d) => allowed.includes(d));
}
