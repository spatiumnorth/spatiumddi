/** #2446 — one wording for "delete a DHCP scope", used by the Scopes tab and
 *  the IPAM subnet panel. The delete is a soft-delete of the scope with its
 *  pools and reservations as one set, restorable from Trash by a
 *  superadmin (every Trash route is superadmin-only, #2706). */
export function scopeDeleteCopy(
  scopeName: string,
  poolCount: number,
  staticCount: number,
) {
  const references: string[] = [];
  if (poolCount)
    references.push(`${poolCount} pool${poolCount === 1 ? "" : "s"}`);
  if (staticCount)
    references.push(
      `${staticCount} reservation${staticCount === 1 ? "" : "s"}`,
    );
  return {
    description:
      `Delete scope "${scopeName}"? ` +
      "Its pools and reservations go with it — they stop being served straight " +
      "away. A superadmin can restore them as a set from Administration → " +
      "Trash. Any " +
      "dynamic clients (leases) it learned are released too, and their IPAM " +
      "and DNS entries removed.",
    referencesTitle: references.length
      ? "This scope currently has:"
      : undefined,
    references: references.length ? references : undefined,
    acknowledgement:
      "I understand the scope and its pools and reservations will be removed.",
  };
}
