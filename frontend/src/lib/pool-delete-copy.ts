/**
 * The sentence in the "Delete pool" confirm (#2603).
 *
 * A pool publishes a record only for an ENABLED member of an ENABLED pool whose
 * last check was healthy (`pool_apply.py`), so the member total is not the
 * number of records the zone serves. Say what is published, and where nothing
 * is, say that deleting withdraws nothing from the zone.
 */
export function poolDeleteSummary(p: {
  name: string;
  fqdn: string;
  recordType: string;
  poolEnabled: boolean;
  memberCount: number;
  publishedCount: number;
}): string {
  const members = `${p.memberCount} member${p.memberCount === 1 ? "" : "s"}`;
  if (p.publishedCount > 0) {
    return `Delete pool ${p.name} and its ${members}? It currently publishes ${p.publishedCount} record${p.publishedCount === 1 ? "" : "s"} as ${p.fqdn} ${p.recordType}, which are removed from the zone.`;
  }
  const why = p.poolEnabled
    ? "no enabled member is healthy"
    : "the pool is disabled";
  return `Delete pool ${p.name} and its ${members}? It publishes no record as ${p.fqdn} ${p.recordType} at the moment (${why}), so nothing is removed from the zone.`;
}
