import type { ApplianceRow } from "@/lib/api";

/**
 * #1284 — a row whose eviction (Fleet → Replace) is still pending is not
 * offered for promotion, and neither is any row that shares its hostname.
 *
 * Until the seed confirms an eviction it removes every etcd member named
 * `<hostname>-<8 hex>` on each heartbeat, so a node promoted into that name
 * meanwhile would join, become a voter, and lose its member on the seed's next
 * tick. The server refuses that promote (409); this keeps the picker from
 * offering it. `evict_requested` is not in the row schema, but Replace stamps
 * `evicting` beside it and the seed's settle clears both together, so the
 * state alone says it. Hostnames compare case-blind, as the server does.
 */
export function hostnamesBeingEvicted(rows: ApplianceRow[]): Set<string> {
  const out = new Set<string>();
  for (const r of rows) {
    if (r.cluster_join_state === "evicting" && r.hostname) {
      out.add(r.hostname.toLowerCase());
    }
  }
  return out;
}

export function heldByEviction(
  row: ApplianceRow,
  evicting: Set<string>,
): boolean {
  return (
    row.cluster_join_state === "evicting" ||
    (!!row.hostname && evicting.has(row.hostname.toLowerCase()))
  );
}
