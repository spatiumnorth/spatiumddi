import type { QueryClient } from "@tanstack/react-query";

/**
 * Refetch every list a Trash restore or purge can change (#4205).
 *
 * The Trash holds IPAM, DNS, DHCP, customer, overlay and service rows, and
 * the pages that show them cache under dozens of first-element names
 * (`dns-records`, `subnets`, `blocks`, `customers`, `dhcp-scopes-subnet`, …)
 * that a prefix match on `["dns"]` / `["ipam"]` never reaches. Rather than
 * keep a list that rots every time a page gets a new query, mark every cached
 * query stale: only the mounted ones refetch, the rest refetch when next shown.
 */
export function invalidateAfterTrashChange(qc: QueryClient) {
  return qc.invalidateQueries({ predicate: () => true });
}
