/**
 * Why a hostname named exactly "gateway" gets no forward DNS record (#2101),
 * and plain-words text for each Sync DNS stale reason code.
 *
 * Subnet create seeds a placeholder row on the first usable address with
 * hostname "gateway". Publishing every one of those would put one
 * gateway.<zone> per subnet in the zone, each at a different IP, so the
 * backend (`_sync_dns_record`) skips the forward A/AAAA record for that exact
 * hostname. The PTR is still published.
 */

export const GATEWAY_HOSTNAME = "gateway";

export const GATEWAY_FORWARD_SKIPPED_LABEL = "forward DNS skipped";

export const GATEWAY_FORWARD_SKIPPED_NOTE =
  "Hostnames named exactly 'gateway' get a PTR but no A/AAAA record, so every subnet's gateway doesn't collide on gateway.<zone>. Rename it (e.g. 'gw', 'core-rtr1') or add the A record by hand in the zone.";

/** True for a stored hostname the forward-record rule skips. Exact match,
 * like the backend's ``ip.hostname == "gateway"``: a row an integration wrote
 * as "Gateway" bypassed the API's normalisation and does get its A record. */
export function isDefaultGatewayHostname(
  hostname: string | null | undefined,
): boolean {
  return hostname === GATEWAY_HOSTNAME;
}

/** True for a hostname being TYPED that the API will store as "gateway".
 * ``validate_hostname`` trims, lower-cases and drops one trailing root dot,
 * so " Gateway." is saved as "gateway" and skipped all the same. */
export function isDefaultGatewayHostnameInput(
  hostname: string | null | undefined,
): boolean {
  return (
    (hostname ?? "").trim().replace(/\.$/, "").toLowerCase() ===
    GATEWAY_HOSTNAME
  );
}

const STALE_REASON_TEXT: Record<string, string> = {
  "ip-deleted": "The IPAM address this record belonged to no longer exists.",
  "ip-orphan":
    "The IPAM address is an orphan (no longer inside any managed subnet), so IPAM no longer publishes DNS for it.",
  "no-hostname":
    "The IPAM address has no hostname, so IPAM no longer publishes DNS for it.",
  "dynamic-lease-untracked":
    "This address is a dynamic DHCP lease on a scope that doesn't track leases in DNS.",
  "default-gateway-name":
    "The address is still in IPAM, but a hostname named exactly 'gateway' gets a PTR and no A/AAAA record, so every subnet's gateway doesn't collide on gateway.<zone>. Rename the host (e.g. 'gw', 'core-rtr1') or keep this record by adding it by hand instead.",
  "no-forward-zone":
    "The subnet has no forward zone now, so there is no domain to build the name from and the record can't be kept in sync.",
};

/** Plain-words sentence for a stale reason; unknown codes fall back to the code. */
export function staleReasonText(reason: string): string {
  return STALE_REASON_TEXT[reason] ?? `Reason: ${reason}`;
}

/** Stale reasons where the IPAM address still exists (so "no longer have a
 * live IPAM address" would be false for them). */
export function staleReasonKeepsAddress(reason: string): boolean {
  return reason !== "ip-deleted";
}

export type IpDnsState = "in-sync" | "out-of-sync" | "forward-skipped" | "n/a";

/** DNS column state for one IP row in the subnet table. */
export function classifyIpDnsState(opts: {
  status: string;
  hostname: string | null | undefined;
  subnetHasDnsZone: boolean;
  hasForwardZone: boolean;
  outOfSync: boolean;
}): IpDnsState {
  if (!opts.subnetHasDnsZone) return "n/a";
  if (
    opts.status === "network" ||
    opts.status === "broadcast" ||
    opts.status === "orphan"
  )
    return "n/a";
  if (!opts.hostname) return "n/a";
  // A "gateway" host gets a PTR but no forward record (#2101). A leftover
  // forward record is still drift and reads "out of sync".
  if (isDefaultGatewayHostname(opts.hostname)) {
    if (opts.outOfSync) return "out-of-sync";
    return opts.hasForwardZone ? "forward-skipped" : "n/a";
  }
  return opts.outOfSync ? "out-of-sync" : "in-sync";
}
