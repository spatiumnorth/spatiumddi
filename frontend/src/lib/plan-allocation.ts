/**
 * The prefix a new row opens with. IPv4 starts 8 bits below the block; IPv6 at
 * /64, the smallest subnet that carries SLAAC (as New Subnet and the Subnet
 * Planner do, #3850). A v6 block already at /64 or longer has no /64 to offer,
 * so its field opens empty for the operator to fill (#4281).
 */
export function defaultPlanPrefix(v6: boolean, blockPrefix: number): string {
  if (v6) return blockPrefix < 64 ? "64" : "";
  return String(Math.min(blockPrefix + 8, 32));
}
