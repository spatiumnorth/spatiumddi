// Fill colour of a DHCP pool's occupancy bar (#3539).
//
// Pool occupancy is not subnet utilization: Settings' Warning / Critical
// Threshold are IPAM settings, and each `dhcp_pool_exhaustion` alert rule
// carries its own threshold, so there is no pool setting to follow. The
// fleet occupancy endpoint counts `pools_warning` / `pools_critical` at fixed
// 80 / 95 (`_POOL_WARNING_PERCENT` / `_POOL_CRITICAL_PERCENT` in
// backend/app/api/v1/dhcp/pools.py), and the Dashboard prints those counts as
// "Pools >= 80%" / "Pools >= 95%" right above the bars. The bars, there and
// on the DHCP page, band at the same lines so a pool is never amber beside a
// card that says no pool is at 80%.

export const POOL_OCCUPANCY_WARN = 80;
export const POOL_OCCUPANCY_CRITICAL = 95;

export function poolOccupancyTone(percent: number): string {
  return percent >= POOL_OCCUPANCY_CRITICAL
    ? "bg-red-500"
    : percent >= POOL_OCCUPANCY_WARN
      ? "bg-amber-400"
      : "bg-emerald-500";
}
