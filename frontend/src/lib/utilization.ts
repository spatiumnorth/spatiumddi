/**
 * Shared helpers for the utilization-reporting filter.
 *
 * Operators exclude small PTP / loopback-style subnets from the
 * dashboard heatmap + the (incoming) alerts framework via two
 * PlatformSettings knobs: utilization_max_prefix_ipv4 (default 29,
 * excludes /30../32) and utilization_max_prefix_ipv6 (default 126,
 * excludes /127, /128). Anything with a prefix strictly greater than
 * the configured max is excluded from utilization-driven UI.
 *
 * `undefined` settings (still loading) → include everything, so the
 * dashboard doesn't blink empty on first paint.
 */

import type { PlatformSettingsPublic, Subnet } from "./api";

export function prefixOf(network: string): {
  prefix: number;
  family: 4 | 6;
} | null {
  const slash = network.lastIndexOf("/");
  if (slash < 0) return null;
  const prefix = parseInt(network.slice(slash + 1), 10);
  if (!Number.isFinite(prefix)) return null;
  const addr = network.slice(0, slash);
  return { prefix, family: addr.includes(":") ? 6 : 4 };
}

export function includeInUtilization(
  subnet: Pick<Subnet, "network">,
  settings:
    | Pick<
        PlatformSettingsPublic,
        "utilization_max_prefix_ipv4" | "utilization_max_prefix_ipv6"
      >
    | undefined,
): boolean {
  if (!settings) return true;
  const parsed = prefixOf(subnet.network);
  if (parsed === null) return true;
  const max =
    parsed.family === 4
      ? settings.utilization_max_prefix_ipv4
      : settings.utilization_max_prefix_ipv6;
  return parsed.prefix <= max;
}
