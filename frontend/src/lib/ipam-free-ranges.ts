// Whether the IP table draws the green "N free · click to allocate" rows
// between allocated addresses (#2137). Purely presentational.
//
// Precedence: the operator's session toggle > the subnet's own setting >
// the default rule below. The default is off where the rows are noise or
// misleading: an integration-mirrored subnet (the overlay assigns the
// addresses, SpatiumDDI only mirrors them, so "click to allocate" invites an
// allocation it will never honour) and anything larger than a /16 IPv4, where
// a sparse range turns most of the table into gap bars. IPv6 gap rows are
// not drawn at all today (the table builder only walks IPv4 ints); the
// equivalent threshold (shorter than /48) is kept so the default stays
// correct if they ever are.

import type { Subnet } from "@/lib/api";

export const FREE_RANGE_MIN_PREFIX_V4 = 16;
export const FREE_RANGE_MIN_PREFIX_V6 = 48;

type FreeRangeSubnet = Pick<
  Subnet,
  "network" | "show_free_ranges" | "integration_owner"
>;

/** The default when the subnet has no explicit setting. */
export function defaultShowFreeRanges(subnet: FreeRangeSubnet): boolean {
  if (subnet.integration_owner) return false;
  const [addr, len] = String(subnet.network).split("/");
  const prefix = Number(len);
  if (!Number.isFinite(prefix)) return true;
  const min = addr.includes(":")
    ? FREE_RANGE_MIN_PREFIX_V6
    : FREE_RANGE_MIN_PREFIX_V4;
  return prefix >= min;
}

/** Whether free-range rows show, before any session override. */
export function resolveShowFreeRanges(subnet: FreeRangeSubnet): boolean {
  return subnet.show_free_ranges ?? defaultShowFreeRanges(subnet);
}
