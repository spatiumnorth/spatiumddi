// Kea HA runs per daemon (#1258): kea-dhcp4 and kea-dhcp6 are separate
// processes, each with its own HA hook, listener and state machine, so every
// surface that shows HA state names the protocol (`HA v4` / `HA v6`). DHCPv6
// HA needs every member's agent to render the v6 hook; until the control plane
// reports the group as `ha_v6_ready`, a stateful v6 scope on a multi-Kea group
// is served by each member on its own and is flagged.

export const HA_PROTOCOLS_NOTE =
  "DHCPv4 and DHCPv6 run separate HA relationships, each with its own state.";

/** Tooltip for an HA state pill: the heartbeat, then what the pill covers. */
export function haPillTitle(
  lastHeartbeatAt: string | null | undefined,
  family: "v4" | "v6" = "v4",
): string {
  const beat = lastHeartbeatAt
    ? `Last HA heartbeat ${new Date(lastHeartbeatAt).toLocaleString()}`
    : "No HA heartbeat received yet";
  return `${beat}. This is the DHCP${family} daemon's HA state. ${HA_PROTOCOLS_NOTE}`;
}

/**
 * True when an enabled, stateful DHCPv6 scope sits on a group with two or
 * more Kea members whose DHCPv6 HA is not active (`ha_v6_ready` false: a
 * member's agent predates it, or the group renders no HA at all).
 *
 * A group whose membership is unknown (not loaded yet) reads as false, so
 * the flag never appears on a guess.
 *
 * Only a scope that ALLOCATES addresses is at risk: a `stateless` scope
 * serves options only and a `slaac` one renders nothing, so two members
 * answering it independently hand out identical option sets and no
 * address. A disabled scope is not in the bundle at all. Flagging either
 * would warn about a duplicate-address hazard that cannot happen.
 */
export function v6ScopeLacksHa(
  scope: {
    address_family?: "ipv4" | "ipv6";
    v6_address_mode?: "stateful" | "stateless" | "slaac";
    enabled?: boolean;
  },
  group:
    | { kea_member_count?: number; ha_v6_ready?: boolean }
    | null
    | undefined,
): boolean {
  return (
    scope.address_family === "ipv6" &&
    (scope.v6_address_mode ?? "stateful") === "stateful" &&
    scope.enabled !== false &&
    (group?.kea_member_count ?? 0) >= 2 &&
    group?.ha_v6_ready !== true
  );
}

export function v6ScopeNoHaNote(keaMemberCount: number): string {
  return (
    `This group has ${keaMemberCount} Kea members, but DHCPv6 HA is not active: ` +
    "a member's agent has not reported DHCPv6 HA support yet (upgrade it), or the group has no HA peer URLs. " +
    "Until then each member serves this DHCPv6 scope on its own: leases are not shared, " +
    "so two members can hand the same address to different clients."
  );
}
