// #1238 — Kea HA covers DHCPv4 only. The agent renders `libdhcp_ha.so`
// into the `Dhcp4` config alone, and the HA state every surface shows is
// read from the DHCPv4 daemon's control socket. A DHCPv6 scope on a group
// with two or more Kea members is served by each member on its own. Real
// DHCPv6 HA is #1258; until then every place that shows HA state says
// which protocol it covers, and a v6 scope on such a group is flagged.

export const HA_V4_ONLY_NOTE =
  "HA covers DHCPv4 only. DHCPv6 scopes are served by each member on its own, with no lease coordination.";

/** Tooltip for an HA state pill: the heartbeat, then what HA covers. */
export function haPillTitle(
  lastHeartbeatAt: string | null | undefined,
): string {
  const beat = lastHeartbeatAt
    ? `Last HA heartbeat ${new Date(lastHeartbeatAt).toLocaleString()}`
    : "No HA heartbeat received yet";
  return `${beat}. ${HA_V4_ONLY_NOTE}`;
}

/**
 * True when a DHCPv6 scope sits on a group with two or more Kea members.
 *
 * Deliberately not "the group's HA hook is rendered": that also needs every
 * member's peer URL, but a v6 scope is served uncoordinated by every Kea
 * member either way. A group whose membership is unknown (not loaded yet)
 * reads as false, so the flag never appears on a guess.
 */
export function v6ScopeLacksHa(
  scope: { address_family?: "ipv4" | "ipv6" },
  group: { kea_member_count?: number } | null | undefined,
): boolean {
  return scope.address_family === "ipv6" && (group?.kea_member_count ?? 0) >= 2;
}

export function v6ScopeNoHaNote(keaMemberCount: number): string {
  return (
    `This group has ${keaMemberCount} Kea members, and HA covers DHCPv4 only. ` +
    "Each member serves this DHCPv6 scope on its own: leases are not shared, " +
    "so two members can hand the same address to different clients. " +
    "To avoid that, serve DHCPv6 from a group with one Kea member."
  );
}
