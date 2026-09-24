import { useQuery } from "@tanstack/react-query";

import {
  dhcpApi,
  type DHCPGroupFailover,
  type DHCPScopeServing,
} from "@/lib/api";

// Non-component helpers for WindowsFailoverPanel.tsx, split out so that file
// exports components only (react-refresh/only-export-components).

export const GROUP_FAILOVER_QUERY_KEY = "dhcp-group-failover";

/** #1110 — the group's Windows failover report (stored observations). */
export function useGroupFailover(groupId: string | undefined) {
  return useQuery({
    queryKey: [GROUP_FAILOVER_QUERY_KEY, groupId],
    queryFn: () => dhcpApi.getGroupFailover(groupId as string),
    enabled: !!groupId,
    staleTime: 30_000,
  });
}

/** Map a group's per-scope verdicts by dhcp_scope id, for table badges. */
export function servingByScopeId(
  report: DHCPGroupFailover | undefined,
): Map<string, DHCPScopeServing> {
  const out = new Map<string, DHCPScopeServing>();
  for (const s of report?.scopes ?? []) {
    if (s.scope_id) out.set(s.scope_id, s);
  }
  return out;
}
