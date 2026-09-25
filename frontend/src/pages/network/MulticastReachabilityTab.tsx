import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, XCircle } from "lucide-react";

import { lookingGlassApi } from "@/lib/api";
import { zebraBodyCls } from "@/lib/utils";

/** Read-only cross-reference of PIM rendezvous-point addresses + multicast
 *  group producer source subnets against the BGP Looking Glass learned RIB
 *  (issue #566 Phase 6). Nothing persisted — computed on every load.
 *  Mounted only when the parent `MulticastGroupsPage` tab bar shows this
 *  entry, which is itself gated on the `network.looking_glass` feature
 *  module — see that file's `lgEnabled` check. */

function ReachBadge({ reachable }: { reachable: boolean }) {
  return reachable ? (
    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400">
      <CheckCircle2 className="h-3 w-3" /> Reachable
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full bg-rose-500/15 px-2 py-0.5 text-[10px] font-medium text-rose-700 dark:text-rose-400">
      <XCircle className="h-3 w-3" /> No route
    </span>
  );
}

export function MulticastReachabilityTab() {
  const { data, isFetching, error } = useQuery({
    queryKey: ["bgp-lg-multicast-reachability"],
    queryFn: () => lookingGlassApi.getMulticastReachability(),
  });

  const domains = data?.domains ?? [];
  const groups = data?.groups ?? [];

  return (
    <div className="space-y-6">
      <p className="text-xs text-muted-foreground">
        Cross-references PIM rendezvous-point addresses and multicast-group
        producer source subnets against the BGP Looking Glass learned RIB —
        read-only, computed live on every load.
      </p>
      {error && (
        <p className="text-sm text-destructive">Failed to load reachability.</p>
      )}

      <div>
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          PIM domain rendezvous points ({domains.length})
        </div>
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-xs">
            <thead className="bg-muted/30 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr className="border-b">
                <th className="px-3 py-2">Domain</th>
                <th className="px-3 py-2">RP address</th>
                <th className="px-3 py-2">Covering route</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {domains.length === 0 && !isFetching && (
                <tr>
                  <td
                    colSpan={4}
                    className="px-3 py-6 text-center text-muted-foreground"
                  >
                    No sparse/bidir PIM domains with a resolvable RP address.
                  </td>
                </tr>
              )}
              {domains.map((d) => (
                <tr
                  key={d.domain_id}
                  className="border-b last:border-0 hover:bg-muted/20"
                >
                  <td className="px-3 py-2 font-medium">{d.domain_name}</td>
                  <td className="px-3 py-2 font-mono text-muted-foreground">
                    {d.rp_address}
                  </td>
                  <td className="px-3 py-2 font-mono text-muted-foreground">
                    {d.covering_route ? d.covering_route.prefix : "—"}
                  </td>
                  <td className="px-3 py-2">
                    <ReachBadge reachable={!!d.covering_route} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Multicast group source subnets ({groups.length})
        </div>
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-xs">
            <thead className="bg-muted/30 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr className="border-b">
                <th className="px-3 py-2">Group</th>
                <th className="px-3 py-2">Source subnet</th>
                <th className="px-3 py-2">Covering route</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {groups.length === 0 && !isFetching && (
                <tr>
                  <td
                    colSpan={4}
                    className="px-3 py-6 text-center text-muted-foreground"
                  >
                    No multicast groups with a producer membership yet.
                  </td>
                </tr>
              )}
              {groups.map((g) => (
                <tr
                  key={`${g.group_id}-${g.source_subnet_id}`}
                  className="border-b last:border-0 hover:bg-muted/20"
                >
                  <td className="px-3 py-2 font-medium">{g.group_name}</td>
                  <td className="px-3 py-2 font-mono text-muted-foreground">
                    {g.source_subnet}
                  </td>
                  <td className="px-3 py-2 font-mono text-muted-foreground">
                    {g.covering_route ? g.covering_route.prefix : "—"}
                  </td>
                  <td className="px-3 py-2">
                    <ReachBadge reachable={!!g.covering_route} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
