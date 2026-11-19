import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";

import { lookingGlassApi, type BGPLGRoute } from "@/lib/api";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";
import { cn } from "@/lib/utils";

// Issue #566 Phase 3 — per-space-scoped shared route fetch backing the
// "BGP" chip rendered on subnet + block rows in the IPAM tree. Mirrors
// the CustomerChip/SiteChip dedup pattern
// (frontend/src/components/ownership/pickers.tsx): every chip instance
// on a page shares one underlying React Query fetch instead of firing
// its own network call. Unlike customer_id/site_id (a raw FK column on
// the row itself), "does this subnet/block have an advertised route"
// lives on the *other* side of the relationship
// (BGPLGRoute.matched_subnet_id / matched_block_id), so the shared
// query here is a space-scoped route fetch rather than a per-row FK
// lookup.

const chipBaseCls =
  "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium";

const RPKI_CHIP_COLOR: Record<string, string> = {
  invalid: "border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  unknown:
    "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  valid:
    "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
};

/** One shared per-space route fetch backing every BgpAdvertisedChip on
 *  the page (subnet rows + block rows both call this with the same
 *  spaceId, so React Query dedupes to one request). */
function useBgpLgSpaceRoutes(spaceId: string, enabledModule: boolean) {
  const q = useQuery({
    queryKey: ["bgp-lg-routes-by-space", spaceId],
    queryFn: () =>
      lookingGlassApi.searchRoutes({
        matched_space_id: spaceId,
        withdrawn: false,
        limit: 1000,
      }),
    enabled: enabledModule && !!spaceId,
    staleTime: 30_000,
  });
  return useMemo(() => {
    const bySubnet = new Map<string, BGPLGRoute[]>();
    const byBlock = new Map<string, BGPLGRoute[]>();
    for (const r of q.data?.items ?? []) {
      if (r.matched_subnet_id) {
        const list = bySubnet.get(r.matched_subnet_id) ?? [];
        list.push(r);
        bySubnet.set(r.matched_subnet_id, list);
      }
      if (r.matched_block_id) {
        const list = byBlock.get(r.matched_block_id) ?? [];
        list.push(r);
        byBlock.set(r.matched_block_id, list);
      }
    }
    return { bySubnet, byBlock };
  }, [q.data]);
}

function worstRpki(routes: BGPLGRoute[]): string {
  // invalid > unknown > valid, worst-first for the chip's colour.
  if (routes.some((r) => r.rpki_status === "invalid")) return "invalid";
  if (routes.some((r) => r.rpki_status === "unknown")) return "unknown";
  return "valid";
}

/** Small "BGP" chip for a subnet or block row in the IPAM tree — shows
 *  when the row has at least one active advertised route, colour-coded
 *  by the worst RPKI status among its matched routes. Renders null when
 *  the network.looking_glass module is off, the user may not read the
 *  Looking Glass, or nothing matches. */
export function BgpAdvertisedChip({
  spaceId,
  subnetId,
  blockId,
  className,
}: {
  spaceId: string;
  subnetId?: string;
  blockId?: string;
  className?: string;
}) {
  const { enabled } = useFeatureModules();
  // The route search takes read on 'bgp_lg_peer'. Without it the search is
  // not asked, so opening a space no longer costs a 403 and a denied audit
  // row per space (#2745, the class of #2704).
  const canRead = usePermissions().can("read", "bgp_lg_peer");
  const lgEnabled = enabled("network.looking_glass") && canRead;
  const { bySubnet, byBlock } = useBgpLgSpaceRoutes(spaceId, lgEnabled);
  if (!lgEnabled) return null;
  const routes = subnetId
    ? bySubnet.get(subnetId)
    : blockId
      ? byBlock.get(blockId)
      : undefined;
  if (!routes || routes.length === 0) return null;
  const worst = worstRpki(routes);
  return (
    <span
      className={cn(chipBaseCls, RPKI_CHIP_COLOR[worst], className)}
      title={`Advertised by BGP — ${routes.length} route${routes.length === 1 ? "" : "s"}, worst RPKI: ${worst}`}
    >
      BGP
    </span>
  );
}
