import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Check } from "lucide-react";

import {
  asnsApi,
  lookingGlassApi,
  type BGPLGRoute,
  type BGPLGRouteQuery,
  type BGPLGRpkiStatus,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Field, errMsg, inputCls } from "../_shared";
import { RouteDetailModal } from "./RouteDetailModal";
import { FormError } from "@/components/ui/form-error";

const SEARCH_PAGE_SIZE = 100;

const RPKI_COLOR: Record<BGPLGRpkiStatus, string> = {
  invalid: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
  unknown: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  valid: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
};

function Pill({ text, cls }: { text: string; cls: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        cls,
      )}
    >
      {text}
    </span>
  );
}

type RouteSortKey = "prefix" | "origin_asn" | "local_pref" | "med";
type RouteSortState = { key: RouteSortKey; dir: "asc" | "desc" };

// Cycle a sort spec asc → desc → cleared for a clicked column, mirroring
// the IPAM address table's ``cycleSort`` (issue #519). Client-side only —
// applied over whatever page is currently loaded, since the server always
// orders by (prefix, peer_id).
function cycleRouteSort(
  prev: RouteSortState | null,
  key: RouteSortKey,
): RouteSortState | null {
  if (!prev || prev.key !== key) return { key, dir: "asc" };
  if (prev.dir === "asc") return { key, dir: "desc" };
  return null;
}

function compareRoutes(
  a: BGPLGRoute,
  b: BGPLGRoute,
  key: RouteSortKey,
): number {
  switch (key) {
    case "prefix":
      return a.prefix.localeCompare(b.prefix);
    case "origin_asn":
      return (a.origin_asn ?? -1) - (b.origin_asn ?? -1);
    case "local_pref":
      return (a.local_pref ?? -1) - (b.local_pref ?? -1);
    case "med":
      return (a.med ?? -1) - (b.med ?? -1);
    default:
      return 0;
  }
}

function RouteSortLabel({
  label,
  sortKey,
  state,
  onSort,
}: {
  label: string;
  sortKey: RouteSortKey;
  state: RouteSortState | null;
  onSort: (key: RouteSortKey) => void;
}) {
  const active = state?.key === sortKey;
  const sortedDesc = active
    ? `sorted ${state?.dir === "asc" ? "ascending" : "descending"}`
    : "not sorted";
  const nextDesc = !active
    ? "sort ascending"
    : state?.dir === "asc"
      ? "sort descending"
      : "clear the sort";
  const a11yLabel = `${label} — ${sortedDesc}. Activate to ${nextDesc}.`;
  return (
    <button
      type="button"
      onClick={() => onSort(sortKey)}
      title={a11yLabel}
      aria-label={a11yLabel}
      className={cn(
        "inline-flex items-center gap-1 hover:text-foreground",
        active && "text-primary",
      )}
    >
      <span>{label}</span>
      <span className="text-[9px] leading-none">
        {active ? (state?.dir === "asc" ? "▲" : "▼") : "⇅"}
      </span>
    </button>
  );
}

function toOptionalInt(s: string): number | undefined {
  if (!s.trim()) return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? n : undefined;
}

type AppliedFilters = {
  prefix: string;
  originAsn: string;
  community: string;
  rpki: BGPLGRpkiStatus | "";
  peerId: string;
  bestPathOnly: boolean;
  withdrawn: boolean;
};

const EMPTY_FILTERS: AppliedFilters = {
  prefix: "",
  originAsn: "",
  community: "",
  rpki: "",
  peerId: "",
  bestPathOnly: false,
  withdrawn: false,
};

export function RoutesTab({
  initialPeerId,
}: {
  /** Pre-select the Peer filter — set when the tab is reached via the
   *  Sessions-tab peer detail modal's "View all routes" deep link
   *  (``?tab=routes&peer=<id>``). */
  initialPeerId?: string;
}) {
  const [prefixDraft, setPrefixDraft] = useState("");
  const [originAsnDraft, setOriginAsnDraft] = useState("");
  const [communityDraft, setCommunityDraft] = useState("");
  const [rpkiDraft, setRpkiDraft] = useState<BGPLGRpkiStatus | "">("");
  const [peerIdDraft, setPeerIdDraft] = useState(initialPeerId ?? "");
  const [bestPathOnlyDraft, setBestPathOnlyDraft] = useState(false);
  const [withdrawnDraft, setWithdrawnDraft] = useState(false);

  const [applied, setApplied] = useState<AppliedFilters>({
    ...EMPTY_FILTERS,
    peerId: initialPeerId ?? "",
  });
  const [offset, setOffset] = useState(0);
  const [sort, setSort] = useState<RouteSortState | null>(null);
  const [viewingPrefix, setViewingPrefix] = useState<string | null>(null);

  // The tab is remounted fresh on every navigation into it (see
  // LookingGlassPage's conditional render), so a plain useState
  // initializer normally suffices — but guard with an effect too in
  // case a future caller keeps the tab mounted across peer changes.
  useEffect(() => {
    if (!initialPeerId) return;
    setPeerIdDraft(initialPeerId);
    setApplied((prev) => ({ ...prev, peerId: initialPeerId }));
    setOffset(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialPeerId]);

  function runSearch() {
    setOffset(0);
    setApplied({
      prefix: prefixDraft.trim(),
      originAsn: originAsnDraft.trim(),
      community: communityDraft.trim(),
      rpki: rpkiDraft,
      peerId: peerIdDraft,
      bestPathOnly: bestPathOnlyDraft,
      withdrawn: withdrawnDraft,
    });
  }

  function onFilterKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") runSearch();
  }

  const peersQ = useQuery({
    queryKey: ["bgp-lg-peers"],
    queryFn: () => lookingGlassApi.listPeers(),
    staleTime: 30_000,
  });
  const peers = peersQ.data ?? [];

  // One shared cached query for the well-known community catalog — avoids
  // an N+1 per-row lookup (mirrors the CustomerChip precedent).
  const communitiesQ = useQuery({
    queryKey: ["bgp-communities-standard"],
    queryFn: () => asnsApi.listStandardCommunities(),
    staleTime: 5 * 60_000,
  });
  const communityNameByValue = useMemo(() => {
    const map = new Map<string, string>();
    for (const c of communitiesQ.data ?? []) map.set(c.value, c.name);
    return map;
  }, [communitiesQ.data]);

  const params: BGPLGRouteQuery = {
    prefix: applied.prefix || undefined,
    origin_asn: toOptionalInt(applied.originAsn),
    community: applied.community || undefined,
    rpki_status: applied.rpki || undefined,
    peer_id: applied.peerId || undefined,
    best_path_only: applied.bestPathOnly || undefined,
    withdrawn: applied.withdrawn || undefined,
    limit: SEARCH_PAGE_SIZE,
    offset,
  };

  const { data, isFetching, error } = useQuery({
    queryKey: [
      "bgp-lg-routes",
      applied.prefix,
      applied.originAsn,
      applied.community,
      applied.rpki,
      applied.peerId,
      applied.bestPathOnly,
      applied.withdrawn,
      offset,
    ],
    queryFn: () => lookingGlassApi.searchRoutes(params),
    placeholderData: (prev) => prev,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  const sortedItems = useMemo(() => {
    if (!sort) return items;
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...items].sort((a, b) => compareRoutes(a, b, sort.key) * dir);
  }, [items, sort]);

  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = Math.min(offset + SEARCH_PAGE_SIZE, total);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3 rounded-md border bg-card p-3">
        <Field label="Prefix">
          <input
            className={cn(inputCls, "w-40")}
            value={prefixDraft}
            onChange={(e) => setPrefixDraft(e.target.value)}
            onKeyDown={onFilterKeyDown}
            placeholder="10.0.0.0/8"
          />
        </Field>
        <Field label="Origin ASN">
          <input
            className={cn(inputCls, "w-28")}
            value={originAsnDraft}
            onChange={(e) => setOriginAsnDraft(e.target.value)}
            onKeyDown={onFilterKeyDown}
            placeholder="65001"
          />
        </Field>
        <Field label="Community">
          <input
            className={cn(inputCls, "w-32")}
            value={communityDraft}
            onChange={(e) => setCommunityDraft(e.target.value)}
            onKeyDown={onFilterKeyDown}
            placeholder="65535:666"
          />
        </Field>
        <Field label="RPKI">
          <select
            className={inputCls}
            value={rpkiDraft}
            onChange={(e) =>
              setRpkiDraft(e.target.value as BGPLGRpkiStatus | "")
            }
          >
            <option value="">Any</option>
            <option value="valid">Valid</option>
            <option value="invalid">Invalid</option>
            <option value="unknown">Unknown</option>
          </select>
        </Field>
        <Field label="Peer">
          <select
            className={inputCls}
            value={peerIdDraft}
            onChange={(e) => setPeerIdDraft(e.target.value)}
          >
            <option value="">Any</option>
            {peers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <label className="flex items-center gap-1.5 pb-1.5 text-sm">
          <input
            type="checkbox"
            checked={bestPathOnlyDraft}
            onChange={(e) => setBestPathOnlyDraft(e.target.checked)}
          />
          Best path only
        </label>
        <label className="flex items-center gap-1.5 pb-1.5 text-sm">
          <input
            type="checkbox"
            checked={withdrawnDraft}
            onChange={(e) => setWithdrawnDraft(e.target.checked)}
          />
          Show withdrawn
        </label>
        <button
          type="button"
          onClick={runSearch}
          className="mb-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
        >
          Search
        </button>
      </div>

      {error && (
        <FormError className="text-sm text-destructive">
          {errMsg(error, "Failed to load routes.")}
        </FormError>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>
          {isFetching ? (
            "Loading…"
          ) : (
            <>
              Showing {pageStart.toLocaleString()}–{pageEnd.toLocaleString()} of{" "}
              {total.toLocaleString()} route{total === 1 ? "" : "s"}
            </>
          )}
        </span>
      </div>

      <div className="overflow-x-auto rounded-md border">
        {items.length === 0 && !isFetching ? (
          <p className="px-3 py-6 text-center text-sm text-muted-foreground">
            No routes match. Once a peer session reaches Established, its
            learned routes appear here.
          </p>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b bg-muted/30 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-3 py-2">
                  <RouteSortLabel
                    label="Prefix"
                    sortKey="prefix"
                    state={sort}
                    onSort={(k) => setSort((p) => cycleRouteSort(p, k))}
                  />
                </th>
                <th className="px-3 py-2">
                  <RouteSortLabel
                    label="Origin ASN"
                    sortKey="origin_asn"
                    state={sort}
                    onSort={(k) => setSort((p) => cycleRouteSort(p, k))}
                  />
                </th>
                <th className="px-3 py-2">AS path</th>
                <th className="px-3 py-2">Next hop</th>
                <th className="px-3 py-2">
                  <RouteSortLabel
                    label="Local pref"
                    sortKey="local_pref"
                    state={sort}
                    onSort={(k) => setSort((p) => cycleRouteSort(p, k))}
                  />
                </th>
                <th className="px-3 py-2">
                  <RouteSortLabel
                    label="MED"
                    sortKey="med"
                    state={sort}
                    onSort={(k) => setSort((p) => cycleRouteSort(p, k))}
                  />
                </th>
                <th className="px-3 py-2">Communities</th>
                <th className="px-3 py-2">RPKI</th>
                <th className="px-3 py-2">Best</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {sortedItems.map((r) => {
                const allCommunities = [
                  ...r.communities,
                  ...r.large_communities,
                ];
                return (
                  <tr
                    key={r.id}
                    className={cn(
                      "cursor-pointer border-b last:border-0 hover:bg-muted/20",
                      r.withdrawn_at && "opacity-50",
                    )}
                    onClick={() => setViewingPrefix(r.prefix)}
                  >
                    <td className="px-3 py-2 align-top font-mono">
                      {r.prefix}
                    </td>
                    <td
                      className="px-3 py-2 align-top font-mono"
                      onClick={(e) => r.matched_asn_id && e.stopPropagation()}
                    >
                      {r.origin_asn == null ? (
                        "—"
                      ) : r.matched_asn_id ? (
                        <Link
                          to={`/network/asns/${r.matched_asn_id}`}
                          className="hover:text-primary hover:underline"
                        >
                          AS{r.origin_asn}
                        </Link>
                      ) : (
                        `AS${r.origin_asn}`
                      )}
                    </td>
                    <td className="px-3 py-2 align-top break-all font-mono text-muted-foreground">
                      {r.as_path.length ? r.as_path.join(" ") : "—"}
                    </td>
                    <td className="px-3 py-2 align-top break-all font-mono text-muted-foreground">
                      {r.next_hop}
                    </td>
                    <td className="px-3 py-2 align-top tabular-nums">
                      {r.local_pref ?? "—"}
                    </td>
                    <td className="px-3 py-2 align-top tabular-nums">
                      {r.med ?? "—"}
                    </td>
                    <td className="px-3 py-2 align-top break-all font-mono text-muted-foreground">
                      {allCommunities.length === 0 ? (
                        "—"
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {allCommunities.map((cVal, idx) => (
                            <span
                              key={`${cVal}-${idx}`}
                              title={communityNameByValue.get(cVal)}
                              className="rounded bg-muted px-1 py-0.5"
                            >
                              {cVal}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 align-top">
                      <Pill
                        text={r.rpki_status}
                        cls={RPKI_COLOR[r.rpki_status]}
                      />
                    </td>
                    <td className="px-3 py-2 align-top">
                      {r.is_best ? (
                        <Check className="h-3.5 w-3.5 text-emerald-500" />
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                      {r.withdrawn_at && (
                        <span className="ml-1 text-[10px] text-muted-foreground">
                          withdrawn
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {total > SEARCH_PAGE_SIZE && (
        <div className="flex items-center justify-between text-xs">
          <button
            type="button"
            disabled={offset === 0 || isFetching}
            onClick={() => setOffset((o) => Math.max(0, o - SEARCH_PAGE_SIZE))}
            className="rounded border px-2 py-1 hover:bg-muted disabled:opacity-40"
          >
            ← Prev
          </button>
          <span className="text-muted-foreground">
            Page {Math.floor(offset / SEARCH_PAGE_SIZE) + 1} of{" "}
            {Math.ceil(total / SEARCH_PAGE_SIZE)}
          </span>
          <button
            type="button"
            disabled={pageEnd >= total || isFetching}
            onClick={() => setOffset((o) => o + SEARCH_PAGE_SIZE)}
            className="rounded border px-2 py-1 hover:bg-muted disabled:opacity-40"
          >
            Next →
          </button>
        </div>
      )}

      {viewingPrefix && (
        <RouteDetailModal
          prefix={viewingPrefix}
          onClose={() => setViewingPrefix(null)}
        />
      )}
    </div>
  );
}
