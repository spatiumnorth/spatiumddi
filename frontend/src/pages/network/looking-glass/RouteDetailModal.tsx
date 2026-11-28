import { countNoun } from "@/lib/count-noun";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { AlertTriangle, Check, Copy, Info, Star } from "lucide-react";

import {
  asnsApi,
  lookingGlassApi,
  type BGPLGRouteDetailPath,
  type BGPLGRpkiStatus,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { AskAIButton } from "@/components/copilot/AskAIButton";
import { RpkiPill } from "@/components/network/bgp-route-table";
import { errMsg, humanTime } from "../_shared";

/** Compact "first seen / last seen" caption shown under the AS-path cell —
 *  answers "is this path fresh, or has it been stable for weeks?" without
 *  spending a whole extra column on it. */
function SeenCaption({ path }: { path: BGPLGRouteDetailPath }) {
  return (
    <div
      className="text-[10px] text-muted-foreground"
      title={`First seen ${path.first_seen_at}`}
    >
      seen {humanTime(path.last_seen_at)}
      {path.flap_count > 0 &&
        ` · ${path.flap_count} flap${path.flap_count === 1 ? "" : "s"}`}
    </div>
  );
}

/** Worst-first aggregate across a set of per-path RPKI statuses — used for
 *  the header chip + the plain-English prefix-context note. "Worst" means
 *  "least trustworthy", so a single invalid path colours the whole prefix
 *  invalid even if the other paths are valid/unknown. */
function worstRpki(rpki: {
  valid: number;
  invalid: number;
  unknown: number;
}): BGPLGRpkiStatus {
  if (rpki.invalid > 0) return "invalid";
  if (rpki.unknown > 0) return "unknown";
  return "valid";
}

const RPKI_NOTE: Record<BGPLGRpkiStatus, string> = {
  valid:
    "All paths are covered by a valid RPKI ROA — the origin ASN is cryptographically authorised to announce this prefix.",
  invalid:
    "At least one path is RPKI INVALID — an origin ASN not authorised by a ROA is announcing this prefix. Treat with suspicion.",
  unknown:
    "No RPKI ROA covers this prefix (or the ROA cache hasn't been checked) — announcements can't be cryptographically verified either way.",
};

type WinnerResult = { winner: BGPLGRouteDetailPath | null; reason: string };

/** A simplified, client-side approximation of the BGP best-path algorithm,
 *  restricted to the attributes a receive-only collector actually gives
 *  us: local-pref (higher wins) -> AS-path length (shorter wins) -> MED
 *  (lower wins). Each path's own ``is_best`` flag is the collector's
 *  per-peer Adj-RIB-In decision (trivially true for a single-homed
 *  session), NOT a cross-router comparison — this helper is what answers
 *  "which router's view would actually win" when that's determinable. */
function pickOverallWinner(paths: BGPLGRouteDetailPath[]): WinnerResult {
  if (paths.length === 0) return { winner: null, reason: "No paths." };
  if (paths.length === 1) {
    return {
      winner: paths[0],
      reason: "Only one path is known for this prefix.",
    };
  }

  let candidates = paths;
  const localPrefs = candidates
    .map((p) => p.local_pref)
    .filter((v): v is number => v != null);
  if (localPrefs.length > 0) {
    const maxLocalPref = Math.max(...localPrefs);
    const withMax = candidates.filter(
      (p) => (p.local_pref ?? -Infinity) === maxLocalPref,
    );
    if (withMax.length === 1) {
      return {
        winner: withMax[0],
        reason: `Highest local-pref (${maxLocalPref}).`,
      };
    }
    if (withMax.length < candidates.length) candidates = withMax;
  }

  const minAsPathLen = Math.min(...candidates.map((p) => p.as_path.length));
  const afterAsPath = candidates.filter(
    (p) => p.as_path.length === minAsPathLen,
  );
  if (afterAsPath.length === 1) {
    const qualifier = localPrefs.length > 0 ? ", after local-pref" : "";
    return {
      winner: afterAsPath[0],
      reason: `Shortest AS-path (${minAsPathLen} hop${minAsPathLen === 1 ? "" : "s"})${qualifier}.`,
    };
  }
  candidates = afterAsPath;

  const withMed = candidates.filter((p) => p.med != null);
  if (withMed.length > 0) {
    const minMed = Math.min(...withMed.map((p) => p.med as number));
    const afterMed = withMed.filter((p) => p.med === minMed);
    if (afterMed.length === 1) {
      return {
        winner: afterMed[0],
        reason: `Lowest MED (${minMed}), after local-pref and AS-path length.`,
      };
    }
  }

  return {
    winner: null,
    reason:
      "These paths tie on local-pref, AS-path length, and MED — no single winner is distinguishable from what the collector receives. Each row's checkmark is that router's own Adj-RIB-In best.",
  };
}

function SectionCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border p-3">
      <div className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </div>
      <div className="space-y-1.5 text-xs">{children}</div>
    </div>
  );
}

function StatRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="min-w-0 truncate text-right font-medium">{value}</span>
    </div>
  );
}

/** True when the column has more than one distinct non-null value across
 *  every path AND this path's own value differs from the reference
 *  (the overall winner when one was found, otherwise the first path) —
 *  drives the "router A sends X, router B sends Y" highlight. */
function isDivergent<T>(
  path: BGPLGRouteDetailPath,
  paths: BGPLGRouteDetailPath[],
  reference: BGPLGRouteDetailPath,
  getter: (p: BGPLGRouteDetailPath) => T,
): boolean {
  const values = new Set(paths.map(getter).filter((v) => v != null));
  if (values.size <= 1) return false;
  return getter(path) !== getter(reference);
}

const DIVERGENT_CLS = "font-semibold text-amber-700 dark:text-amber-400";

export function RouteDetailModal({
  prefix,
  onClose,
}: {
  prefix: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const detailQ = useQuery({
    queryKey: ["bgp-lg-route-detail", prefix],
    queryFn: () => lookingGlassApi.getRouteDetail(prefix),
  });

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

  async function copyPrefix() {
    try {
      await navigator.clipboard.writeText(prefix);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable — operator can still select+copy */
    }
  }

  if (detailQ.isLoading) {
    return (
      <Modal title="Route detail" onClose={onClose} wide>
        <p className="py-8 text-center text-sm text-muted-foreground">
          Loading…
        </p>
      </Modal>
    );
  }
  if (detailQ.isError || !detailQ.data) {
    return (
      <Modal title="Route detail" onClose={onClose} wide>
        <p className="text-sm text-destructive">
          {errMsg(detailQ.error, "Failed to load route detail.")}
        </p>
      </Modal>
    );
  }

  const d = detailQ.data;
  const paths = d.paths;
  const summary = d.summary;
  const ipam = d.ipam;
  const rpki = worstRpki(summary.rpki);

  const { winner, reason: winnerReason } = pickOverallWinner(paths);
  const referencePath = winner ?? paths.find((p) => p.is_best) ?? paths[0];

  const originLabels = summary.distinct_origin_asns.map((asn) => {
    const name = summary.origin_names[String(asn)];
    return name ? `AS${asn} (${name})` : `AS${asn}`;
  });

  return (
    <Modal title="Route detail" onClose={onClose} wide>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex flex-wrap items-start justify-between gap-3 border-b pb-3">
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="break-all font-mono text-xl font-semibold">
                {d.prefix}
              </span>
              <RpkiPill status={rpki} />
            </div>
            <div className="text-xs text-muted-foreground">
              {summary.path_count} path{summary.path_count === 1 ? "" : "s"}{" "}
              from {summary.peer_count} router
              {summary.peer_count === 1 ? "" : "s"}
            </div>
          </div>
        </div>

        {/* Headline banner */}
        {summary.multi_origin ? (
          <div
            className={cn(
              "flex items-start gap-2 rounded-md border p-3 text-sm",
              summary.rpki.invalid > 0
                ? "border-rose-500/40 bg-rose-500/5 text-rose-800 dark:text-rose-300"
                : "border-amber-500/40 bg-amber-500/5 text-amber-800 dark:text-amber-300",
            )}
          >
            <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
            <div className="space-y-1">
              <div className="font-semibold">
                Announced with {summary.distinct_origin_asns.length} different
                origin ASNs ({originLabels.join(", ")}) — anycast, or a possible
                origin hijack / route leak.
              </div>
              <div className="text-xs opacity-90">
                Review the origins in the table below. If this prefix isn&apos;t
                intentionally announced from multiple ASes, this may indicate a
                hijack or route leak in progress.
              </div>
            </div>
          </div>
        ) : summary.anycast_candidate ? (
          <div className="flex items-start gap-2 rounded-md border border-sky-500/40 bg-sky-500/5 p-3 text-sm text-sky-800 dark:text-sky-300">
            <Info className="mt-0.5 h-4 w-4 flex-shrink-0" />
            <div>
              <span className="font-semibold">Anycast / multi-homed:</span> this
              prefix is learned from {countNoun(summary.peer_count, "router")},
              all originated by {originLabels.join(", ")}.
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Single path — learned from one router only, one origin ASN.
          </p>
        )}

        {/* All-paths comparison table */}
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b bg-muted/30 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-3 py-2">Router / peer</th>
                <th className="px-3 py-2">Origin ASN</th>
                <th className="px-3 py-2">Next-hop</th>
                <th className="px-3 py-2">Local-pref</th>
                <th className="px-3 py-2">MED</th>
                <th className="px-3 py-2">AS-path</th>
                <th className="px-3 py-2">Communities</th>
                <th className="px-3 py-2">RPKI</th>
                <th className="px-3 py-2">Best</th>
              </tr>
            </thead>
            <tbody>
              {paths.map((p) => {
                const allCommunities = [
                  ...p.communities,
                  ...p.large_communities,
                ];
                const isWinner = winner?.route_id === p.route_id;
                return (
                  <tr
                    key={p.route_id}
                    className={cn(
                      "border-b last:border-0",
                      isWinner
                        ? "bg-emerald-500/5"
                        : p.withdrawn_at
                          ? "opacity-50"
                          : undefined,
                    )}
                  >
                    <td className="px-3 py-2 align-top">
                      <div className="font-medium">{p.peer_name}</div>
                      <div className="text-[10px] text-muted-foreground">
                        via {p.collector_name}
                      </div>
                      <SeenCaption path={p} />
                    </td>
                    <td
                      className={cn(
                        "px-3 py-2 align-top font-mono",
                        isDivergent(
                          p,
                          paths,
                          referencePath,
                          (x) => x.origin_asn,
                        ) && DIVERGENT_CLS,
                      )}
                    >
                      {p.origin_asn == null ? (
                        "—"
                      ) : p.matched_asn_id ? (
                        <Link
                          to={`/network/asns/${p.matched_asn_id}`}
                          className="hover:text-primary hover:underline"
                        >
                          AS{p.origin_asn}
                        </Link>
                      ) : (
                        `AS${p.origin_asn}`
                      )}
                    </td>
                    <td
                      className={cn(
                        "px-3 py-2 align-top break-all font-mono",
                        isDivergent(
                          p,
                          paths,
                          referencePath,
                          (x) => x.next_hop,
                        ) && DIVERGENT_CLS,
                      )}
                    >
                      {p.next_hop}
                    </td>
                    <td
                      className={cn(
                        "px-3 py-2 align-top tabular-nums",
                        isDivergent(
                          p,
                          paths,
                          referencePath,
                          (x) => x.local_pref,
                        ) && DIVERGENT_CLS,
                      )}
                    >
                      {p.local_pref ?? "—"}
                    </td>
                    <td
                      className={cn(
                        "px-3 py-2 align-top tabular-nums",
                        isDivergent(p, paths, referencePath, (x) => x.med) &&
                          DIVERGENT_CLS,
                      )}
                    >
                      {p.med ?? "—"}
                    </td>
                    <td className="px-3 py-2 align-top">
                      <div className="break-all font-mono text-muted-foreground">
                        {p.as_path.length ? p.as_path.join(" ") : "—"}
                      </div>
                      <div className="text-[10px] text-muted-foreground">
                        {p.as_path.length} hop
                        {p.as_path.length === 1 ? "" : "s"}
                      </div>
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
                      <RpkiPill status={p.rpki_status} />
                    </td>
                    <td className="px-3 py-2 align-top">
                      <div className="flex items-center gap-1">
                        {p.is_best ? (
                          <Check className="h-3.5 w-3.5 text-emerald-500" />
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                        {isWinner && (
                          <Star
                            className="h-3.5 w-3.5 text-amber-500"
                            fill="currentColor"
                            aria-label="Overall winner"
                          />
                        )}
                      </div>
                      {p.withdrawn_at && (
                        <span className="text-[10px] text-muted-foreground">
                          withdrawn
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Best-path explanation */}
        <div className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
          <p>
            BGP best-path selection prefers, in order: highest local-pref →
            shortest AS-path → lowest origin type → lowest MED → eBGP over iBGP
            → lowest IGP metric → oldest route → lowest router ID. Since this is
            a receive-only collector, each row&apos;s ✓ reflects what{" "}
            <em>that router itself</em> considers best in its own Adj-RIB-In —
            not a cross-router comparison.
          </p>
          <p className="mt-1.5 flex items-center gap-1.5">
            {winner ? (
              <Star
                className="h-3 w-3 flex-shrink-0 text-amber-500"
                fill="currentColor"
              />
            ) : null}
            <span>
              {winner ? (
                <>
                  <span className="font-medium text-foreground">
                    {winner.peer_name}
                  </span>{" "}
                  is the closest thing to an overall winner across routers:{" "}
                  {winnerReason}
                </>
              ) : (
                winnerReason
              )}
            </span>
          </p>
        </div>

        {/* Prefix context */}
        <SectionCard title="Prefix context">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <StatRow
                label="Subnet"
                value={
                  ipam.subnet_id ? (
                    <Link
                      to={`/ipam?subnet=${ipam.subnet_id}`}
                      className="text-primary hover:underline"
                    >
                      {ipam.subnet_name}
                    </Link>
                  ) : (
                    "—"
                  )
                }
              />
              <StatRow label="Block" value={ipam.block_name ?? "—"} />
              <StatRow label="Space" value={ipam.space_name ?? "—"} />
            </div>
            <div className="space-y-1.5">
              <StatRow
                label="ASN"
                value={
                  ipam.asn_id ? (
                    <Link
                      to={`/network/asns/${ipam.asn_id}`}
                      className="text-primary hover:underline"
                    >
                      AS{ipam.asn_number} · {ipam.asn_name}
                    </Link>
                  ) : (
                    "—"
                  )
                }
              />
              <StatRow label="VRF" value={ipam.vrf_name ?? "—"} />
            </div>
          </div>
          <p className="border-t pt-1.5 text-muted-foreground">
            {RPKI_NOTE[rpki]}
          </p>
        </SectionCard>

        {/* Footer */}
        <div className="flex flex-wrap justify-between gap-2 border-t pt-3">
          <div className="flex flex-wrap gap-2">
            <AskAIButton
              context={[
                `BGP prefix ${d.prefix}`,
                `${countNoun(summary.path_count, "path")} from ${countNoun(summary.peer_count, "router")}`,
                `origin ASN${summary.distinct_origin_asns.length === 1 ? "" : "s"}: ${originLabels.join(", ")}`,
                summary.multi_origin
                  ? "multiple distinct origin ASNs (possible hijack/leak)"
                  : null,
                ipam.subnet_name
                  ? `covering subnet: ${ipam.subnet_name}`
                  : null,
              ]
                .filter(Boolean)
                .join(". ")}
              prompt={`Is the BGP prefix ${d.prefix} being announced normally, or does this look like a route leak / hijack?`}
              tooltip="Ask AI about this prefix"
            />
            {ipam.subnet_id && (
              <HeaderButton
                onClick={() => {
                  window.location.href = `/ipam?subnet=${ipam.subnet_id}`;
                }}
              >
                View in IPAM
              </HeaderButton>
            )}
          </div>
          <div className="flex gap-2">
            <HeaderButton icon={Copy} onClick={copyPrefix}>
              {copied ? "Copied!" : "Copy prefix"}
            </HeaderButton>
            <HeaderButton variant="primary" onClick={onClose}>
              Close
            </HeaderButton>
          </div>
        </div>
      </div>
    </Modal>
  );
}
