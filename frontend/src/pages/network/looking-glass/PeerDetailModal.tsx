import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ArrowRight, RefreshCw, Route as RouteIcon } from "lucide-react";

import {
  asnsApi,
  lookingGlassApi,
  type BGPLGAddressFamily,
  type BGPLGPeer,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { BgpRouteMiniTable } from "@/components/network/bgp-route-table";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { errMsg, humanDuration, humanTime } from "../_shared";
import { FALLBACK_STATE_COLOR, STATE_COLOR } from "./SessionsTab";

const AF_LABELS: Partial<Record<BGPLGAddressFamily, string>> = {
  "ipv4-unicast": "IPv4 unicast",
  "ipv6-unicast": "IPv6 unicast",
  vpnv4: "VPNv4",
  vpnv6: "VPNv6",
};

const COLLECTOR_STATUS_DOT: Record<string, string> = {
  active: "bg-emerald-500",
  unreachable: "bg-rose-500",
  error: "bg-rose-500",
  unknown: "bg-zinc-400",
};

function StatePill({ state }: { state: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide",
        STATE_COLOR[state as keyof typeof STATE_COLOR] ?? FALLBACK_STATE_COLOR,
      )}
    >
      {state}
    </span>
  );
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

/** Coloured stacked meter over the peer's active-route RPKI mix, with a
 *  direct-labelled legend underneath so status is never colour-alone. */
function RpkiMeter({
  valid,
  invalid,
  unknown,
}: {
  valid: number;
  invalid: number;
  unknown: number;
}) {
  const total = valid + invalid + unknown;
  const pct = (n: number) => (total === 0 ? 0 : (n / total) * 100);
  return (
    <div className="space-y-1.5">
      <div className="flex h-2 w-full gap-0.5 overflow-hidden rounded-full bg-muted">
        {valid > 0 && (
          <div
            className="h-full rounded-full bg-emerald-500"
            style={{ width: `${pct(valid)}%` }}
          />
        )}
        {invalid > 0 && (
          <div
            className="h-full rounded-full bg-rose-500"
            style={{ width: `${pct(invalid)}%` }}
          />
        )}
        {unknown > 0 && (
          <div
            className="h-full rounded-full bg-zinc-400 dark:bg-zinc-500"
            style={{ width: `${pct(unknown)}%` }}
          />
        )}
      </div>
      <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-emerald-500" /> Valid {valid}
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-rose-500" /> Invalid{" "}
          {invalid}
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-zinc-400 dark:bg-zinc-500" />{" "}
          Unknown {unknown}
        </span>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === "critical"
      ? "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400"
      : severity === "warning"
        ? "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400"
        : "bg-blue-100 text-blue-700 dark:bg-blue-950/30 dark:text-blue-400";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider",
        cls,
      )}
    >
      {severity}
    </span>
  );
}

export function PeerDetailModal({
  peerId,
  onClose,
  onEdit,
  onDelete,
  onViewRoutes,
}: {
  peerId: string;
  onClose: () => void;
  /** Closes this modal and hands the full peer object to the caller's
   *  existing edit-form flow. */
  onEdit: (peer: BGPLGPeer) => void;
  /** Closes this modal and hands the full peer object to the caller's
   *  existing delete-confirm flow. */
  onDelete: (peer: BGPLGPeer) => void;
  /** Deep-links into the Routes tab, pre-filtered to this peer. */
  onViewRoutes: (peerId: string) => void;
}) {
  const qc = useQueryClient();
  // #3104 — peers sit under the router's 'bgp_lg_peer' gate; a read-only
  // user is offered no write on them.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "bgp_lg_peer"),
    "Requires write permission on BGP peers",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "bgp_lg_peer"),
    "Requires delete permission on BGP peers",
  );

  // Live-ticking clock — re-render every second while the session is
  // established so "Up for Xm Ys" counts up smoothly instead of jumping
  // only when the 15s session/detail polls land.
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(id);
  }, []);

  const detailQ = useQuery({
    queryKey: ["bgp-lg-peer-detail", peerId],
    queryFn: () => lookingGlassApi.getPeerDetail(peerId),
    refetchInterval: 15_000,
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

  function refresh() {
    void detailQ.refetch();
    void qc.invalidateQueries({ queryKey: ["bgp-lg-sessions"] });
  }

  if (detailQ.isLoading) {
    return (
      <Modal title="Peer detail" onClose={onClose} wide>
        <p className="py-8 text-center text-sm text-muted-foreground">
          Loading…
        </p>
      </Modal>
    );
  }
  if (detailQ.isError || !detailQ.data) {
    return (
      <Modal title="Peer detail" onClose={onClose} wide>
        <p className="text-sm text-destructive">
          {errMsg(detailQ.error, "Failed to load peer detail.")}
        </p>
      </Modal>
    );
  }

  const d = detailQ.data;
  const peer = d.peer;
  const rs = d.route_stats;

  const uptimeSeconds =
    peer.session_state === "established" && peer.uptime_started_at
      ? Math.max(
          0,
          Math.floor(
            (Date.now() - new Date(peer.uptime_started_at).getTime()) / 1000,
          ),
        )
      : null;

  return (
    <Modal title={peer.name} onClose={onClose} wide>
      <div className="space-y-4">
        {/* Header strip */}
        <div className="flex flex-wrap items-start justify-between gap-3 border-b pb-3">
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <StatePill state={peer.session_state} />
              <span
                className={cn(
                  "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
                  peer.enabled
                    ? "bg-muted text-muted-foreground"
                    : "bg-zinc-200 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-300",
                )}
              >
                {peer.enabled ? "Enabled" : "Disabled"}
              </span>
              <span className="break-all font-mono text-xs text-muted-foreground">
                {peer.peer_address}
              </span>
            </div>
            <div className="text-xs text-muted-foreground">
              {uptimeSeconds != null
                ? `Up for ${humanDuration(uptimeSeconds)}`
                : peer.down_since
                  ? `Down since ${humanTime(peer.down_since)}`
                  : "Not established"}
            </div>
          </div>
          <HeaderButton
            icon={RefreshCw}
            onClick={refresh}
            iconClassName={detailQ.isFetching ? "animate-spin" : undefined}
          >
            Refresh
          </HeaderButton>
        </div>

        {/* Card grid */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <SectionCard title="Session">
            <StatRow
              label="Uptime"
              value={uptimeSeconds != null ? humanDuration(uptimeSeconds) : "—"}
            />
            <StatRow label="Last flap" value={humanTime(peer.last_flap_at)} />
            <StatRow label="Down since" value={humanTime(peer.down_since)} />
            <StatRow
              label="Prefixes recv / accepted"
              value={`${peer.prefixes_received.toLocaleString()} / ${peer.prefixes_accepted.toLocaleString()}`}
            />
            <StatRow
              label="RPKI invalid"
              value={
                peer.rpki_invalid_count > 0 ? (
                  <span className="font-semibold text-rose-600 dark:text-rose-400">
                    {peer.rpki_invalid_count}
                  </span>
                ) : (
                  "0"
                )
              }
            />
          </SectionCard>

          <SectionCard title="BGP configuration">
            <div className="flex items-center justify-center gap-2 rounded-md bg-muted/40 px-2 py-1.5 font-mono text-sm">
              <span>AS{peer.local_asn}</span>
              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
              <span>AS{peer.peer_asn}</span>
            </div>
            <div className="flex flex-wrap gap-1 pt-1">
              {peer.address_families.map((af) => (
                <span
                  key={af}
                  className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium"
                >
                  {AF_LABELS[af] ?? af}
                </span>
              ))}
            </div>
            <StatRow
              label="Max prefixes"
              value={peer.max_prefixes.toLocaleString()}
            />
            <StatRow
              label="Import filter"
              value={
                peer.import_filter.mode === "accept_all"
                  ? "Accept all"
                  : `Scoped (${(peer.import_filter.prefixes ?? []).length} prefixes)`
              }
            />
            <StatRow
              label="MD5 auth"
              value={peer.md5_password_set ? "Set" : "None"}
            />
            {peer.description && (
              <div className="border-t pt-1.5 text-muted-foreground">
                {peer.description}
              </div>
            )}
          </SectionCard>

          <SectionCard title="Collector">
            <StatRow label="Name" value={d.collector.name} />
            <StatRow label="Host" value={d.collector.host ?? "—"} />
            <StatRow
              label="Status"
              value={
                <span className="inline-flex items-center gap-1.5">
                  <span
                    className={cn(
                      "h-1.5 w-1.5 rounded-full",
                      COLLECTOR_STATUS_DOT[d.collector.status] ?? "bg-zinc-400",
                    )}
                  />
                  {d.collector.status}
                </span>
              }
            />
            <StatRow
              label="Last-seen IP"
              value={d.collector.last_seen_ip ?? "—"}
            />
            <StatRow
              label="Agent version"
              value={d.collector.agent_version ?? "—"}
            />
          </SectionCard>

          <SectionCard title="Linked">
            <StatRow
              label="Remote ASN"
              value={
                d.matched_asn ? (
                  <Link
                    to={`/network/asns/${d.matched_asn.id}`}
                    className="text-primary hover:underline"
                  >
                    AS{peer.peer_asn} · {d.matched_asn.name}
                  </Link>
                ) : (
                  `AS${peer.peer_asn} (unlinked)`
                )
              }
            />
            <StatRow
              label="Peer device"
              value={
                d.peer_router ? (
                  <Link
                    to={`/network/devices/${d.peer_router.id}`}
                    className="text-primary hover:underline"
                  >
                    {d.peer_router.name}
                  </Link>
                ) : (
                  "—"
                )
              }
            />
            <StatRow
              label="VPN routes"
              value={rs.has_vpn_routes ? "Yes (RD present)" : "No"}
            />
          </SectionCard>
        </div>

        {/* Learned routes */}
        <div className="rounded-md border p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              <RouteIcon className="h-3 w-3" /> Learned routes
            </div>
            <button
              type="button"
              onClick={() => onViewRoutes(peerId)}
              className="text-xs text-primary hover:underline"
            >
              View all {rs.active_total.toLocaleString()} routes →
            </button>
          </div>

          <div className="mb-3 flex flex-wrap gap-6">
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Active
              </div>
              <div className="text-sm font-semibold">
                {rs.active_total.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Withdrawn
              </div>
              <div className="text-sm font-semibold">
                {rs.withdrawn_total.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Best path
              </div>
              <div className="text-sm font-semibold">
                {rs.best_count.toLocaleString()}
              </div>
            </div>
          </div>

          <div className="mb-3">
            <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">
              RPKI mix
            </div>
            <RpkiMeter
              valid={rs.rpki.valid}
              invalid={rs.rpki.invalid}
              unknown={rs.rpki.unknown}
            />
          </div>

          {rs.top_origin_asns.length > 0 && (
            <div className="mb-3">
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                Top origin ASNs
              </div>
              <div className="flex flex-wrap gap-1.5">
                {rs.top_origin_asns.map((o) => (
                  <span
                    key={o.asn}
                    className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                  >
                    AS{o.asn} · {o.count}
                  </span>
                ))}
              </div>
            </div>
          )}

          {rs.top_communities.length > 0 && (
            <div className="mb-3">
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                Top communities
              </div>
              <div className="flex flex-wrap gap-1.5">
                {rs.top_communities.map((c) => (
                  <span
                    key={c.value}
                    title={communityNameByValue.get(c.value)}
                    className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                  >
                    {c.value} · {c.count}
                  </span>
                ))}
              </div>
            </div>
          )}

          {rs.sample_routes.length > 0 ? (
            <div>
              <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">
                Sample routes
              </div>
              <BgpRouteMiniTable items={rs.sample_routes} />
            </div>
          ) : (
            <p className="text-xs italic text-muted-foreground">
              No active routes learned from this peer yet.
            </p>
          )}
        </div>

        {/* Active alerts */}
        {d.active_alerts.length > 0 && (
          <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-amber-800 dark:text-amber-300">
              Active alerts
            </div>
            <ul className="space-y-1.5">
              {d.active_alerts.map((a, i) => (
                <li
                  key={`${a.rule_type}-${i}`}
                  className="flex flex-wrap items-start gap-2 text-xs"
                >
                  <SeverityBadge severity={a.severity} />
                  <span className="min-w-0 flex-1">{a.message}</span>
                  <span className="whitespace-nowrap text-muted-foreground">
                    {humanTime(a.fired_at)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Footer */}
        <div className="flex justify-end gap-2 border-t pt-3">
          <HeaderButton onClick={onClose}>Close</HeaderButton>
          <HeaderButton
            variant="destructive"
            onClick={() => onDelete(peer)}
            {...deleteGate}
          >
            Delete
          </HeaderButton>
          <HeaderButton
            variant="primary"
            onClick={() => onEdit(peer)}
            {...writeGate}
          >
            Edit
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}
