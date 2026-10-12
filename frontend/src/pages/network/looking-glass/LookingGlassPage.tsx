import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Binoculars, Plus, RefreshCw } from "lucide-react";

import { lookingGlassApi, type BGPLGPeer } from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { cn } from "@/lib/utils";
import { ConfigApplyBanner } from "@/components/ConfigApplyChip";

import { PeerFormModal, SessionsTab } from "./SessionsTab";
import { RoutesTab } from "./RoutesTab";
import { QueryTab } from "./QueryTab";

type LGTab = "sessions" | "routes" | "query";

function TabPill({
  active,
  onClick,
  label,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "border-b-2 px-3 py-2 text-sm font-medium transition-colors -mb-px",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}

export function LookingGlassPage() {
  const qc = useQueryClient();
  const { enabled, ready } = useFeatureModules();
  const moduleOn = enabled("network.looking_glass");

  const [searchParams, setSearchParams] = useSearchParams();
  const tab: LGTab =
    searchParams.get("tab") === "routes"
      ? "routes"
      : searchParams.get("tab") === "query"
        ? "query"
        : "sessions";
  // Set only when the Routes tab was reached via the peer-detail modal's
  // "View all routes" link — pre-filters RoutesTab's Peer picker.
  const routesPeerFilter = searchParams.get("peer") ?? undefined;

  const [showPeerModal, setShowPeerModal] = useState(false);
  const [editingPeer, setEditingPeer] = useState<BGPLGPeer | null>(null);

  const collectorsQ = useQuery({
    queryKey: ["bgp-lg-collectors"],
    queryFn: () => lookingGlassApi.listCollectors(),
    enabled: ready && moduleOn,
    staleTime: 30_000,
  });
  const collectors = collectorsQ.data ?? [];

  function selectTab(next: LGTab) {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        if (next === "sessions") params.delete("tab");
        else params.set("tab", next);
        // A manual tab-pill click starts fresh — the peer filter only
        // makes sense as a one-shot deep link from the detail modal.
        params.delete("peer");
        return params;
      },
      { replace: true },
    );
  }

  // Deep-link from the peer detail modal's "View all routes" button.
  function viewPeerRoutes(peerId: string) {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        params.set("tab", "routes");
        params.set("peer", peerId);
        return params;
      },
      { replace: true },
    );
  }

  function openAddPeer() {
    setEditingPeer(null);
    setShowPeerModal(true);
  }

  function openEditPeer(peer: BGPLGPeer) {
    setEditingPeer(peer);
    setShowPeerModal(true);
  }

  function refresh() {
    void qc.invalidateQueries({
      predicate: (q) =>
        typeof q.queryKey[0] === "string" &&
        (q.queryKey[0] as string).startsWith("bgp-lg-"),
    });
  }

  if (ready && !moduleOn) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-sm text-muted-foreground">
        The BGP Looking Glass is disabled. An administrator can enable the
        "network.looking_glass" feature module on the Features & Integrations
        page.
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="flex items-center gap-2 text-lg font-semibold">
              <Binoculars className="h-5 w-5 text-muted-foreground" />
              BGP Looking Glass
            </h1>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              A receive-only BGP collector — peers passively with your edge /
              core routers and shows the live routing table it learns.
              SpatiumDDI never advertises routes to your network from these
              sessions.
            </p>
          </div>
          <div className="flex flex-shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              onClick={refresh}
              iconClassName={
                collectorsQ.isFetching ? "animate-spin" : undefined
              }
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={openAddPeer}
              disabled={ready && collectors.length === 0}
              title={
                ready && collectors.length === 0
                  ? "No collector has registered yet — install a Looking Glass agent first."
                  : undefined
              }
            >
              Add Peer
            </HeaderButton>
          </div>
        </div>

        <div className="mt-3 flex gap-1 border-b">
          <TabPill
            active={tab === "sessions"}
            onClick={() => selectTab("sessions")}
            label="Sessions"
          />
          <TabPill
            active={tab === "routes"}
            onClick={() => selectTab("routes")}
            label="Routes"
          />
          <TabPill
            active={tab === "query"}
            onClick={() => selectTab("query")}
            label="Query"
          />
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {/* #882 — a collector whose peer set failed to render keeps running on
            the previous one, so its sessions look healthy while the peers the
            operator added are simply absent. There is no collector list to
            hang a per-row chip on, so surface it above the tab content. */}
        {collectors
          .filter(
            (c) => c.config_apply_status && c.config_apply_status !== "ok",
          )
          .map((c) => (
            <div key={c.id} className="mb-4">
              <div className="mb-1 text-xs font-medium text-muted-foreground">
                Collector “{c.name}”
              </div>
              <ConfigApplyBanner server={c} />
            </div>
          ))}
        {tab === "sessions" ? (
          <SessionsTab
            collectors={collectors}
            onEdit={openEditPeer}
            onViewRoutes={viewPeerRoutes}
          />
        ) : tab === "routes" ? (
          <RoutesTab initialPeerId={routesPeerFilter} />
        ) : (
          <QueryTab collectors={collectors} />
        )}
      </div>

      {showPeerModal && (
        <PeerFormModal
          existing={editingPeer}
          collectors={collectors}
          onClose={() => {
            setShowPeerModal(false);
            setEditingPeer(null);
          }}
        />
      )}
    </div>
  );
}
