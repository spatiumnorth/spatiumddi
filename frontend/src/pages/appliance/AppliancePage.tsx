import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Boxes,
  Network,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Stamp,
  Wrench,
} from "lucide-react";

import { applianceApi } from "@/lib/api";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { useSessionState } from "@/lib/useSessionState";
import { FleetTab } from "./FleetTab";
import { ClusterTab } from "./ClusterTab";
import { FirewallTab } from "./FirewallTab";
import { LogsTab } from "./LogsTab";
import { MaintenanceTab } from "./MaintenanceTab";
import { NetworkTab } from "./NetworkTab";

// #404 — Rolling Upgrade, Releases, and Web UI Certificate moved OUT of the
// top-level tab bar and INTO the Fleet tab's left sidebar (Rolling Upgrade now
// also hosts the Releases catalog). The legacy ?tab= deep-links + the Fleet
// drilldown's onNavigateTab calls for those keys are remapped to the Fleet tab
// + the matching sidebar section via LEGACY_TAB_TO_FLEET_SECTION below.
const LEGACY_TAB_TO_FLEET_SECTION: Record<string, string> = {
  tls: "web-ui-certificate",
  releases: "cluster-upgrade",
  "cluster-upgrade": "cluster-upgrade",
};

/**
 * SpatiumDDI OS appliance management hub (issue #134, Phase 4).
 *
 * Phase 4a (this commit) lands just the frame:
 *   - sidebar visibility gate via versionInfo.appliance_mode
 *   - permission-gated /api/v1/appliance/info call
 *   - tab shell with six placeholders for the sub-surfaces 4b-4g
 *     will fill in
 *
 * Each tab is a hard-coded "Coming in Phase 4x" panel right now so
 * the route is reachable, navigable, and obviously incomplete. The
 * goal of 4a is to ship the scaffolding everything else lands behind
 * — TLS first (4b, prevents secrets-over-plain-HTTP regressions),
 * then releases / containers / logs / network / wizard in any order.
 */
type Tab =
  | "fleet"
  | "firewall"
  | "cluster"
  | "logs"
  | "network"
  | "maintenance";

interface TabSpec {
  key: Tab;
  label: string;
  phase: string;
  icon: typeof ShieldCheck;
  summary: string;
  // #14 — feature-module-gated tab. Hidden (and the underlying router 404s)
  // when the module is disabled. The /appliance NavItem itself stays
  // always-visible (docker/k8s control planes need Fleet); module gating
  // happens at the TAB level here.
  module?: string;
  // Self-only tabs operate on local host state (TLS cert files, the
  // local docker socket, journalctl, hostname / network config,
  // reboot / shutdown). They only make sense when the control plane
  // itself is running on the SpatiumDDI OS appliance ISO. On a
  // docker / k8s control plane we hide these — the operator manages
  // host-level concerns through their own tooling. Releases + OS
  // Versions are universally useful (release catalog, fleet
  // management of remote appliance agents) so they stay visible.
  selfOnly?: boolean;
}

// ── Tab order: Fleet pinned first, the rest alphabetical by label ────
// The render-time sort in ``visibleTabs`` (below) does the ordering, so
// the source order here doesn't matter — Fleet is pinned to the front
// and every other tab sorts by its ``label`` (case-insensitive). This
// is robust to label renames (e.g. "Containers" → "Pods" no longer
// strands the tab in the wrong slot) + new tabs slotting in
// automatically. selfOnly tabs are hidden on docker / k8s control
// planes at filter time, also below.
const TABS: TabSpec[] = [
  {
    // Issue #170 Wave D1 — Fleet tab (renamed from Approvals).
    // Pending pairings pin at the top with Approve / Reject; approved
    // rows expose role assignment, OS upgrade, reboot, re-key, and
    // delete via the per-row drilldown. Not selfOnly: docker / k8s
    // control planes still manage remote Application appliances here.
    key: "fleet",
    label: "Fleet",
    phase: "170-D1",
    icon: Stamp,
    summary:
      "Manage the Application appliance fleet — approve / reject pending pairings, assign roles + groups, schedule OS slot upgrades + reboots, re-key + delete. Pending rows pin at the top; approved rows open a per-appliance drilldown with capability detail + role assignment + firewall preview + OS upgrade controls.",
  },
  {
    // #402 — Cluster tab. Combines the Pods view + the etcd snapshot /
    // restore surface (lifted out of Fleet, where it crowded the roster)
    // into one operator-friendly tab behind a left sub-nav. Named
    // "Cluster" rather than "Kubernetes" so operators don't need k8s
    // vocabulary to find pod / etcd controls. selfOnly: both halves need
    // the in-cluster kubeapi / embedded-etcd seed that only an appliance
    // host has.
    key: "cluster",
    label: "Cluster",
    phase: "402",
    icon: Boxes,
    selfOnly: true,
    summary:
      "The k3s cluster underneath the appliance — Pods (running workloads, with restart + live log streaming over SSE) and etcd snapshots (the cluster's disaster-recovery state + guided single-node restore). Both are driven off the in-cluster kubeapi via the api pod's ServiceAccount.",
  },
  {
    key: "logs",
    label: "Logs & Diagnostics",
    phase: "4e",
    icon: ScrollText,
    selfOnly: true,
    summary:
      'Host-log viewer (when bind-mounted), the "Run self-test" health-check button (DNS resolution + kubeapi reachability + pod health + role presence), and the "Download diagnostic bundle" one-click zip with secrets redacted.',
  },
  {
    key: "maintenance",
    label: "Maintenance",
    phase: "4f",
    icon: Activity,
    selfOnly: true,
    summary:
      "Maintenance-mode toggle that drains DNS/DHCP traffic before letting the operator perform host work, plus reboot / shutdown buttons with confirmation prompts so accidental clicks don't take an appliance offline.",
  },
  {
    key: "network",
    label: "Network & Host",
    phase: "4f",
    icon: Network,
    selfOnly: true,
    summary:
      "Hostname, DNS resolvers, IPv4/IPv6 mode (DHCP vs static, with the wizard's same form), nftables drop-in editor for /etc/nftables.d/, SSH key upload, proxy config, and a reboot-pending banner.",
  },
  {
    // #285 Phase 3 — fleet firewall. Gated on the appliance.firewall feature
    // module (the /appliance/firewall router 404s when off); not selfOnly —
    // a docker/k8s control plane manages the firewall policy for its
    // registered appliance agents from here too.
    key: "firewall",
    label: "Firewall",
    phase: "285",
    icon: ShieldAlert,
    module: "appliance.firewall",
    summary:
      "Declarative per-role / per-appliance nftables policy compiled into each node's drop-in. Edit fleet / role / appliance policies + rules + aliases, and preview any node's effective merged ruleset (dark until the firewall_enabled master switch is on). The seeded builtin role policies reproduce the hardcoded Phase-2 renderer byte-for-byte.",
  },
];

export function AppliancePage() {
  const { data: info } = useQuery({
    queryKey: ["appliance", "info"],
    queryFn: applianceApi.getInfo,
    staleTime: 5 * 60 * 1000,
  });

  // On docker / k8s control planes, hide every tab that only makes
  // sense for a local-appliance host. The page still ships Releases +
  // OS Versions so operators with appliance *agents* (registered
  // against this docker/k8s control plane) can manage them.
  const isApplianceHost = !!info?.appliance_mode;
  const { enabled: moduleEnabled } = useFeatureModules();
  // Fleet pinned first; every other visible tab sorted alphabetically
  // by label (case-insensitive). See the comment on TABS above. Module-gated
  // tabs (e.g. Firewall) drop out when their feature module is disabled — the
  // #14 tab-level gate (the /appliance parent stays always-visible).
  const visibleTabs = TABS.filter(
    (t) =>
      (!t.selfOnly || isApplianceHost) &&
      (!t.module || moduleEnabled(t.module)),
  ).sort((a, b) => {
    if (a.key === "fleet") return -1;
    if (b.key === "fleet") return 1;
    return a.label.localeCompare(b.label, undefined, { sensitivity: "base" });
  });

  // Default tab — Fleet (pinned first, always visible on every deployment
  // shape). Keeps the session-stored value if it's still in the visible set;
  // falls back here if the operator last visited a now-removed tab (#404 moved
  // Rolling Upgrade / Releases / Web UI Certificate into the Fleet sidebar).
  const defaultTab: Tab = "fleet";
  const [tab, setTab] = useSessionState<Tab>("appliance.tab", defaultTab);

  // #404 — a deep-link / onNavigateTab target that now lives in the Fleet
  // sidebar jumps to Fleet and hands the section down for FleetTab to select.
  const [fleetSection, setFleetSection] = useState<string | null>(null);
  // Deep-linked sub-section for the Cluster tab (e.g. Platform Insights →
  // Containers links to ?tab=cluster&section=pods, #404 follow-up).
  const [clusterSection, setClusterSection] = useState<string | null>(null);
  const navigate = (t: string) => {
    const target = LEGACY_TAB_TO_FLEET_SECTION[t];
    if (target) {
      setTab("fleet");
      setFleetSection(target);
    } else {
      setTab(t as Tab);
    }
  };

  // Deep-link support: ``/appliance?tab=<key>`` forces a specific tab on
  // arrival regardless of the session-stored last-active tab — e.g. the
  // Setup Wizard's "Manage certificate" CTA (→ ?tab=tls) and "View
  // releases" (→ ?tab=releases). We honor it once, persist the choice
  // into the session-backed tab state, then strip the param so a later
  // manual tab switch (or a refresh) isn't overridden. Validating
  // against the full TABS list (not visibleTabs) sidesteps the async
  // ``info`` load race; ``effectiveTab`` below already falls back when a
  // deep-linked tab turns out to be hidden on a docker/k8s control plane.
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get("tab");
  const requestedSection = searchParams.get("section");
  useEffect(() => {
    if (!requestedTab) return;
    const target = LEGACY_TAB_TO_FLEET_SECTION[requestedTab];
    if (target) {
      // Legacy ?tab=tls / ?tab=releases / ?tab=cluster-upgrade now resolve to
      // the Fleet tab + the matching sidebar section (#404).
      setTab("fleet");
      setFleetSection(target);
    } else if (TABS.some((t) => t.key === requestedTab)) {
      setTab(requestedTab as Tab);
      // ?section= deep-links a tab's left sub-section (Cluster: Platform
      // Insights → Containers points at ?tab=cluster&section=pods).
      if (requestedTab === "cluster" && requestedSection) {
        setClusterSection(requestedSection);
      }
    }
    const next = new URLSearchParams(searchParams);
    next.delete("tab");
    next.delete("section");
    setSearchParams(next, { replace: true });
  }, [requestedTab, requestedSection, searchParams, setSearchParams, setTab]);

  const effectiveTab: Tab = visibleTabs.some((t) => t.key === tab)
    ? tab
    : defaultTab;

  const active =
    visibleTabs.find((t) => t.key === effectiveTab) ?? visibleTabs[0];

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center gap-2">
          <Wrench className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold">Appliance management</h1>
          {info?.appliance_version && (
            <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
              v{info.appliance_version}
            </span>
          )}
          {info?.appliance_hostname && (
            <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
              {info.appliance_hostname}
            </span>
          )}
          {!isApplianceHost && (
            <span
              className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground"
              title="This control plane is running on Docker or Kubernetes. Host-level tabs (Cluster, Logs, Network, Maintenance) are hidden — the OS Versions tab still drives slot upgrades on any registered appliance agents."
            >
              docker/k8s
            </span>
          )}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          {isApplianceHost ? (
            <>
              Manage the SpatiumDDI OS appliance — fleet, firewall, cluster,
              logs, host network, and lifecycle. Releases, rolling OS upgrades,
              and the Web UI certificate now live under the Fleet sidebar.
            </>
          ) : (
            <>
              This control plane is running on Docker / Kubernetes. Host-level
              tabs (Cluster, Logs, Network, Maintenance) only apply to an
              appliance-hosted control plane and are hidden here. The OS
              Versions tab still drives slot upgrades on any registered
              appliance agents.
            </>
          )}
        </p>
        <div className="-mb-px mt-3 flex flex-wrap gap-1 border-b">
          {visibleTabs.map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.key}
                type="button"
                onClick={() => setTab(t.key)}
                className={`-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-1.5 text-sm ${
                  effectiveTab === t.key
                    ? "border-primary text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </button>
            );
          })}
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-background p-6">
        {effectiveTab === "fleet" ? (
          <FleetTab
            onNavigateTab={navigate}
            isApplianceHost={isApplianceHost}
            initialSection={fleetSection}
            onSectionApplied={() => setFleetSection(null)}
          />
        ) : effectiveTab === "firewall" ? (
          <FirewallTab />
        ) : effectiveTab === "cluster" ? (
          <ClusterTab
            initialSection={clusterSection}
            onSectionApplied={() => setClusterSection(null)}
          />
        ) : effectiveTab === "logs" ? (
          <LogsTab />
        ) : effectiveTab === "network" ? (
          <NetworkTab />
        ) : effectiveTab === "maintenance" ? (
          <MaintenanceTab />
        ) : active ? (
          <PhasePlaceholder spec={active} />
        ) : null}
      </div>
    </div>
  );
}

function PhasePlaceholder({ spec }: { spec: TabSpec }) {
  const Icon = spec.icon;
  return (
    <div className="mx-auto max-w-2xl rounded-lg border bg-card p-6 shadow-sm">
      <div className="flex items-start gap-3">
        <div className="rounded-md bg-muted p-2 text-muted-foreground">
          <Icon className="h-5 w-5" />
        </div>
        <div className="flex-1">
          <h2 className="text-base font-semibold">{spec.label}</h2>
          <p className="mt-2 text-sm text-muted-foreground">{spec.summary}</p>
        </div>
      </div>
    </div>
  );
}
