import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Boxes,
  Container as ContainerIcon,
  DatabaseBackup,
  Gauge,
} from "lucide-react";

import { applianceApprovalApi } from "@/lib/api";
import { ListEmpty } from "@/components/ui/list-read-error";
import { useSessionState } from "@/lib/useSessionState";
import { ClusterOverview } from "./ClusterOverview";
import { ContainersTab } from "./ContainersTab";
import { EtcdSnapshotsCard } from "./EtcdSnapshotsCard";

/**
 * Cluster tab (issue #402).
 *
 * Combines two views of the k3s cluster underneath the appliance into a
 * single operator-friendly tab behind a left sub-nav:
 *
 *   - Pods           — the running workloads (logs / restart), formerly
 *                      its own top-level "Pods" tab (ContainersTab).
 *   - etcd snapshots — the cluster's disaster-recovery state + guided
 *                      restore, previously rendered inline on the Fleet
 *                      tab where it crowded the appliance roster (#402).
 *
 * Deliberately named "Cluster", not "Kubernetes" — operators shouldn't
 * need k8s vocabulary to find pod / etcd controls, but it's still honest
 * about what it is (a single- or multi-node k3s cluster). The sub-nav
 * keeps each section full-height so neither competes for vertical space
 * (the original Fleet-tab complaint).
 *
 * Whole tab is gated selfOnly at AppliancePage (appliance hosts only):
 * Pods needs the in-cluster kubeapi and etcd snapshots need the embedded
 * etcd seed — neither exists on a docker / k8s control plane.
 */
type ClusterSection = "overview" | "pods" | "etcd";

const SECTIONS: {
  key: ClusterSection;
  label: string;
  icon: typeof ContainerIcon;
  hint: string;
}[] = [
  {
    key: "overview",
    label: "Overview",
    icon: Gauge,
    hint: "Live dashboard & metrics",
  },
  {
    key: "pods",
    label: "Pods",
    icon: ContainerIcon,
    hint: "Running workloads",
  },
  {
    key: "etcd",
    label: "etcd snapshots",
    icon: DatabaseBackup,
    hint: "Disaster recovery",
  },
];

export function ClusterTab({
  initialSection = null,
  onSectionApplied,
}: {
  // #404 follow-up — a deep-link (?tab=cluster&section=pods, e.g. from Platform
  // Insights → Containers) selects a sub-section on arrival; cleared via
  // onSectionApplied so re-navigating to the same section fires again.
  initialSection?: string | null;
  onSectionApplied?: () => void;
} = {}) {
  const [section, setSection] = useSessionState<ClusterSection>(
    "appliance.cluster.section",
    "overview",
  );

  useEffect(() => {
    if (initialSection) {
      setSection(initialSection as ClusterSection);
      onSectionApplied?.();
    }
    // Gate purely on the prop; setSection/onSectionApplied identities are stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialSection]);

  // Shared with EtcdSnapshotsCard (same query key → React Query dedupes)
  // purely so the etcd section can show a friendly placeholder instead of
  // a blank pane before the seed first reports its snapshots on heartbeat.
  const { data: etcd, error: etcdError } = useQuery({
    queryKey: ["appliance", "etcd-snapshots"],
    queryFn: applianceApprovalApi.listEtcdSnapshots,
    staleTime: 20_000,
  });
  const etcdAvailable = !!etcd?.available;

  return (
    <div className="flex gap-6">
      <nav className="w-48 shrink-0 space-y-1">
        <div className="mb-2 flex items-center gap-1.5 px-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          <Boxes className="h-3.5 w-3.5" />
          Cluster
        </div>
        {SECTIONS.map((s) => {
          const Icon = s.icon;
          const active = section === s.key;
          return (
            <button
              key={s.key}
              type="button"
              onClick={() => setSection(s.key)}
              className={`flex w-full flex-col items-start gap-0.5 rounded-md px-2 py-1.5 text-left ${
                active
                  ? "bg-accent text-foreground"
                  : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
              }`}
            >
              <span className="flex items-center gap-1.5 text-sm">
                <Icon className="h-3.5 w-3.5" />
                {s.label}
              </span>
              <span className="pl-5 text-[11px] text-muted-foreground">
                {s.hint}
              </span>
            </button>
          );
        })}
      </nav>

      <div className="min-w-0 flex-1">
        {section === "overview" ? (
          <ClusterOverview onViewPods={() => setSection("pods")} />
        ) : section === "pods" ? (
          <ContainersTab />
        ) : etcdAvailable ? (
          <div className="mx-auto max-w-4xl">
            <EtcdSnapshotsCard />
          </div>
        ) : (
          <div className="mx-auto max-w-2xl rounded-lg border border-dashed bg-muted/30 px-6 py-12 text-center text-sm text-muted-foreground">
            {/* #3107 — a refused read is not "no snapshots yet". */}
            <ListEmpty error={etcdError} what="the etcd snapshots">
              No recoverable etcd snapshots yet. These appear once the cluster
              seed reports its embedded-etcd snapshots on heartbeat (k3s takes
              one every ~6&nbsp;h, retains 8 — or run{" "}
              <code>k3s etcd-snapshot save</code> on the seed for one now).
            </ListEmpty>
          </div>
        )}
      </div>
    </div>
  );
}
