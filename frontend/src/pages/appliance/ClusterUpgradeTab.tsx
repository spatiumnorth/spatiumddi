import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  Clock,
  Hourglass,
  Loader2,
  Pause,
  Play,
  RefreshCw,
  Rocket,
  XCircle,
} from "lucide-react";

import {
  applianceUpgradeImagesApi,
  clusterUpgradesApi,
  formatApiError,
  type ClusterUpgradeFailureCategory,
  type ClusterUpgradeState,
  type PerNodeProgress,
  type PreflightCheck,
  type PreflightLevel,
  type PreflightReport,
  type SystemUpgradeRun,
  type UpgradeImage,
} from "@/lib/api";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { cn } from "@/lib/utils";

/**
 * Appliance → Rolling Upgrade tab (#296 Phase G).
 *
 * Consumes the orchestrator surface shipped in Phases A-F:
 *   - GET /upgrades/preflight, /lease, /runs, /{id}
 *   - POST /upgrades/plan, /{id}/start, /{id}/halt, /{id}/resume,
 *     /{id}/abort
 *
 * Layout:
 *   - Top: lease + current-run banner (state pill, holder, target).
 *   - Middle: split between "Plan an upgrade" (when nothing in flight)
 *     and "Live progress" (when a run is in flight).
 *   - Bottom: history of recent runs.
 *
 * Polling cadence:
 *   - 2 s while a run is in flight (state ∈ planned/running/halted)
 *   - 15 s otherwise (terminal-state runs don't change; lease state
 *     can drift slightly from another operator's actions)
 */

const TERMINAL_STATES: ReadonlySet<ClusterUpgradeState> = new Set([
  "succeeded",
  "failed",
  "aborted",
]);

const ACTIVE_STATES: ReadonlySet<ClusterUpgradeState> = new Set([
  "planned",
  "running",
  "halted",
]);

const CATEGORY_LABELS: Record<ClusterUpgradeFailureCategory, string> = {
  preflight_fail: "Pre-flight refused",
  drain_stuck: "Drain stuck",
  cordon_fail: "Cordon failed",
  cnpg_primary_stuck: "CNPG primary stuck",
  node_auto_reverted: "Node auto-reverted",
  node_unreachable_after_apply: "Node unreachable after apply",
  supervisor_reported_failed: "Supervisor reported failed",
  node_did_not_rejoin: "Node didn't rejoin",
  chart_bump_failed: "Chart bump failed",
  uncordon_fail: "Uncordon failed",
  other: "Other",
};

// NB: keep in sync with backend/app/services/upgrades/alerts.py:operator_hint().
// The strings are intentionally shorter here (UI surface is tighter than an
// alert email body); a CI smoke test that walks every category and asserts
// the frontend has a non-empty entry is in test_upgrades_alerts.py's
// test_operator_hint_non_empty parametrisation. If you add a new
// CATEGORY_* constant to the backend, the TypeScript enum guarantees this
// table needs a corresponding entry to compile.
const CATEGORY_HINTS: Record<ClusterUpgradeFailureCategory, string> = {
  preflight_fail:
    "Re-run preflight to see which check failed; resolve before retrying.",
  drain_stuck:
    "Check PodDisruptionBudgets + per-pod status; once unblocked, abort + plan a fresh run.",
  cordon_fail:
    "RBAC issue. Verify api.upgradeOrchestratorRBAC.enabled=true in chart values.",
  cnpg_primary_stuck:
    "CNPG primary didn't switch. Check Cluster.status + replica replay lag.",
  node_auto_reverted:
    "Node reverted to the old slot. Check /health/live + firstboot logs.",
  node_unreachable_after_apply:
    "Check supervisor heartbeat + appliance last_upgrade_state. If unreachable, evict + re-pair.",
  supervisor_reported_failed:
    "Slot apply failed on the node. Check spatium-upgrade-slot.log; the upgrade image may be corrupt.",
  node_did_not_rejoin:
    "Node rebooted but didn't rejoin etcd / DaemonSet pods. Consider evict + re-pair (#272 Ph9).",
  chart_bump_failed:
    "Forward-fix: helm rollback the chart, debug, re-apply the bump.",
  uncordon_fail:
    "Node upgraded but cordon/maintenance-window clear failed. Manual kubectl uncordon required.",
  other: "Check progress.per_node[<node>].error for the raw message.",
};

export function ClusterUpgradeTab() {
  const qc = useQueryClient();

  const { data: lease, isLoading: leaseLoading } = useQuery({
    queryKey: ["upgrades", "lease"],
    queryFn: clusterUpgradesApi.lease,
    refetchInterval: 5_000,
  });

  const { data: runs, refetch: refetchRuns } = useQuery({
    queryKey: ["upgrades", "runs"],
    queryFn: () => clusterUpgradesApi.runs(25),
    refetchInterval: (q) => {
      const list = q.state.data as SystemUpgradeRun[] | undefined;
      const anyActive = list?.some((r) => ACTIVE_STATES.has(r.state));
      return anyActive ? 2_000 : 15_000;
    },
    // Review polish — transient network blips during the 2 s active-run
    // poll shouldn't strand the operator on stale data. Retry 3 times
    // with a linear backoff (1 s / 2 s / 3 s) so a brief api restart
    // self-recovers within ~10 s without surfacing an error banner.
    retry: 3,
    retryDelay: (attempt) => attempt * 1000,
  });

  const activeRun = useMemo(
    () => (runs ?? []).find((r) => ACTIVE_STATES.has(r.state)) ?? null,
    [runs],
  );

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <header className="rounded-lg border bg-card p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Rocket className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-base font-semibold">
              Multi-node rolling upgrade
            </h2>
            {leaseLoading ? null : <LeasePill lease={lease} />}
          </div>
          <button
            type="button"
            onClick={() => {
              qc.invalidateQueries({ queryKey: ["upgrades"] });
              void refetchRuns();
            }}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Walks the cluster from version N-1 to N one node at a time — preflight
          gate, CNPG cordon-triggered switchover, drain, slot apply + reboot,
          health gate, DS-Ready gate, uncordon. Once every node commits the new
          slot, the chart's image.tag bumps + the migrate Job runs.
        </p>
      </header>

      {activeRun ? <ActiveRunPanel run={activeRun} /> : <PlanFormPanel />}

      <HistoryPanel runs={runs ?? []} activeRunId={activeRun?.id ?? null} />
    </div>
  );
}

// ── Lease pill ───────────────────────────────────────────────────────

function LeasePill({ lease }: { lease: ReturnType<typeof useQuery>["data"] }) {
  const state = lease as
    | { held: boolean; holder: string | null; expired: boolean }
    | undefined;
  if (!state)
    return (
      <span className="rounded-md bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
        Lease unknown
      </span>
    );
  if (!state.held)
    return (
      <span className="rounded-md bg-emerald-500/10 px-1.5 py-0.5 text-xs text-emerald-700 dark:text-emerald-300">
        Lease free
      </span>
    );
  return (
    <span
      className="rounded-md bg-blue-500/10 px-1.5 py-0.5 font-mono text-xs text-blue-700 dark:text-blue-300"
      title="The upgrade lease is the cluster-wide single-upgrader lock. While held, no other orchestrator (or operator) can start a new run."
    >
      Lease held · {state.holder ?? "?"}
    </span>
  );
}

// ── Plan form ────────────────────────────────────────────────────────

// Upgrade-image source mode for the rolling upgrade. Operators stage
// an image through Fleet → Upgrade images (upload or GitHub import)
// then pick from the dropdown here ("uploaded"); connected installs
// can instead paste a GitHub release URL ("url"). Default is decided
// dynamically: "uploaded" if at least one image is on file, else "url"
// — so the dropdown becomes invisible to operators who don't use it.
type UpgradeImageSource = "uploaded" | "url";

function PlanFormPanel() {
  const qc = useQueryClient();
  const [targetVersion, setTargetVersion] = useState("");
  const [slotImageUrl, setSlotImageUrl] = useState("");
  const [slotImageId, setSlotImageId] = useState<string>("");
  // ``null`` means "use the smart default once the upgrade-images query
  // resolves"; once the operator explicitly picks one we honour it.
  const [sourceMode, setSourceMode] = useState<UpgradeImageSource | null>(null);
  const [cnpgClusterName, setCnpgClusterName] = useState("");
  const [preflightTarget, setPreflightTarget] = useState<string | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);

  const slotImagesQuery = useQuery({
    queryKey: ["appliance", "upgrade-images"],
    queryFn: applianceUpgradeImagesApi.list,
    // Upgrade images change rarely (operator stages one on a fresh
    // release) — 30 s is plenty of staleness for this picker. Same
    // cadence + cache key the FleetTab UpgradeImageManager uses so the
    // two surfaces don't race each other in cache.
    staleTime: 30_000,
  });
  const slotImages: UpgradeImage[] = slotImagesQuery.data ?? [];

  // Resolve the effective source mode. If the operator hasn't picked
  // explicitly, default to "uploaded" iff at least one image is on
  // file — operators land directly on the dropdown they need.
  const effectiveSource: UpgradeImageSource =
    sourceMode ?? (slotImages.length > 0 ? "uploaded" : "url");

  // Preflight runs on-demand — operator types a target then clicks
  // "Run preflight" before committing to the plan. Cached by target so
  // re-clicking the same target is instant.
  const {
    data: preflight,
    isFetching: preflightLoading,
    refetch: refetchPreflight,
  } = useQuery({
    queryKey: ["upgrades", "preflight", preflightTarget],
    queryFn: () => clusterUpgradesApi.preflight(preflightTarget as string),
    enabled: !!preflightTarget && preflightTarget.length > 0,
    refetchOnWindowFocus: false,
    // Preflight verdicts can move between an operator's preflight click
    // + their Plan click (replication lag spikes, a node flips
    // NotReady). Treat the cached result as stale immediately so any
    // re-mount of the panel fetches a fresh verdict — the operator
    // explicitly clicked Run preflight when they wanted the current
    // value.
    staleTime: 0,
    gcTime: 60_000,
  });

  const planMut = useMutation({
    mutationFn: () =>
      clusterUpgradesApi.plan({
        target_version: targetVersion,
        // Send either ``slot_image_url`` OR ``slot_image_id`` — the
        // backend's ``PlanRequest.model_validator`` rejects "both" /
        // "neither" with a 422 so the UI guard mirrors that shape.
        ...(effectiveSource === "uploaded"
          ? { slot_image_id: slotImageId }
          : { slot_image_url: slotImageUrl }),
        cnpg_cluster_name: cnpgClusterName,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["upgrades"] });
      setPlanError(null);
    },
    onError: (err) => setPlanError(formatApiError(err)),
  });

  // Disable Plan / Run preflight when no image source is resolved.
  // "uploaded" needs a picked image_id; "url" needs a non-empty URL.
  const sourceReady =
    effectiveSource === "uploaded"
      ? slotImageId.trim().length > 0
      : slotImageUrl.trim().length > 0;

  const startMut = useMutation({
    mutationFn: (runId: string) => clusterUpgradesApi.start(runId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upgrades"] }),
    onError: (err) => setPlanError(formatApiError(err)),
  });

  const plannedRunId = planMut.data?.run_id ?? null;

  return (
    <section className="rounded-lg border bg-card p-4">
      <h3 className="text-sm font-semibold">Plan an upgrade</h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Run preflight against a target CalVer tag, review the verdict, then plan
        + start. The orchestrator acquires the Lease at start time; nothing
        happens to the cluster until you click Start.
      </p>

      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="text-xs font-medium text-muted-foreground">
            Target version (CalVer)
          </span>
          <input
            type="text"
            placeholder="2026.06.01-1"
            value={targetVersion}
            onChange={(e) => setTargetVersion(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 font-mono text-sm"
          />
        </label>
        <div className="flex flex-col gap-1">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              Upgrade image source
            </span>
            {/* Air-gap-friendly + online: two radio chips. Selection
                survives until the operator changes it; the default
                tracks "is there at least one uploaded image?" so the
                dropdown becomes visible only when it's useful. */}
            <div className="flex items-center gap-1 text-xs">
              <button
                type="button"
                onClick={() => setSourceMode("uploaded")}
                className={cn(
                  "rounded-l-md border px-2 py-0.5",
                  effectiveSource === "uploaded"
                    ? "border-primary bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-muted",
                )}
              >
                Uploaded
              </button>
              <button
                type="button"
                onClick={() => setSourceMode("url")}
                className={cn(
                  "rounded-r-md border border-l-0 px-2 py-0.5",
                  effectiveSource === "url"
                    ? "border-primary bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-muted",
                )}
              >
                URL
              </button>
            </div>
          </div>
          {effectiveSource === "uploaded" ? (
            slotImages.length === 0 ? (
              // Empty-state copy — point to Fleet → Upgrade images.
              // Workflow is unambiguous: stage there, come back here.
              <div className="rounded-md border border-dashed bg-muted/30 px-2 py-1.5 text-xs text-muted-foreground">
                No staged upgrade images yet. Upload or import a{" "}
                <code>.raw.xz</code> in <strong>Fleet → Upgrade images</strong>,
                then return here. Or switch to <strong>URL</strong> for an
                online install.
              </div>
            ) : (
              <select
                value={slotImageId}
                onChange={(e) => setSlotImageId(e.target.value)}
                className="rounded-md border bg-background px-2 py-1 text-sm"
              >
                <option value="">— pick an uploaded image —</option>
                {slotImages.map((img) => (
                  <option key={img.id} value={img.id}>
                    {img.appliance_version} · {img.filename} ·{" "}
                    {(img.size_bytes / (1024 * 1024)).toFixed(0)} MiB
                  </option>
                ))}
              </select>
            )
          ) : (
            <input
              type="text"
              placeholder="https://github.com/.../spatiumddi-appliance-slot-<VERSION>-amd64.raw.xz"
              value={slotImageUrl}
              onChange={(e) => setSlotImageUrl(e.target.value)}
              className="rounded-md border bg-background px-2 py-1 text-sm"
            />
          )}
        </div>
        <label className="flex flex-col gap-1 sm:col-span-2">
          <span className="text-xs font-medium text-muted-foreground">
            CNPG cluster name (optional)
          </span>
          <input
            type="text"
            placeholder="spatium-control-spatiumddi-postgresql"
            value={cnpgClusterName}
            onChange={(e) => setCnpgClusterName(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 font-mono text-sm"
          />
          <span className="text-xs text-muted-foreground">
            Empty disables CNPG-related steps (single-instance / non-CNPG
            deploys). On the appliance shape this is{" "}
            <code className="font-mono">
              {"<release>"}-spatiumddi-postgresql
            </code>
            .
          </span>
        </label>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={!targetVersion || preflightLoading}
          onClick={() => {
            setPreflightTarget(targetVersion);
            void refetchPreflight();
          }}
          className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
        >
          {preflightLoading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Hourglass className="h-3.5 w-3.5" />
          )}
          Run preflight
        </button>
        <button
          type="button"
          disabled={
            !targetVersion ||
            !sourceReady ||
            !preflight ||
            !preflight.can_start ||
            // #296 review fix — refuse Plan when the typed target
            // has drifted from the preflight target. Otherwise the
            // operator could type a version, run preflight, then
            // type a different version + click Plan, getting a Plan
            // against version X but with preflight verdict from
            // version Y. The backend re-runs preflight inside plan()
            // so the worst case is a 409, but the UI shouldn't
            // surface a green Plan button against a stale verdict.
            preflightTarget !== targetVersion ||
            planMut.isPending
          }
          onClick={() => planMut.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
          title={
            preflight && !preflight.can_start
              ? "Preflight failed — resolve before planning."
              : preflightTarget !== targetVersion
                ? "Re-run preflight against the current target version first."
                : ""
          }
        >
          {planMut.isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <CheckCircle2 className="h-3.5 w-3.5" />
          )}
          Plan
        </button>
        {plannedRunId ? (
          <button
            type="button"
            disabled={startMut.isPending}
            onClick={() => startMut.mutate(plannedRunId)}
            className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 text-sm text-white hover:bg-emerald-700 disabled:opacity-50"
          >
            {startMut.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            Start
          </button>
        ) : null}
      </div>

      {planError ? (
        <div className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-300">
          {planError}
        </div>
      ) : null}

      {preflight ? <PreflightPanel report={preflight} /> : null}

      {planMut.data ? (
        <div className="mt-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs">
          Planned run <code className="font-mono">{planMut.data.run_id}</code> —
          node order:{" "}
          <span className="font-mono">
            {planMut.data.node_order.join(" → ")}
          </span>
          . Click Start to acquire the lease + drive the upgrade.
        </div>
      ) : null}
    </section>
  );
}

// ── Preflight panel ──────────────────────────────────────────────────

function PreflightPanel({ report }: { report: PreflightReport }) {
  const OverallIcon =
    report.overall === "ok"
      ? CheckCircle2
      : report.overall === "warn"
        ? AlertTriangle
        : XCircle;
  const overallTone =
    report.overall === "ok"
      ? "text-emerald-700 dark:text-emerald-300"
      : report.overall === "warn"
        ? "text-amber-700 dark:text-amber-300"
        : "text-rose-700 dark:text-rose-300";

  return (
    <div className="mt-4 rounded-md border">
      <div
        className={cn(
          "flex items-center gap-2 border-b px-3 py-2 text-xs",
          overallTone,
        )}
      >
        <OverallIcon className="h-3.5 w-3.5" />
        <span className="font-medium">
          Preflight: {report.overall.toUpperCase()}
        </span>
        <span className="text-muted-foreground">
          → {report.target_version} (running {report.current_version})
        </span>
      </div>
      <ul className="divide-y">
        {report.results.map((c) => (
          <PreflightRow key={c.name} check={c} />
        ))}
      </ul>
    </div>
  );
}

function PreflightRow({ check }: { check: PreflightCheck }) {
  const tone = levelTone(check.level);
  const Icon =
    check.level === "ok"
      ? CheckCircle2
      : check.level === "warn"
        ? AlertTriangle
        : XCircle;
  return (
    <li className="flex items-start gap-2 px-3 py-2 text-xs">
      <Icon className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", tone)} />
      <div className="flex-1 min-w-0">
        <div className="font-mono">{check.name}</div>
        <div className="text-muted-foreground break-all">{check.message}</div>
      </div>
    </li>
  );
}

function levelTone(level: PreflightLevel): string {
  if (level === "ok") return "text-emerald-600 dark:text-emerald-400";
  if (level === "warn") return "text-amber-600 dark:text-amber-400";
  return "text-rose-600 dark:text-rose-400";
}

// ── Active run panel ─────────────────────────────────────────────────

function ActiveRunPanel({ run }: { run: SystemUpgradeRun }) {
  const qc = useQueryClient();
  const [halting, setHalting] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [aborting, setAborting] = useState(false);
  // Mutation errors that don't fit cleanly in a modal — surfaced as a
  // banner inside the panel. Cleared on the next successful mutation.
  const [actionError, setActionError] = useState<string | null>(null);

  const haltMut = useMutation({
    mutationFn: () => clusterUpgradesApi.halt(run.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["upgrades"] });
      setActionError(null);
    },
    onError: (err) => setActionError(`Halt failed: ${formatApiError(err)}`),
    onSettled: () => setHalting(false),
  });
  const resumeMut = useMutation({
    mutationFn: () => clusterUpgradesApi.resume(run.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["upgrades"] });
      setActionError(null);
    },
    onError: (err) => setActionError(`Resume failed: ${formatApiError(err)}`),
    onSettled: () => setResuming(false),
  });
  const abortMut = useMutation({
    mutationFn: () => clusterUpgradesApi.abort(run.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["upgrades"] });
      setActionError(null);
    },
    onError: (err) => setActionError(`Abort failed: ${formatApiError(err)}`),
    onSettled: () => setAborting(false),
  });
  // #296 review fix — a ``planned`` run that the operator landed on
  // after refresh (the original PlanFormPanel start button is gone
  // since activeRun is now truthy + PlanFormPanel doesn't render).
  // Surfacing Start in the ActiveRunPanel for that state means the
  // operator isn't stranded.
  const startMut = useMutation({
    mutationFn: () => clusterUpgradesApi.start(run.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["upgrades"] });
      setActionError(null);
    },
    onError: (err) => setActionError(`Start failed: ${formatApiError(err)}`),
  });

  const planOrder = run.plan?.node_order ?? [];
  const completedCount = planOrder.filter(
    (n) => run.progress?.per_node?.[n]?.ok === true,
  ).length;
  const failedNode = planOrder.find(
    (n) => run.progress?.per_node?.[n]?.ok === false,
  );

  return (
    <section className="rounded-lg border bg-card p-4">
      <header className="flex flex-wrap items-center gap-2">
        <StatePill state={run.state} />
        <h3 className="text-sm font-semibold">
          → <code className="font-mono">{run.target_version}</code>
        </h3>
        <span className="text-xs text-muted-foreground">
          run{" "}
          <code className="font-mono" title={run.id}>
            {run.id.slice(0, 8)}
          </code>
          {run.lease_holder ? ` · holder ${run.lease_holder}` : ""}
        </span>
        <div className="ml-auto flex flex-wrap gap-2">
          {run.state === "planned" ? (
            // #296 review fix — a planned-but-not-started run that
            // the operator left behind (e.g. closed the tab between
            // Plan + Start) needs a way to start. Without this the
            // operator's only choices are Abort + re-plan from scratch.
            <button
              type="button"
              disabled={startMut.isPending}
              onClick={() => startMut.mutate()}
              className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 text-xs text-white hover:bg-emerald-700 disabled:opacity-50"
            >
              {startMut.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Play className="h-3.5 w-3.5" />
              )}
              Start
            </button>
          ) : null}
          {run.state === "running" ? (
            <button
              type="button"
              onClick={() => setHalting(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-amber-400 px-3 py-1.5 text-xs text-amber-700 hover:bg-amber-50 dark:text-amber-300 dark:hover:bg-amber-950"
            >
              <Pause className="h-3.5 w-3.5" />
              Halt
            </button>
          ) : null}
          {run.state === "halted" ? (
            <button
              type="button"
              onClick={() => setResuming(true)}
              className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 text-xs text-white hover:bg-emerald-700"
            >
              <Play className="h-3.5 w-3.5" />
              Resume
            </button>
          ) : null}
          {ACTIVE_STATES.has(run.state) ? (
            <button
              type="button"
              onClick={() => setAborting(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-rose-400 px-3 py-1.5 text-xs text-rose-700 hover:bg-rose-50 dark:text-rose-300 dark:hover:bg-rose-950"
            >
              <CircleSlash className="h-3.5 w-3.5" />
              Abort
            </button>
          ) : null}
        </div>
      </header>

      {actionError ? (
        <div className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700 dark:text-rose-300">
          {actionError}
        </div>
      ) : null}

      <div className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-3">
        <div className="rounded-md border px-2 py-1.5">
          <div className="text-muted-foreground">Progress</div>
          <div className="font-mono">
            {completedCount} / {planOrder.length} nodes
          </div>
        </div>
        <div className="rounded-md border px-2 py-1.5">
          <div className="text-muted-foreground">Started</div>
          <div className="font-mono">{run.started_at ?? "—"}</div>
        </div>
        <div className="rounded-md border px-2 py-1.5">
          <div className="text-muted-foreground">Last event</div>
          <div className="font-mono">
            {run.progress?.events?.at?.(-1)?.event ?? "—"}
          </div>
        </div>
      </div>

      {failedNode ? (
        <FailureBanner
          node={failedNode}
          progress={run.progress?.per_node?.[failedNode]}
          runError={run.last_error}
        />
      ) : null}

      <NodeProgressList run={run} />

      {run.progress?.chart_bump ? (
        <ChartBumpRow bump={run.progress.chart_bump} />
      ) : null}

      <ConfirmModal
        open={halting}
        title="Halt upgrade?"
        message="Halt pauses the current run between nodes. The currently-driving node finishes its step before pausing. Use Resume to continue."
        confirmLabel="Halt"
        onClose={() => setHalting(false)}
        onConfirm={() => haltMut.mutate()}
      />
      <ConfirmModal
        open={resuming}
        title="Resume upgrade?"
        message="Re-enqueues the orchestrator to pick up where it halted. Already-completed nodes are skipped."
        confirmLabel="Resume"
        onClose={() => setResuming(false)}
        onConfirm={() => resumeMut.mutate()}
      />
      <ConfirmModal
        open={aborting}
        title="Abort upgrade?"
        message="Abort is terminal — no resume. Leaves the cluster in whatever partial state the in-flight nodes ended in. Operator owns cleanup."
        confirmLabel="Abort"
        tone="destructive"
        onClose={() => setAborting(false)}
        onConfirm={() => abortMut.mutate()}
      />
    </section>
  );
}

function FailureBanner({
  node,
  progress,
  runError,
}: {
  node: string;
  progress: PerNodeProgress | undefined;
  runError: string | null;
}) {
  if (!progress) return null;
  const cat = progress.failure_category;
  return (
    <div className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs">
      <div className="flex items-center gap-2 text-rose-700 dark:text-rose-300">
        <XCircle className="h-3.5 w-3.5" />
        <span className="font-semibold">
          Failed at <code className="font-mono">{progress.failed_at}</code> on{" "}
          <code className="font-mono">{node}</code>
        </span>
        {cat ? (
          <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] uppercase">
            {CATEGORY_LABELS[cat] ?? cat}
          </span>
        ) : null}
      </div>
      {progress.error ? (
        <div className="mt-1 font-mono text-rose-700 dark:text-rose-300 break-all">
          {progress.error}
        </div>
      ) : null}
      {cat && CATEGORY_HINTS[cat] ? (
        <div className="mt-2 text-rose-700/80 dark:text-rose-300/80">
          <strong>Next step:</strong> {CATEGORY_HINTS[cat]}
        </div>
      ) : runError ? (
        <div className="mt-2 text-rose-700/80 dark:text-rose-300/80 break-all">
          {runError}
        </div>
      ) : null}
    </div>
  );
}

function NodeProgressList({ run }: { run: SystemUpgradeRun }) {
  const planOrder = run.plan?.node_order ?? [];
  return (
    <ul className="mt-3 divide-y rounded-md border">
      {planOrder.map((node) => {
        const p = run.progress?.per_node?.[node];
        return <NodeRow key={node} node={node} progress={p} />;
      })}
    </ul>
  );
}

function NodeRow({
  node,
  progress,
}: {
  node: string;
  progress: PerNodeProgress | undefined;
}) {
  const status: "pending" | "running" | "ok" | "failed" = !progress
    ? "pending"
    : progress.ok
      ? "ok"
      : progress.failed_at === null
        ? "running"
        : "failed";

  const Icon =
    status === "ok"
      ? CheckCircle2
      : status === "failed"
        ? XCircle
        : status === "running"
          ? Loader2
          : Clock;
  const tone =
    status === "ok"
      ? "text-emerald-600"
      : status === "failed"
        ? "text-rose-600"
        : status === "running"
          ? "text-blue-600 animate-spin"
          : "text-muted-foreground";

  return (
    <li className="flex items-start gap-2 px-3 py-2 text-xs">
      <Icon className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", tone)} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <code className="font-mono font-medium">{node}</code>
          {progress?.steps?.length ? (
            <span className="text-muted-foreground">
              · last step{" "}
              <code className="font-mono">{progress.steps.at(-1)?.name}</code>
            </span>
          ) : null}
        </div>
        {progress?.error ? (
          <div className="mt-1 text-rose-700 dark:text-rose-300 break-all">
            {progress.error}
          </div>
        ) : null}
      </div>
    </li>
  );
}

function ChartBumpRow({
  bump,
}: {
  bump: NonNullable<SystemUpgradeRun["progress"]["chart_bump"]>;
}) {
  const Icon = bump.ok ? CheckCircle2 : bump.skipped ? Clock : XCircle;
  const tone = bump.ok
    ? "text-emerald-600"
    : bump.skipped
      ? "text-muted-foreground"
      : "text-rose-600";
  return (
    <div className="mt-3 rounded-md border px-3 py-2 text-xs">
      <div className="flex items-center gap-2">
        <Icon className={cn("h-3.5 w-3.5", tone)} />
        <span className="font-medium">Chart bump</span>
        <span className="text-muted-foreground">
          → image.tag = {bump.new_tag}
        </span>
        {bump.skipped ? (
          <span className="text-muted-foreground">
            (skipped: {bump.skip_reason})
          </span>
        ) : null}
      </div>
      {bump.rolled_deployments && bump.rolled_deployments.length ? (
        <div className="mt-1 text-muted-foreground">
          Rolled: {bump.rolled_deployments.join(", ")}
        </div>
      ) : null}
      {bump.migrate_job_state ? (
        <div className="mt-1 text-muted-foreground">
          Migrate Job: {bump.migrate_job_state}
        </div>
      ) : null}
      {bump.error ? (
        <div className="mt-1 text-rose-700 dark:text-rose-300 break-all">
          {bump.error}
        </div>
      ) : null}
    </div>
  );
}

function StatePill({ state }: { state: ClusterUpgradeState }) {
  const tone =
    state === "succeeded"
      ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
      : state === "failed"
        ? "bg-rose-500/10 text-rose-700 dark:text-rose-300"
        : state === "halted"
          ? "bg-amber-500/10 text-amber-700 dark:text-amber-300"
          : state === "aborted"
            ? "bg-muted text-muted-foreground"
            : state === "running"
              ? "bg-blue-500/10 text-blue-700 dark:text-blue-300"
              : "bg-muted text-muted-foreground";
  return (
    <span
      className={cn(
        "rounded-md px-1.5 py-0.5 text-xs uppercase tracking-wide",
        tone,
      )}
    >
      {state}
    </span>
  );
}

// ── History ──────────────────────────────────────────────────────────

function HistoryPanel({
  runs,
  activeRunId,
}: {
  runs: SystemUpgradeRun[];
  activeRunId: string | null;
}) {
  const past = runs.filter(
    (r) => r.id !== activeRunId && TERMINAL_STATES.has(r.state),
  );
  if (past.length === 0)
    return (
      <section className="rounded-lg border bg-card p-4 text-sm text-muted-foreground">
        No past upgrades yet.
      </section>
    );
  return (
    <section className="rounded-lg border bg-card p-4">
      <h3 className="text-sm font-semibold">History</h3>
      <ul className="mt-2 divide-y">
        {past.slice(0, 10).map((r) => (
          <li
            key={r.id}
            className="flex items-center gap-2 py-2 text-xs"
            title={r.id}
          >
            <StatePill state={r.state} />
            <code className="font-mono">{r.target_version}</code>
            <span className="text-muted-foreground">
              · {r.finished_at ?? r.started_at ?? "—"}
            </span>
            {r.last_error ? (
              <span className="ml-auto truncate text-rose-600 dark:text-rose-300">
                {r.last_error}
              </span>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}
