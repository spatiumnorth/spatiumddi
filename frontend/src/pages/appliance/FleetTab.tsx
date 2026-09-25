import { Fragment, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  Ban,
  CheckCircle2,
  DownloadCloud,
  FileText,
  HardDrive,
  KeyRound,
  Loader2,
  Network,
  Power,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Trash2,
  Upload,
  XCircle,
} from "lucide-react";

import {
  applianceApi,
  applianceApprovalApi,
  applianceUpgradeImagesApi,
  authApi,
  dhcpApi,
  dnsApi,
  type ApplianceRow,
  type ApplianceListResponse,
  type ApplianceWorkload,
  type ApplianceState,
  type ApplianceUpgradeStep,
  type ControlPlaneReplaceResult,
  type RemovableDisk,
  type RemovableMount,
  type StorageActionRequest,
  type StorageActionResult,
  type SupervisorCapabilities,
  type AvailableUpgradeImage,
  type UpgradeImage,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { ReauthFields } from "@/components/ReauthFields";
import { useSessionState } from "@/lib/useSessionState";
import { cn } from "@/lib/utils";
import {
  formatEta,
  formatMdLevel,
  mpathChipLabel,
  storageChipClass,
  storageSeverityClass,
} from "@/lib/storage-health";
import { fmtDiskBytes } from "./clusterShared";
import { LLDPTab } from "./LLDPTab";
import { AptTab } from "./AptTab";
import { NTPTab } from "./NTPTab";
import { PairingTab } from "./PairingTab";
import { ResolverTab } from "./ResolverTab";
import { SNMPTab } from "./SNMPTab";
import { SSHTab } from "./SSHTab";
import { SyslogTab } from "./SyslogTab";
// #404 — these three moved out of the top-level tab bar into this sidebar.
import { CertificatesTab } from "./CertificatesTab";
import { ClusterUpgradeTab } from "./ClusterUpgradeTab";
import { ReleasesTab } from "./ReleasesTab";

/**
 * Appliance → Fleet tab (#170 Wave D1; supersedes Wave B3 "Approvals").
 *
 * Supervisors that claimed a pairing code show up here. Pending rows
 * pin at the top with Approve / Reject; approved rows render capability
 * chips + cert metadata + Re-key / Delete actions. Clicking any row
 * opens the drilldown modal carrying the full capabilities block,
 * cert serial, fingerprint, and audit metadata.
 *
 * Adaptive polling — 2 s while at least one pending row exists (so a
 * fresh supervisor registration appears within seconds of the operator
 * paging the admin to approve), 15 s otherwise.
 */

const inputCls =
  "rounded-md border bg-background px-3 py-1.5 text-sm disabled:opacity-60";

function stateBadge(state: ApplianceState): {
  label: string;
  className: string;
  Icon: typeof ShieldCheck;
} {
  if (state === "approved") {
    return {
      label: "approved",
      className:
        "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30",
      Icon: ShieldCheck,
    };
  }
  if (state === "rejected") {
    return {
      label: "rejected",
      className:
        "bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/30",
      Icon: ShieldAlert,
    };
  }
  if (state === "revoked") {
    // Issue #170 Wave E follow-up — soft-deleted. Visually distinct
    // from ``rejected`` (which is an admin saying "I don't want this
    // pairing") via the amber palette; rejected stays rose.
    return {
      label: "revoked",
      className:
        "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30",
      Icon: ShieldAlert,
    };
  }
  return {
    label: "pending",
    className:
      "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/40",
    Icon: ShieldQuestion,
  };
}

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return "<1m ago";
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

function shortFingerprint(fp: string | null | undefined): string {
  if (!fp) return "—";
  return fp.length > 16 ? `${fp.slice(0, 8)}…${fp.slice(-6)}` : fp;
}

// Compact capability chips for the row. Each chip lights up only when
// the supervisor advertised that capability. has_baked_images is shown
// as a separate badge because operationally it's a deployment-mode
// signal (air-gap-ready) rather than a service capability.
function capabilityChips(caps: SupervisorCapabilities): {
  key: string;
  label: string;
}[] {
  const out: { key: string; label: string }[] = [];
  if (caps.can_run_dns_bind9) out.push({ key: "bind9", label: "BIND9" });
  if (caps.can_run_dns_powerdns)
    out.push({ key: "powerdns", label: "PowerDNS" });
  if (caps.can_run_dns_technitium)
    out.push({ key: "technitium", label: "Technitium" });
  if (caps.can_run_dhcp) out.push({ key: "dhcp", label: "DHCP" });
  if (caps.can_run_looking_glass)
    out.push({ key: "looking-glass", label: "Looking Glass" });
  if (caps.can_run_observer) out.push({ key: "observer", label: "Observer" });
  return out;
}

// Service chips rendered in the appliance-list Services column.
// Distinct from ``capabilityChips``: capabilities = what the supervisor
// CAN run (image is loaded), services = what the supervisor IS running
// (operator assigned the role + the compose lifecycle reports it healthy).
// Colour follows ``role_switch_state``: ``ready`` → green, ``failed`` →
// rose, anything else (``idle`` / null / pre-first-apply) → amber.
// ``observer`` always renders neutral because there's no service
// container behind it — the supervisor IS the observer.
function serviceChips(row: ApplianceRow): {
  key: string;
  label: string;
  status: "ready" | "failed" | "pending" | "neutral";
}[] {
  const roles = row.assigned_roles ?? [];
  if (roles.length === 0) return [];
  const lifecycle = row.role_switch_state;
  const serviceStatus: "ready" | "failed" | "pending" =
    lifecycle === "ready"
      ? "ready"
      : lifecycle === "failed"
        ? "failed"
        : "pending";
  const out: {
    key: string;
    label: string;
    status: "ready" | "failed" | "pending" | "neutral";
  }[] = [];
  if (roles.includes("dns-bind9"))
    out.push({ key: "dns-bind9", label: "DNS · BIND9", status: serviceStatus });
  if (roles.includes("dns-powerdns"))
    out.push({
      key: "dns-powerdns",
      label: "DNS · PowerDNS",
      status: serviceStatus,
    });
  if (roles.includes("dns-technitium"))
    out.push({
      key: "dns-technitium",
      label: "DNS · Technitium",
      status: serviceStatus,
    });
  if (roles.includes("dhcp"))
    out.push({ key: "dhcp", label: "DHCP", status: serviceStatus });
  if (roles.includes("looking-glass"))
    out.push({
      key: "looking-glass",
      label: "Looking Glass",
      status: serviceStatus,
    });
  if (roles.includes("observer"))
    out.push({ key: "observer", label: "Observer", status: "neutral" });
  return out;
}

const SERVICE_CHIP_STYLES: Record<
  "ready" | "failed" | "pending" | "neutral",
  string
> = {
  ready:
    "bg-emerald-500/15 text-emerald-700 border-emerald-500/40 dark:text-emerald-300",
  failed: "bg-rose-500/15 text-rose-700 border-rose-500/40 dark:text-rose-300",
  pending:
    "bg-amber-500/15 text-amber-700 border-amber-500/40 dark:text-amber-300",
  neutral: "bg-muted text-muted-foreground border-border",
};

// #272 Phase 1 — Fleet UI two-table split. Control-plane variants run
// the umbrella chart (api / frontend / worker / beat / postgres /
// redis); the ``appliance`` variant runs the DNS / DHCP service
// containers. NULL is treated as service-agent. The legacy full-stack
// / frontend-core / control-cluster-member strings are kept here so a
// not-yet-reinstalled box still classifies onto the control-plane side.
// (Surfacing a *promoted* appliance on the control-plane side via
// cluster_role is Phase 7c UI work.)
const CONTROL_PLANE_VARIANTS = new Set([
  "control-plane",
  // legacy (pre-#272) aliases:
  "full-stack",
  "frontend-core",
  "control-cluster-member",
]);
function isControlPlaneRow(row: ApplianceRow): boolean {
  // A row belongs on the control-plane side if it installed as a
  // control-plane variant OR it has actually joined the k3s control
  // plane (an `appliance`-variant box promoted to a cluster member —
  // #272 Phase 7). Without the cluster_role check a promoted member
  // keeps rendering under "Service agents" even though it's now an
  // etcd/control-plane node.
  return (
    CONTROL_PLANE_VARIANTS.has(row.appliance_variant ?? "") ||
    row.cluster_role === "primary" ||
    row.cluster_role === "member"
  );
}

// #590 — is this row pinned in a cluster transition that will never
// converge on its own? Every transition settles only when a supervisor
// reports back (``ready`` / ``left`` / the seed's eviction), and none of
// them has a timeout — so a dead node mid-join, or a seed that can't
// reach the kubeapi, leaves the row here indefinitely. ``ready`` /
// ``left`` / ``failed`` are terminal and need no rescue.
//
// The AGE gate is load-bearing, not cosmetic. A k3s server join
// legitimately takes minutes, and clearing a running join blanks the
// desired-state out from under it — the joiner then comes up as a live
// control-plane member that cp-size scaling, MetalLB and quorum math all
// undercount. So the hatch is only offered once the transition has sat
// long enough that it is not going to finish on its own. Must stay in step
// with ``_CLUSTER_TRANSITION_STUCK_AFTER`` on the server, which enforces
// the same threshold and 409s a premature clear.
//
// ``evict_requested`` is deliberately not consulted: the schema doesn't
// expose it, and the replace endpoint always stamps ``evicting`` next to
// it, so the state alone is sufficient. The server re-validates anyway
// and 409s a row that isn't really in flight.
const _STUCK_JOIN_STATES = new Set(["joining", "leaving", "evicting"]);
const _STUCK_AFTER_MS = 10 * 60 * 1000;
function isClusterTransitionStuck(row: ApplianceRow): boolean {
  const inFlight =
    _STUCK_JOIN_STATES.has(row.cluster_join_state ?? "") ||
    row.desired_cluster_role != null;
  if (!inFlight) return false;
  // No timestamp (a row written before this column existed) means we can't
  // prove the transition is young — offer the hatch, exactly as the server
  // allows it in that case.
  if (!row.cluster_join_state_at) return true;
  const startedAt = Date.parse(row.cluster_join_state_at);
  if (Number.isNaN(startedAt)) return true;
  return Date.now() - startedAt >= _STUCK_AFTER_MS;
}

// #272 Phase 7c — settled / in-flight control-plane cluster membership.
const _CLUSTER_CHIP_BASE =
  "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium";
function ClusterStatusChip({ row }: { row: ApplianceRow }) {
  const js = row.cluster_join_state;
  // An in-flight join/leave takes precedence over the settled role.
  if (js && js !== "ready" && js !== "left") {
    const tone =
      js === "failed"
        ? "border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-300"
        : "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-300";
    const label =
      js === "joining" ? "joining…" : js === "leaving" ? "leaving…" : js;
    return (
      <span
        className={cn(_CLUSTER_CHIP_BASE, tone)}
        title={row.cluster_join_reason ?? ""}
      >
        cluster: {label}
      </span>
    );
  }
  if (row.cluster_role === "primary" || row.cluster_role === "member") {
    return (
      <span
        className={cn(
          _CLUSTER_CHIP_BASE,
          "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300",
        )}
        title={
          row.cluster_role === "primary"
            ? "etcd seed — runs the control plane + the cluster's etcd"
            : "control-plane cluster member (joined the seed)"
        }
      >
        {row.cluster_role === "primary" ? "etcd seed" : "cluster member"}
      </span>
    );
  }
  return null;
}

// #272 Phase 7c — batch promote/demote control-plane members. etcd HA
// wants an ODD server count (1 / 3 / 5 / 7), so this is multi-select:
// a single 1→2 promote is refused by the API guard, you promote two at
// once to reach 3. The API enforces the odd-target rule; we both
// pre-empt it (disable when the resulting count is even) and surface
// its 422 message inline.
// #272 — shown after a promote so the operator knows the work is async.
// The POST only stamps desired-state; the k3s join (~30-60s) + the API
// cert regeneration (which adds the new node's SAN and rolls the frontend
// nginx pod, briefly closing :443) all happen after. Without this the
// operator sees a silent success, then a dead page, with no idea a reload
// fixes it. Polls the fleet so it can say WHEN it's safe to reload.
/**
 * Hoisted so their identity is stable across renders.
 *
 * React Query v5 reuses a cached selector result only while
 * `options.select` keeps the same REFERENCE. An inline arrow is a fresh
 * identity every render, so `select` re-runs and its result is re-walked
 * by `replaceEqualDeep` — a deep compare of every appliance row's
 * `cluster_health`, `role_health`, `firewall_state`, `capabilities` and
 * the rest. Before the fleet block was added the query returned the
 * array directly with no `select` at all, so that cost was zero; these
 * are the only `select:` usages in the frontend, so this file sets the
 * pattern.
 */
const selectApplianceRows = (d: ApplianceListResponse) => d.appliances;
const selectMtuFleet = (d: ApplianceListResponse) => d.mtu_fleet;

function PromotionProgressModal({
  promoted,
  onClose,
}: {
  promoted: { id: string; hostname: string }[];
  onClose: () => void;
}) {
  // Poll faster than the parent table's 15s cadence while the promote
  // settles. Same query key → shares the cache (the table behind this
  // modal updates too). retry rides out the brief API outage when the
  // cert regenerates and the frontend nginx pod rolls.
  const { data, error } = useQuery({
    queryKey: ["appliance", "fleet"],
    // #1017 — the response now carries a fleet-level MTU verdict as well
    // as the rows. `select` hands this caller the rows it already
    // expected; React Query still issues one request per key, so the
    // banner below shares this fetch rather than adding another.
    queryFn: applianceApprovalApi.listFleet,
    select: selectApplianceRows,
    refetchInterval: 3000,
    retry: true,
  });

  const rowById = new Map((data ?? []).map((r) => [r.id, r]));
  const statuses = promoted.map((p) => {
    const row = rowById.get(p.id);
    const js = row?.cluster_join_state ?? null;
    const role = row?.cluster_role ?? null;
    return {
      ...p,
      // cluster_role flips to "member" once settled; cluster_join_state
      // hits "ready" a beat earlier — treat either as done.
      ready: role === "member" || js === "ready",
      failed: js === "failed",
      reason: row?.cluster_join_reason ?? null,
    };
  });
  const allReady = statuses.length > 0 && statuses.every((s) => s.ready);
  const anyFailed = statuses.some((s) => s.failed);

  return (
    <Modal title="Promotion started" onClose={onClose}>
      <div className="space-y-4 text-sm">
        <p className="text-muted-foreground">
          {promoted.map((p) => p.hostname).join(", ")}{" "}
          {promoted.length === 1 ? "is" : "are"} joining the control plane. This
          takes about <strong>30–90 seconds</strong>. The API certificate
          regenerates to cover the new node, so this page may briefly show a
          connection error — that’s expected.
        </p>

        <div className="space-y-1">
          {statuses.map((s) => (
            <div key={s.id} className="flex items-center gap-2">
              <span
                className={cn(
                  "h-2 w-2 rounded-full",
                  s.failed
                    ? "bg-rose-500"
                    : s.ready
                      ? "bg-emerald-500"
                      : "animate-pulse bg-amber-500",
                )}
              />
              <span>{s.hostname}</span>
              <span
                className={cn(
                  "text-xs",
                  s.failed
                    ? "text-rose-500"
                    : s.ready
                      ? "text-emerald-600 dark:text-emerald-400"
                      : "text-muted-foreground",
                )}
                title={s.reason ?? ""}
              >
                {s.failed ? "failed" : s.ready ? "ready" : "joining…"}
              </span>
            </div>
          ))}
        </div>

        {error && !allReady && (
          <p className="text-xs text-amber-600 dark:text-amber-400">
            API briefly unreachable — expected while the certificate
            regenerates. Reconnecting…
          </p>
        )}

        {allReady ? (
          <p className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-emerald-700 dark:text-emerald-300">
            Cluster converged. Reload the page to reconnect over the new
            certificate.
          </p>
        ) : anyFailed ? (
          <p className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-rose-700 dark:text-rose-300">
            A node failed to join — check the Fleet list / supervisor logs. You
            can reload to refresh the view.
          </p>
        ) : (
          <p className="text-xs text-muted-foreground">
            Waiting for the cluster to converge…
          </p>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            className="rounded-md border px-3 py-1.5 text-sm"
            onClick={onClose}
          >
            Dismiss
          </button>
          <button
            type="button"
            className={cn(
              "rounded-md border px-3 py-1.5 text-sm",
              allReady && "border-emerald-500/50 bg-emerald-500/10 font-medium",
            )}
            onClick={() => window.location.reload()}
          >
            Reload now
          </button>
        </div>
      </div>
    </Modal>
  );
}

function ClusterMembershipModal({
  rows,
  onClose,
}: {
  rows: ApplianceRow[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [promoteSel, setPromoteSel] = useState<Set<string>>(new Set());
  const [demoteSel, setDemoteSel] = useState<Set<string>>(new Set());

  // Current control-plane members for the odd-count math. A node is a
  // member if it's a control-plane node by INSTALL VARIANT (the seed —
  // isControlPlaneRow) OR an actually-joined cluster member. The seed
  // has cluster_role=null until the first promote *designates* it, so
  // counting cluster_role alone undercounts by 1 and the modal showed
  // "Current members: 0" / blocked an odd 1→3 promote. Matches the
  // backend's _resolve_primary (which counts the lone seed as 1).
  const members = rows.filter(
    (r) =>
      r.state !== "revoked" &&
      (isControlPlaneRow(r) ||
        r.cluster_role === "primary" ||
        r.cluster_role === "member"),
  );
  // Alphabetical by hostname (natural sort so ddi2 < ddi10), not the
  // API's IP order — operators scan the promote/demote lists by name.
  const byHostname = (a: ApplianceRow, b: ApplianceRow) =>
    (a.hostname ?? "").localeCompare(b.hostname ?? "", undefined, {
      numeric: true,
      sensitivity: "base",
    });
  // Only actually-joined members are demotable (never the seed).
  const demotable = members
    .filter((r) => r.cluster_role === "member")
    .sort(byHostname);
  const memberCount = members.length;
  // Eligible to promote: approved OS-appliance nodes that aren't already
  // a control-plane node (the seed / a promoted member) and aren't
  // mid-join. ``isControlPlaneRow`` keys off the install variant, so a
  // control-plane node is excluded even before it's formally designated
  // primary (cluster_role is null until the first promote) — you can't
  // promote a control plane to a control plane.
  const eligible = rows
    .filter(
      (r) =>
        r.state === "approved" &&
        r.deployment_kind === "appliance" &&
        !isControlPlaneRow(r) &&
        !r.cluster_role &&
        r.desired_cluster_role !== "member",
    )
    .sort(byHostname);

  // Captured on a successful promote so PromotionProgressModal can track
  // the very nodes we just promoted as they converge.
  const [promotedProgress, setPromotedProgress] = useState<
    { id: string; hostname: string }[] | null
  >(null);

  const refresh = () =>
    qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
  const promote = useMutation({
    mutationFn: () => applianceApprovalApi.promoteControlPlane([...promoteSel]),
    onSuccess: () => {
      // Snapshot the picked rows (hostname for display) before clearing
      // the selection, then hand off to the progress modal.
      setPromotedProgress(
        eligible
          .filter((r) => promoteSel.has(r.id))
          .map((r) => ({ id: r.id, hostname: r.hostname ?? r.id })),
      );
      refresh();
      setPromoteSel(new Set());
    },
  });
  const demote = useMutation({
    mutationFn: () => applianceApprovalApi.demoteControlPlane([...demoteSel]),
    onSuccess: () => {
      refresh();
      setDemoteSel(new Set());
    },
  });

  const toggle = (
    set: Set<string>,
    id: string,
    setter: (s: Set<string>) => void,
  ) => {
    const next = new Set(set);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setter(next);
  };

  const resultingPromote = memberCount + promoteSel.size;
  const resultingDemote = memberCount - demoteSel.size;
  const promoteEven = promoteSel.size > 0 && resultingPromote % 2 === 0;
  const demoteEven = demoteSel.size > 0 && resultingDemote % 2 === 0;

  return (
    <>
      {promotedProgress && (
        <PromotionProgressModal
          promoted={promotedProgress}
          onClose={() => {
            // Promote is done — close the progress modal and the cluster
            // modal behind it; the operator reloads from a clean slate.
            setPromotedProgress(null);
            onClose();
          }}
        />
      )}
      <Modal title="Manage control plane cluster" onClose={onClose} wide>
        <div className="space-y-5 text-sm">
          <p className="text-muted-foreground">
            The control-plane cluster runs on embedded etcd, which wants an{" "}
            <strong>odd</strong> server count (1 / 3 / 5 / 7) for quorum.
            Promote or demote in batches so the total lands on an odd number —
            the server refuses an even result. Current members:{" "}
            <strong>{memberCount}</strong>.
          </p>

          {/* ── Promote ──────────────────────────────────────────── */}
          <section className="space-y-2">
            <h4 className="font-medium">Promote appliances → control plane</h4>
            {eligible.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No eligible appliance nodes (need an approved, paired Appliance
                that isn’t already a member).
              </p>
            ) : (
              <div className="space-y-1">
                {eligible.map((r) => (
                  <label key={r.id} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={promoteSel.has(r.id)}
                      onChange={() => toggle(promoteSel, r.id, setPromoteSel)}
                    />
                    <span>{r.hostname}</span>
                    {r.last_seen_ip && (
                      <span className="text-xs text-muted-foreground">
                        {r.last_seen_ip}
                      </span>
                    )}
                  </label>
                ))}
              </div>
            )}
            {promoteSel.size > 0 && (
              <p
                className={cn(
                  "text-xs",
                  promoteEven ? "text-rose-500" : "text-muted-foreground",
                )}
              >
                Resulting members: {resultingPromote}
                {promoteEven &&
                  " — even; select one more (or fewer) to make it odd"}
              </p>
            )}
            {promote.error && (
              <p className="text-xs text-rose-500">
                {formatApiError(promote.error)}
              </p>
            )}
            <button
              type="button"
              className="rounded-md border px-3 py-1.5 text-sm disabled:opacity-50"
              disabled={
                promoteSel.size === 0 || promoteEven || promote.isPending
              }
              onClick={() => promote.mutate()}
            >
              {promote.isPending
                ? "Promoting…"
                : `Promote ${promoteSel.size || ""} to control plane`}
            </button>
          </section>

          {/* ── Demote ───────────────────────────────────────────── */}
          <section className="space-y-2 border-t pt-4">
            <h4 className="font-medium">Demote members → appliance</h4>
            {demotable.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No demotable members (the etcd seed can’t be demoted here).
              </p>
            ) : (
              <div className="space-y-1">
                {demotable.map((r) => (
                  <label key={r.id} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={demoteSel.has(r.id)}
                      onChange={() => toggle(demoteSel, r.id, setDemoteSel)}
                    />
                    <span>{r.hostname}</span>
                  </label>
                ))}
              </div>
            )}
            {demoteSel.size > 0 && (
              <p
                className={cn(
                  "text-xs",
                  demoteEven ? "text-rose-500" : "text-muted-foreground",
                )}
              >
                Remaining members: {resultingDemote}
                {demoteEven &&
                  " — even; select one more (or fewer) to make it odd"}
              </p>
            )}
            {demote.error && (
              <p className="text-xs text-rose-500">
                {formatApiError(demote.error)}
              </p>
            )}
            <button
              type="button"
              className="rounded-md border px-3 py-1.5 text-sm disabled:opacity-50"
              disabled={demoteSel.size === 0 || demoteEven || demote.isPending}
              onClick={() => demote.mutate()}
            >
              {demote.isPending
                ? "Demoting…"
                : `Demote ${demoteSel.size || ""}`}
            </button>
          </section>
        </div>
      </Modal>
    </>
  );
}

// #272 — localStorage key for the dismissable "set up a VIP" advisory
// shown on the Control plane section once a multi-node cluster exists.
const VIP_ADVISORY_DISMISS_KEY = "spatium.fleet.vipAdvisoryDismissed";

export function FleetTab({
  onNavigateTab,
  isApplianceHost = false,
  initialSection = null,
  onSectionApplied,
}: {
  // #272 Phase 6 — lets the cert card jump to the "Web UI Certificate"
  // tab. Optional so the component still renders standalone.
  onNavigateTab?: (tab: string) => void;
  // Only appliance hosts have a local Web UI cert to manage; docker/k8s
  // control planes hide the cert tab, so we hide the card there too.
  isApplianceHost?: boolean;
  // #404 — a legacy ?tab=tls / ?tab=releases deep-link (or the drilldown's
  // onNavigateTab) resolves to a Fleet sidebar section; AppliancePage hands
  // it down here so we select it on arrival, then clears it via
  // onSectionApplied so re-navigating to the same section fires again.
  initialSection?: string | null;
  onSectionApplied?: () => void;
}) {
  const qc = useQueryClient();
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: authApi.me,
    staleTime: 60_000,
  });
  const isSuperadmin = me?.is_superadmin ?? false;

  const { data, isLoading, isFetching, refetch, error } = useQuery({
    queryKey: ["appliance", "fleet"],
    queryFn: applianceApprovalApi.listFleet,
    select: selectApplianceRows,
    refetchInterval: (query) => {
      // `query.state.data` is the RAW response, before `select` — so the
      // rows live under `.appliances` here even though every consumer of
      // `data` below sees the array.
      const rows = query.state.data?.appliances ?? [];
      // #410 — also fast-poll while any appliance has an upgrade or
      // reboot in flight, so the drilldown's UpgradeStatusPanel shows
      // download progress within ~2 s instead of the 15 s idle cadence.
      // A terminal ``failed`` upgrade is excluded from the desired-version
      // arm so a stale failure doesn't pin every superadmin's browser at
      // 2 s until it's cleared (it still fast-polls while actually
      // in-flight, and a reboot is caught by reboot_requested).
      const busy = rows.some(
        (r) =>
          r.state === "pending_approval" ||
          (r.desired_appliance_version !== null &&
            r.last_upgrade_state !== "failed") ||
          r.last_upgrade_state === "in-flight" ||
          r.reboot_requested === true,
      );
      return busy ? 2_000 : 15_000;
    },
    enabled: isSuperadmin,
  });

  // #272 — the no-VIP advisory. Only meaningful on an appliance-hosted
  // control plane (MetalLB is a baked-in appliance subsystem; docker/k8s
  // control planes manage their own ingress/LB). We read the current
  // MetalLB config to decide whether a VIP is set.
  const { data: metallb } = useQuery({
    queryKey: ["appliance", "metallb"],
    queryFn: applianceApprovalApi.getMetalLBConfig,
    enabled: isSuperadmin && isApplianceHost,
    staleTime: 30_000,
  });

  // #170 follow-up — left-sidebar nav mirroring SettingsPage's
  // shape. Sections: the appliance fleet table, pairing-code
  // management, air-gap slot-image uploads, plus NTP + SNMP
  // (fleet-wide platform_settings the supervisor pushes to every
  // appliance host via the ConfigBundle long-poll). ``useSessionState``
  // persists the operator's pick so a refresh inside the same tab
  // lands them back on the same section.
  const [view, setView] = useSessionState<
    | "appliances"
    | "pairing"
    | "cluster-upgrade"
    | "upgrade-images"
    | "web-ui-certificate"
    | "apt"
    | "lldp"
    | "ntp"
    | "resolver"
    | "snmp"
    | "ssh"
    | "syslog"
  >("appliance.fleet.section", "appliances");

  // #404 — apply a deep-linked sidebar section handed down from AppliancePage
  // (legacy ?tab=tls / ?tab=releases / drilldown onNavigateTab). Runs whenever
  // the prop changes to a non-null value; a later manual click won't re-fire it.
  useEffect(() => {
    if (initialSection) {
      setView(initialSection as typeof view);
      onSectionApplied?.();
    }
    // Gate purely on the prop; setView/onSectionApplied identities are stable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialSection]);

  const [drilldown, setDrilldown] = useState<ApplianceRow | null>(null);
  const [showCluster, setShowCluster] = useState(false);
  // #590 — the row whose wedged cluster transition we're about to clear.
  const [clearStateTarget, setClearStateTarget] = useState<ApplianceRow | null>(
    null,
  );
  const [rejectTarget, setRejectTarget] = useState<ApplianceRow | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ApplianceRow | null>(null);
  const [rekeyTarget, setRekeyTarget] = useState<ApplianceRow | null>(null);
  // #272 Phase 9 — dead-node replacement. ``replaceTarget`` is the
  // member to evict (confirm modal); ``replaceResult`` holds the minted
  // pairing code shown once the eviction is stamped.
  const [replaceTarget, setReplaceTarget] = useState<ApplianceRow | null>(null);
  const [replaceResult, setReplaceResult] =
    useState<ControlPlaneReplaceResult | null>(null);
  // #272 — no-VIP advisory dismissal. Persisted in localStorage (not
  // session) so it stays dismissed across browser restarts; the
  // checkbox gate makes dismissal deliberate rather than a stray click.
  const [vipAdvisoryDismissed, setVipAdvisoryDismissed] = useState<boolean>(
    () => localStorage.getItem(VIP_ADVISORY_DISMISS_KEY) === "1",
  );
  const [vipDismissAck, setVipDismissAck] = useState(false);

  const approve = useMutation({
    mutationFn: (id: string) => applianceApprovalApi.approve(id),
    onSuccess: (row) => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      // Refresh the open drilldown with the updated row so the
      // operator sees ``approved`` state + cert serial + role
      // assignment section immediately, instead of staring at a
      // still-pending modal with no feedback.
      if (drilldown && drilldown.id === row.id) setDrilldown(row);
    },
  });
  const reject = useMutation({
    mutationFn: (id: string) => applianceApprovalApi.reject(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setRejectTarget(null);
    },
  });
  const replace = useMutation({
    mutationFn: (id: string) =>
      applianceApprovalApi.replaceControlPlaneMember(id),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setReplaceTarget(null);
      setReplaceResult(result);
    },
  });
  // #590 — clear a promote / demote / eviction that will never converge.
  const clearClusterState = useMutation({
    mutationFn: (id: string) => applianceApprovalApi.clearControlPlaneState(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setClearStateTarget(null);
    },
  });
  // #170 follow-up — password re-auth required for delete (the
  // destructive action that removes a fleet row + breaks the
  // supervisor's mTLS chain to the control plane). The mutation
  // takes a {id, password} pair; the ConfirmModal's password input
  // surfaces the server's 403 response inline so a typo doesn't
  // bounce the operator out of the modal.
  const [deletePwError, setDeletePwError] = useState<string | null>(null);
  // Issue #197 — preview the dns_server + dhcp_server rows that the
  // revoke flow will sweep alongside the appliance. The query is
  // ``enabled`` only when ``deleteTarget`` is set so we don't hit
  // the endpoint on every row hover. Stays stale-while-revalidate
  // until the modal closes — operator's choice doesn't change once
  // they've opened the modal.
  const dependentsQuery = useQuery({
    queryKey: ["appliance", "dependents", deleteTarget?.id ?? null],
    queryFn: () =>
      deleteTarget
        ? applianceApprovalApi.dependents(deleteTarget.id)
        : Promise.resolve({ dns: [], dhcp: [] }),
    enabled: !!deleteTarget,
    staleTime: 30_000,
  });
  const remove = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      applianceApprovalApi.remove(id, password),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setDeleteTarget(null);
      setDrilldown(null);
      setDeletePwError(null);
    },
    onError: (err: unknown) => {
      // FastAPI 403 lands in axios as ``{response: {status, data:
      // {detail}}}``. Surface the detail inline; fall back to a
      // generic message otherwise.
      const e = err as {
        response?: { status?: number; data?: { detail?: string } };
      };
      if (e?.response?.status === 403) {
        setDeletePwError(
          e.response.data?.detail || "Current password incorrect.",
        );
      } else {
        setDeletePwError("Delete failed. Try again.");
      }
    },
  });
  const rekey = useMutation({
    mutationFn: (id: string) => applianceApprovalApi.rekey(id),
    onSuccess: (row) => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setRekeyTarget(null);
      // Refresh the drilldown view if it's open on this row so the
      // operator sees the new serial + expiry immediately.
      if (drilldown && drilldown.id === row.id) setDrilldown(row);
    },
  });
  // Issue #170 Wave E follow-up — re-authorize a revoked appliance.
  // No password gate (low-risk: just flipping back to approved); the
  // supervisor's three-strike detector self-clears on the next 200.
  // The operator may still need to re-fire role assignment to bring
  // services back up since the revoke teardown ran a ``compose stop``.
  const reauthorize = useMutation({
    mutationFn: (id: string) => applianceApprovalApi.reauthorize(id),
    onSuccess: (row) => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      if (drilldown && drilldown.id === row.id) setDrilldown(row);
    },
  });
  const [permanentDeleteTarget, setPermanentDeleteTarget] =
    useState<ApplianceRow | null>(null);
  const [permanentDeletePwError, setPermanentDeletePwError] = useState<
    string | null
  >(null);
  const permanentDelete = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      applianceApprovalApi.permanentDelete(id, password),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setPermanentDeleteTarget(null);
      setDrilldown(null);
      setPermanentDeletePwError(null);
    },
    onError: (err: unknown) => {
      const e = err as {
        response?: { status?: number; data?: { detail?: string } };
      };
      if (e?.response?.status === 403) {
        setPermanentDeletePwError(
          e.response.data?.detail || "Current password incorrect.",
        );
      } else {
        setPermanentDeletePwError("Permanent delete failed. Try again.");
      }
    },
  });

  const rows = useMemo(() => data ?? [], [data]);
  // #272 Phase 1 — split rows by Fleet section (Control plane vs
  // Service agents) first, then by state (pending sticks at the top
  // of its section). Single-node installs see only one populated
  // section; multi-node HA (Phase 7+) populates both.
  const controlPlaneRows = rows.filter(isControlPlaneRow);
  const serviceAgentRows = rows.filter((r) => !isControlPlaneRow(r));
  const byHostname = (a: ApplianceRow, b: ApplianceRow) =>
    (a.hostname ?? "").localeCompare(b.hostname ?? "", undefined, {
      numeric: true,
    });
  const splitByState = (
    bucket: ApplianceRow[],
  ): { pending: ApplianceRow[]; others: ApplianceRow[] } => ({
    pending: bucket
      .filter((r) => r.state === "pending_approval")
      .sort(byHostname),
    others: bucket
      .filter((r) => r.state !== "pending_approval")
      .sort(byHostname),
  });
  const controlPlane = splitByState(controlPlaneRows);
  const serviceAgents = splitByState(serviceAgentRows);

  // #272 — show the "set up a VIP" advisory once a multi-node control
  // plane exists but no MetalLB VIP is configured. A cluster with >1
  // approved control-plane node and no floating VIP is a latent SPOF:
  // every off-cluster agent + operator browser is pinned to whichever
  // node IP they happened to type, so losing that node strands them
  // even though the cluster itself is healthy.
  const approvedControlPlaneCount = controlPlaneRows.filter(
    (r) => r.state !== "pending_approval",
  ).length;
  const vipConfigured = !!(metallb?.enabled && metallb.control_plane_vip);
  const showVipAdvisory =
    isApplianceHost &&
    approvedControlPlaneCount > 1 &&
    !vipConfigured &&
    !vipAdvisoryDismissed;

  if (!isSuperadmin) {
    return (
      <div className="mx-auto max-w-4xl">
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-4 text-sm">
          <div className="flex items-start gap-2">
            <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-400" />
            <div>
              <p className="font-medium text-amber-700 dark:text-amber-400">
                Superadmin only
              </p>
              <p className="mt-1 text-muted-foreground">
                Approving an appliance signs an X.509 cert against the
                supervisor's submitted Ed25519 pubkey. Only superadmin accounts
                can approve / reject / re-key. Ask your platform admin if a
                fleet appliance is waiting on approval.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Two sections — Infrastructure (appliance lifecycle: approve / pair /
  // upgrade) and Services (fleet-wide host-OS subsystems that ride the
  // supervisor's ConfigBundle long-poll). Items inside a section stay
  // alphabetical; sections are deliberately ordered (Infrastructure
  // first because it's the more frequently-used). Future Wave-E
  // host-OS surfaces (#155-#166 — APT proxy, syslog forwarder, SSH
  // authorized_keys, etc.) drop into Services without restructuring.
  type NavItem = {
    key:
      | "appliances"
      | "pairing"
      | "cluster-upgrade"
      | "upgrade-images"
      | "web-ui-certificate"
      | "apt"
      | "lldp"
      | "ntp"
      | "resolver"
      | "snmp"
      | "ssh"
      | "syslog";
    label: string;
    summary: string;
    badge?: string | number;
  };
  const navGroups: { heading: string; items: NavItem[] }[] = [
    {
      heading: "Infrastructure",
      items: [
        {
          key: "appliances",
          label: "Appliances",
          summary: "Approve / manage paired supervisors.",
          badge:
            controlPlane.pending.length + serviceAgents.pending.length > 0
              ? controlPlane.pending.length + serviceAgents.pending.length
              : undefined,
        },
        {
          key: "pairing",
          label: "Pairing codes",
          summary: "Mint codes for new appliances.",
        },
        // #404 — Rolling Upgrade (releases catalog + multi-node A/B
        // orchestrator) moved here from a top-level tab. Always shown: the
        // releases catalog is universal; the orchestrator self-gates to
        // appliance hosts inside the section.
        {
          key: "cluster-upgrade",
          label: "Rolling Upgrade",
          summary: "Releases + multi-node A/B slot upgrade.",
        },
        {
          key: "upgrade-images",
          label: "Upgrade images",
          summary: "GitHub import or air-gap .raw.xz upload.",
        },
        // #404 — Web UI Certificate moved here from a top-level tab.
        // Appliance-host only (a docker/k8s control plane has no local cert
        // to manage).
        ...(isApplianceHost
          ? [
              {
                key: "web-ui-certificate" as const,
                label: "Web UI Certificate",
                summary: "TLS upload / CSR / Let's Encrypt.",
              },
            ]
          : []),
      ],
    },
    {
      heading: "Services",
      // Keep these alphabetical by label so new host-config services slot
      // in by position rather than append-order.
      items: [
        {
          key: "apt",
          label: "APT",
          summary: "Fleet-wide apt sources / proxy / GPG keys.",
        },
        {
          key: "resolver",
          label: "DNS Resolver",
          summary: "Fleet-wide systemd-resolved config.",
        },
        {
          key: "lldp",
          label: "LLDP",
          summary: "Fleet-wide lldpd config.",
        },
        {
          key: "ntp",
          label: "NTP",
          summary: "Fleet-wide chrony config.",
        },
        {
          key: "snmp",
          label: "SNMP",
          summary: "Fleet-wide snmpd config.",
        },
        {
          key: "ssh",
          label: "SSH",
          summary: "Fleet-wide authorized keys + sshd.",
        },
        {
          key: "syslog",
          label: "Syslog",
          summary: "Fleet-wide log forwarding.",
        },
      ],
    },
  ];

  return (
    <div className="-m-6 flex h-[calc(100%+3rem)] overflow-hidden">
      {/* ── Sidebar ── */}
      <aside className="w-56 flex-shrink-0 overflow-y-auto border-r bg-card">
        <div className="border-b px-4 py-3">
          <h1 className="text-sm font-semibold">Appliance fleet</h1>
          <p className="text-xs text-muted-foreground">
            Lifecycle for Appliance nodes.
          </p>
        </div>
        <nav className="p-2">
          {navGroups.map((group, gi) => (
            <div key={group.heading} className={cn(gi > 0 && "mt-3")}>
              <div className="px-3 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
                {group.heading}
              </div>
              {group.items.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setView(item.key)}
                  className={cn(
                    "block w-full rounded-md px-3 py-2 text-left text-sm hover:bg-accent",
                    view === item.key && "bg-accent font-medium",
                  )}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span>{item.label}</span>
                    {item.badge !== undefined && (
                      <span className="rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-300">
                        {item.badge}
                      </span>
                    )}
                  </span>
                  <span className="mt-0.5 block text-[11px] text-muted-foreground">
                    {item.summary}
                  </span>
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      {/* ── Main pane ── */}
      <main className="flex-1 overflow-y-auto">
        {/* The appliances list is a wide multi-column table — let it use
            the full pane width (like the IPAM table) instead of the
            max-w-5xl cap the narrower config forms (pairing / upgrade-images
            / NTP / SNMP) read better at. */}
        <div
          className={cn(
            "mx-auto p-6",
            view === "appliances" ? "max-w-none" : "max-w-5xl",
          )}
        >
          {view === "pairing" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">Pairing codes</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Mint 8-digit codes that a new supervisor appliance swaps for a
                pending-approval registration on{" "}
                <code>/api/v1/appliance/supervisor/register</code>. Ephemeral
                codes are single-use with a short expiry; persistent codes admit
                many appliances and can be re-revealed.
              </p>
              <PairingTab />
            </div>
          )}

          {view === "upgrade-images" && (
            <div>
              <div className="mb-1 flex items-center justify-between gap-2">
                <h2 className="text-base font-semibold">Upgrade images</h2>
                <button
                  type="button"
                  onClick={() =>
                    qc.invalidateQueries({
                      queryKey: ["appliance", "upgrade-images"],
                    })
                  }
                  title="Refresh the upgrade images list"
                  className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-xs hover:bg-muted"
                >
                  <RefreshCw className="h-3 w-3" />
                  Refresh
                </button>
              </div>
              <p className="mb-4 text-xs text-muted-foreground">
                Stage an appliance OS upgrade image. Connected installs can
                import directly from a GitHub release; air-gapped installs
                upload the <code>.raw.xz</code> out-of-band. Either way the
                supervisor downloads through the control plane via an
                authenticated internal URL once an OS upgrade points at the
                stored row.
              </p>
              <UpgradeImageManager />
            </div>
          )}

          {/* #404 — Rolling Upgrade orchestrator (appliance hosts) + the
              releases catalog (universal), merged from two old top-level tabs. */}
          {view === "cluster-upgrade" && (
            <div className="space-y-6">
              {isApplianceHost && <ClusterUpgradeTab />}
              <ReleasesTab applianceMode={isApplianceHost} />
            </div>
          )}

          {/* #404 — Web UI Certificate, moved from a top-level tab. */}
          {view === "web-ui-certificate" && isApplianceHost && (
            <CertificatesTab />
          )}

          {view === "lldp" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">LLDP (lldpd)</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Fleet-wide lldpd configuration. The rendered config ships
                through the ConfigBundle long-poll to every appliance host
                (local + every registered supervisor). LLDP is raw Layer-2 — no
                firewall port is opened.
              </p>
              <LLDPTab />
            </div>
          )}

          {view === "apt" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">APT sources</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Fleet-wide APT configuration — managed repositories, proxy, GPG
                signing keys, and private-mirror credentials for air-gapped /
                proxied / internal-mirror sites. The rendered artifacts ship
                through the ConfigBundle long-poll; the appliance host validates
                against a staged config (real <code>apt-get update</code>)
                before swapping the live files. Opt-in — off by default, leaving
                Debian's baked sources untouched.
              </p>
              <AptTab />
            </div>
          )}

          {view === "ntp" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">NTP (chrony)</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Fleet-wide chrony configuration. The rendered{" "}
                <code>chrony.conf</code> ships through the ConfigBundle
                long-poll to every appliance host (local + every registered
                supervisor), validated host-side before activation. Reloaded
                without a daemon restart.
              </p>
              <NTPTab />
            </div>
          )}

          {view === "snmp" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">SNMP (snmpd)</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Fleet-wide snmpd configuration — v2c with community +
                source-CIDR allowlist, or v3 USM with per-user auth/priv. The
                rendered <code>snmpd.conf</code> ships through the ConfigBundle
                long-poll to every appliance host. Disabled by default —
                operators opt in here.
              </p>
              <SNMPTab />
            </div>
          )}

          {view === "resolver" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">
                DNS resolver (systemd-resolved)
              </h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Fleet-wide systemd-resolved configuration. In{" "}
                <strong>override</strong> mode the rendered{" "}
                <code>resolved.conf.d/spatiumddi.conf</code> drop-in pins the
                global upstream DNS servers (with a route-only <code>~.</code>{" "}
                default domain so they win over per-link DHCP / NetworkManager
                resolvers); reverting to <strong>automatic</strong> removes the
                drop-in. The config ships through the ConfigBundle long-poll to
                every appliance host. The drop-in never touches the stub
                listener — BIND9 binds host <code>:53</code>.
              </p>
              <ResolverTab />
            </div>
          )}

          {view === "ssh" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">SSH access</h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Fleet-wide SSH — manage the <code>admin</code> user's authorized
                keys + sshd hardening (password auth, root login, port) across
                every appliance host. The rendered <code>authorized_keys</code>{" "}
                + <code>sshd_config.d/spatiumddi.conf</code> ship through the
                ConfigBundle long-poll, validated host-side via{" "}
                <code>sshd -t</code> before activation. Port 22 stays open in
                the host firewall as an escape hatch, until the source
                restriction below is enabled — that retires the floor and scopes
                SSH to the allowed networks.
              </p>
              <SSHTab />
            </div>
          )}

          {view === "syslog" && (
            <div>
              <h2 className="mb-1 text-base font-semibold">
                Syslog forwarding (rsyslog)
              </h2>
              <p className="mb-4 text-xs text-muted-foreground">
                Fleet-wide rsyslog forwarding — ship journald + file log sources
                off-box to a SIEM / collector over UDP / TCP / TLS. The rendered{" "}
                <code>50-spatium-forward.conf</code> ships through the
                ConfigBundle long-poll to every appliance host, validated
                host-side before activation. Disabled by default; forwarding is
                outbound only (no inbound port opened).
              </p>
              <SyslogTab />
            </div>
          )}

          {view === "appliances" && (
            <>
              <div className="mb-4 flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <h2 className="text-base font-semibold">Appliances</h2>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Supervisors that claimed a pairing code sit here until a
                    superadmin clicks Approve. Approval signs an X.509 cert
                    against the submitted Ed25519 pubkey using the control
                    plane&apos;s internal CA (lazy-bootstrapped on the first
                    approve). The supervisor picks the cert up on its next poll
                    and switches from session-token auth to mTLS. Rows split by
                    installer variant: <strong>Control plane</strong> hosts the
                    SpatiumDDI control-plane workloads (api / frontend / worker
                    / postgres / redis); <strong>Service agents</strong> are
                    Appliance appliances running DNS / DHCP service containers
                    paired to a remote control plane.
                  </p>
                </div>
                <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowCluster(true)}
                    className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted"
                    title="Promote appliances into the control-plane cluster, or demote members"
                  >
                    Manage control plane cluster…
                  </button>
                  {isApplianceHost && (
                    <button
                      type="button"
                      onClick={() => onNavigateTab?.("tls")}
                      className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted"
                      title="Upload a Web UI certificate, generate a CSR, or activate a cert"
                    >
                      Manage certificates…
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => refetch()}
                    disabled={isFetching}
                    className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
                  >
                    <RefreshCw
                      className={cn(
                        "h-3.5 w-3.5",
                        isFetching && "animate-spin",
                      )}
                    />
                    Refresh
                  </button>
                </div>
              </div>

              {/* No `enabled` gate: FleetTab early-returns for a
                  non-superadmin, and `enabled: false` would not gate the
                  banner anyway — a sibling observer on this key fills the
                  cache, and `enabled` only suppresses fetching. */}
              <MtuFleetAdvisory />

              {showVipAdvisory && (
                <div className="mb-4 rounded-md border border-amber-500/50 bg-amber-500/10 p-4">
                  <div className="flex items-start gap-3">
                    <AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-700 dark:text-amber-400" />
                    <div className="min-w-0 flex-1">
                      <p className="font-semibold text-amber-700 dark:text-amber-400">
                        Set up a control-plane VIP
                      </p>
                      <p className="mt-1 text-sm text-muted-foreground">
                        This control plane has{" "}
                        <strong>{approvedControlPlaneCount} nodes</strong> but
                        no MetalLB virtual IP (VIP) is configured. Without a
                        VIP, operator browsers and every off-cluster DNS / DHCP
                        agent are pinned to a single node&apos;s address — if
                        that node goes down they lose the control plane even
                        though the cluster is still healthy on the surviving
                        nodes. Set a floating VIP so there&apos;s one stable
                        address that re-homes automatically on node loss.
                      </p>
                      <div className="mt-3 flex flex-wrap items-center gap-3">
                        <button
                          type="button"
                          onClick={() => onNavigateTab?.("network")}
                          className="inline-flex items-center gap-1.5 rounded-md bg-amber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-amber-700"
                        >
                          <Network className="h-3.5 w-3.5" />
                          Set up a VIP
                        </button>
                        <label className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                          <input
                            type="checkbox"
                            checked={vipDismissAck}
                            onChange={(e) => setVipDismissAck(e.target.checked)}
                            className="h-3.5 w-3.5 rounded border-input"
                          />
                          I understand the risk and want to dismiss this
                        </label>
                        <button
                          type="button"
                          disabled={!vipDismissAck}
                          onClick={() => {
                            localStorage.setItem(VIP_ADVISORY_DISMISS_KEY, "1");
                            setVipAdvisoryDismissed(true);
                          }}
                          className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          Dismiss
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {error ? (
                <div className="rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">
                  Failed to load appliances: {formatApiError(error)}
                </div>
              ) : isLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading
                  appliances…
                </div>
              ) : rows.length === 0 ? (
                <div className="rounded-md border border-dashed bg-card p-8 text-center text-sm text-muted-foreground">
                  No appliances have paired yet. Open the{" "}
                  <button
                    type="button"
                    onClick={() => setView("pairing")}
                    className="underline decoration-dotted underline-offset-2 hover:text-foreground"
                  >
                    Pairing codes
                  </button>{" "}
                  section to mint one, then install an Appliance node against it
                  — the row appears here once the supervisor claims the code.
                </div>
              ) : (
                <div className="space-y-6">
                  <ApplianceTableSection
                    title="Control plane"
                    subtitle="Boxes hosting the SpatiumDDI control plane — the control-plane node plus any promoted appliances."
                    pendingRows={controlPlane.pending}
                    otherRows={controlPlane.others}
                    emptyMessage="No control-plane appliances registered yet."
                    busyId={
                      approve.isPending
                        ? approve.variables
                        : rekey.isPending
                          ? rekey.variables
                          : null
                    }
                    onOpen={(row) => setDrilldown(row)}
                    onApprove={(row) => approve.mutate(row.id)}
                    onReject={(row) => setRejectTarget(row)}
                    onRekey={(row) => setRekeyTarget(row)}
                    onDelete={(row) => setDeleteTarget(row)}
                    onReauthorize={(row) => reauthorize.mutate(row.id)}
                    onPermanentDelete={(row) => setPermanentDeleteTarget(row)}
                    onReplace={(row) => setReplaceTarget(row)}
                    onClearClusterState={(row) => setClearStateTarget(row)}
                  />
                  {/* #402 — the etcd snapshot list + guided restore moved
                    to the Cluster tab (it crowded the fleet roster here). */}
                  <ApplianceTableSection
                    title="Service agents"
                    subtitle="Appliance nodes running DNS / DHCP service containers paired to a remote control plane."
                    pendingRows={serviceAgents.pending}
                    otherRows={serviceAgents.others}
                    emptyMessage="No service-agent appliances registered yet."
                    busyId={
                      approve.isPending
                        ? approve.variables
                        : rekey.isPending
                          ? rekey.variables
                          : null
                    }
                    onOpen={(row) => setDrilldown(row)}
                    onApprove={(row) => approve.mutate(row.id)}
                    onReject={(row) => setRejectTarget(row)}
                    onRekey={(row) => setRekeyTarget(row)}
                    onDelete={(row) => setDeleteTarget(row)}
                    onReauthorize={(row) => reauthorize.mutate(row.id)}
                    onPermanentDelete={(row) => setPermanentDeleteTarget(row)}
                  />
                </div>
              )}
            </>
          )}
        </div>
      </main>

      {showCluster && (
        <ClusterMembershipModal
          rows={rows}
          onClose={() => setShowCluster(false)}
        />
      )}

      {drilldown && (
        <ApplianceDrilldownModal
          // #410 — render the freshly-polled row (matched by id) rather
          // than the frozen open-time snapshot, so live upgrade progress
          // shipped via the supervisor heartbeat updates the drilldown
          // without a hard page reload. Falls back to the snapshot if the
          // row briefly drops out of the list (e.g. mid-refetch).
          row={data?.find((r) => r.id === drilldown.id) ?? drilldown}
          onClose={() => setDrilldown(null)}
          onApprove={() => approve.mutate(drilldown.id)}
          approving={approve.isPending}
          onReject={() => setRejectTarget(drilldown)}
          onRekey={() => setRekeyTarget(drilldown)}
          onDelete={() => setDeleteTarget(drilldown)}
          onRowUpdated={(next) => setDrilldown(next)}
          onViewUpgradeImages={() => {
            setDrilldown(null);
            setView("upgrade-images");
          }}
        />
      )}

      {rejectTarget && (
        <ConfirmModal
          open
          title="Reject appliance?"
          message={
            <>
              <p className="text-sm">
                Reject <strong>{rejectTarget.hostname}</strong>? The row is
                deleted; the supervisor's next poll returns 403 and it falls
                back to bootstrapping. To re-pair, mint a fresh pairing code and
                re-install or re-trigger the supervisor.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Fingerprint:{" "}
                <code className="text-foreground">
                  {shortFingerprint(rejectTarget.public_key_fingerprint)}
                </code>
              </p>
            </>
          }
          confirmLabel="Reject"
          tone="destructive"
          loading={reject.isPending}
          onConfirm={() => reject.mutate(rejectTarget.id)}
          onClose={() => setRejectTarget(null)}
        />
      )}

      {deleteTarget && (
        <ConfirmModal
          open
          title="Revoke appliance?"
          message={
            <>
              <p className="text-sm">
                Revoke <strong>{deleteTarget.hostname}</strong>. The row flips
                to{" "}
                <span className="rounded bg-amber-500/15 px-1 font-medium text-amber-700 dark:text-amber-400">
                  revoked
                </span>{" "}
                — heartbeats start returning 403, the supervisor's three-strike
                detector tears down its DNS / DHCP service containers within ~3
                min, and the chip on the appliance console flips to red.
              </p>
              <p className="mt-2 text-sm">
                The row stays for <strong>30 days</strong> by default — long
                enough for an operator to <em>Re-authorize</em> if they revoked
                by mistake. The <em>Delete</em> button appears on revoked rows
                for permanent removal.
              </p>
              {/* Issue #197 — list the dns_server + dhcp_server rows
                  that will be swept alongside the revoke. Operator
                  sees the full blast radius before clicking; if the
                  appliance has zero dependent rows the block stays
                  out so the modal isn't padded for the common case. */}
              {dependentsQuery.data &&
                (dependentsQuery.data.dns.length > 0 ||
                  dependentsQuery.data.dhcp.length > 0) && (
                  <div className="mt-2 rounded-md border bg-muted/30 p-2 text-xs">
                    <p className="font-medium">
                      Will also remove the following server rows:
                    </p>
                    <ul className="mt-1 list-inside list-disc text-muted-foreground">
                      {dependentsQuery.data.dns.map((d) => (
                        <li key={d.id}>
                          <span className="rounded bg-sky-500/15 px-1 font-mono text-[10px] uppercase text-sky-700 dark:text-sky-400">
                            DNS
                          </span>{" "}
                          <span className="text-foreground">{d.name}</span>
                          {d.host !== d.name && <span> ({d.host})</span>} —{" "}
                          {d.status}
                        </li>
                      ))}
                      {dependentsQuery.data.dhcp.map((d) => (
                        <li key={d.id}>
                          <span className="rounded bg-emerald-500/15 px-1 font-mono text-[10px] uppercase text-emerald-700 dark:text-emerald-400">
                            DHCP
                          </span>{" "}
                          <span className="text-foreground">{d.name}</span>
                          {d.host !== d.name && <span> ({d.host})</span>} —{" "}
                          {d.status}
                        </li>
                      ))}
                    </ul>
                    <p className="mt-2 text-[11px] text-muted-foreground">
                      Re-authorize re-creates these on the supervisor's next
                      heartbeat — data on the appliance itself isn't lost.
                    </p>
                  </div>
                )}
              <p className="mt-2 text-xs text-muted-foreground">
                Cert serial:{" "}
                <code className="text-foreground">
                  {deleteTarget.cert_serial ?? "—"}
                </code>
              </p>
            </>
          }
          confirmLabel="Revoke"
          tone="destructive"
          loading={remove.isPending}
          requireCheckboxLabel={`I understand ${deleteTarget.hostname} will stop heartbeating successfully and its service containers will tear down within ~3 minutes.`}
          requirePassword
          passwordError={deletePwError}
          onConfirm={(password) =>
            remove.mutate({ id: deleteTarget.id, password: password ?? "" })
          }
          onClose={() => {
            setDeleteTarget(null);
            setDeletePwError(null);
          }}
        />
      )}

      {permanentDeleteTarget && (
        <ConfirmModal
          open
          title="Delete appliance?"
          message={
            <>
              <p className="text-sm">
                Hard DELETE the{" "}
                <strong>{permanentDeleteTarget.hostname}</strong> row from the
                database. <strong>This cannot be undone.</strong> The
                supervisor's mTLS calls will fail; the supervisor's cached
                identity will be orphaned until the operator re-pairs against a
                fresh pairing code.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Cert serial:{" "}
                <code className="text-foreground">
                  {permanentDeleteTarget.cert_serial ?? "—"}
                </code>
              </p>
            </>
          }
          confirmLabel="Delete"
          tone="destructive"
          loading={permanentDelete.isPending}
          requireCheckboxLabel={`I understand this permanently removes ${permanentDeleteTarget.hostname} and cannot be reversed.`}
          requirePassword
          passwordError={permanentDeletePwError}
          onConfirm={(password) =>
            permanentDelete.mutate({
              id: permanentDeleteTarget.id,
              password: password ?? "",
            })
          }
          onClose={() => {
            setPermanentDeleteTarget(null);
            setPermanentDeletePwError(null);
          }}
        />
      )}

      {rekeyTarget && (
        <ConfirmModal
          open
          title="Re-key appliance?"
          message={
            <>
              <p className="text-sm">
                Issue a fresh cert against the supervisor's existing pubkey on{" "}
                <strong>{rekeyTarget.hostname}</strong>. The current cert
                remains technically valid in the CA's eye until it expires (CRL
                work lands in a later wave); the supervisor picks up the new
                cert on its next poll.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Use this for the routine 60-day renewal or after suspected
                compromise.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Current serial:{" "}
                <code className="text-foreground">
                  {rekeyTarget.cert_serial ?? "—"}
                </code>
              </p>
            </>
          }
          confirmLabel="Re-key"
          loading={rekey.isPending}
          onConfirm={() => rekey.mutate(rekeyTarget.id)}
          onClose={() => setRekeyTarget(null)}
        />
      )}

      {/* #272 Phase 9 — confirm dead-node eviction. */}
      {replaceTarget && (
        <ConfirmModal
          open
          title="Replace dead control-plane member?"
          message={
            <>
              <p className="text-sm">
                Evict <strong>{replaceTarget.hostname}</strong> from the
                control-plane cluster. The seed deletes its k8s Node (k3s drops
                the etcd member with it) and the cluster drops to{" "}
                {"the remaining members"}. A single-use pairing code is minted
                so a fresh appliance can take its place — pair it, approve it,
                and promote it back into the cluster.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Use this only when the node is gone for good. For a node that's
                still alive, demote it gracefully via "Manage control plane
                cluster…" instead.
              </p>
              {replace.isError && (
                <p className="mt-2 text-xs text-rose-600">
                  {formatApiError(replace.error)}
                </p>
              )}
            </>
          }
          confirmLabel="Evict + mint replacement code"
          loading={replace.isPending}
          onConfirm={() => replace.mutate(replaceTarget.id)}
          onClose={() => setReplaceTarget(null)}
        />
      )}

      {/* #590 — confirm clearing a wedged cluster transition. */}
      {clearStateTarget && (
        <ConfirmModal
          open
          title="Clear stuck cluster state?"
          message={
            <>
              <p className="text-sm">
                <strong>{clearStateTarget.hostname}</strong> is stuck in{" "}
                <code className="rounded bg-muted px-1 py-0.5 text-xs">
                  {clearStateTarget.cluster_join_state ??
                    clearStateTarget.desired_cluster_role}
                </code>
                {clearStateTarget.cluster_join_state_at && (
                  <>
                    {" since "}
                    {new Date(
                      clearStateTarget.cluster_join_state_at,
                    ).toLocaleString()}
                  </>
                )}
                . Clearing drops the desired-state, the in-flight join
                coordinates, and the eviction flag so the row stops waiting for
                a report that isn't coming.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Bookkeeping only — the node, k3s and etcd are untouched, and the
                appliance keeps whatever cluster role it already had. Re-drive
                the promote / demote / replace afterwards, or revoke the
                appliance if the node is gone for good.
              </p>
              {clearClusterState.isError && (
                <p className="mt-2 text-xs text-rose-600">
                  {formatApiError(clearClusterState.error)}
                </p>
              )}
            </>
          }
          confirmLabel="Clear stuck state"
          loading={clearClusterState.isPending}
          onConfirm={() => clearClusterState.mutate(clearStateTarget.id)}
          onClose={() => setClearStateTarget(null)}
        />
      )}

      {/* #272 Phase 9 — show the minted replacement pairing code once. */}
      {replaceResult && (
        <Modal
          title="Replacement pairing code"
          onClose={() => setReplaceResult(null)}
        >
          <div className="space-y-3 text-sm">
            <p>
              <strong>{replaceResult.evicted.hostname}</strong> has been
              evicted. Install a fresh appliance (Appliance role) and pair it
              with this single-use code, then approve + promote it to restore
              the cluster:
            </p>
            <div className="flex items-center gap-2">
              <code className="rounded-md bg-muted px-3 py-2 font-mono text-lg tracking-widest">
                {replaceResult.pairing_code}
              </code>
              <button
                type="button"
                onClick={() =>
                  navigator.clipboard?.writeText(replaceResult.pairing_code)
                }
                className="rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted"
              >
                Copy
              </button>
            </div>
            <p className="text-xs text-muted-foreground">
              Expires{" "}
              {new Date(replaceResult.pairing_expires_at).toLocaleString()}.
              Shown once — regenerate from the Pairing tab if you lose it.
            </p>
          </div>
        </Modal>
      )}
    </div>
  );
}

// Compact "what's actually running on this appliance" cell rendered
// in the Appliances list. Empty assigned_roles → ``—``; non-empty
// renders one chip per role with colour driven by the supervisor's
// last ``role_switch_state`` heartbeat.
function ServiceChipList({ row }: { row: ApplianceRow }) {
  const services = serviceChips(row);
  if (services.length === 0) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {services.map((s) => (
        <span
          key={s.key}
          className={cn(
            "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
            SERVICE_CHIP_STYLES[s.status],
          )}
          title={
            s.status === "ready"
              ? `Assigned + healthy (supervisor reports role_switch_state=ready)`
              : s.status === "failed"
                ? `Assigned, supervisor lifecycle apply failed — inspect drilldown`
                : s.status === "pending"
                  ? `Assigned, supervisor hasn't reported ready yet`
                  : `Assigned (no service container — supervisor is the runtime)`
          }
        >
          {s.status === "ready" && <CheckCircle2 className="h-2.5 w-2.5" />}
          {s.status === "failed" && <AlertCircle className="h-2.5 w-2.5" />}
          {s.status === "pending" && <Loader2 className="h-2.5 w-2.5" />}
          {s.label}
        </span>
      ))}
    </div>
  );
}

// Issue #156 — best-effort syslog-forwarding status chip rendered under
// the per-role service chips. Only shown when the supervisor has
// reported a value (``forwarding`` green / ``unreachable`` amber-red /
// ``disabled`` muted); a null status (non-appliance / pre-#156 / never
// reported) renders nothing so the column stays clean.
function SyslogChip({ row }: { row: ApplianceRow }) {
  const status = row.syslog_forwarding;
  if (!status) return null;
  const style =
    status === "forwarding"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
      : status === "unreachable"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
        : "border-muted bg-muted/40 text-muted-foreground";
  const label =
    status === "forwarding"
      ? "Syslog: forwarding"
      : status === "unreachable"
        ? "Syslog: unreachable"
        : "Syslog: off";
  return (
    <span
      className={cn(
        "inline-flex w-fit items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
        style,
      )}
      title={
        status === "forwarding"
          ? "rsyslog is active + the forward config is applied"
          : status === "unreachable"
            ? "Forwarding enabled but the rsyslog unit failed / is inactive"
            : "Syslog forwarding is disabled"
      }
    >
      {label}
    </span>
  );
}

// Issue #157 — per-host applied authorized_keys count chip, rendered under
// the service + syslog chips. Only shown when the supervisor has reported a
// value (null = non-appliance / pre-#157 / never reported → render nothing
// so the column stays clean). Zero keys is a meaningful state (managed-off
// or password-auth-only) so it still renders.
function SshKeyChip({ row }: { row: ApplianceRow }) {
  const count = row.ssh_key_count;
  if (count === null || count === undefined) return null;
  return (
    <span
      className={cn(
        "inline-flex w-fit items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
        count > 0
          ? "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-400"
          : "border-muted bg-muted/40 text-muted-foreground",
      )}
      title={
        count > 0
          ? `${count} SSH authorized key(s) applied on this host`
          : "No managed SSH authorized keys applied on this host"
      }
    >
      SSH: {count} key{count === 1 ? "" : "s"}
    </span>
  );
}

// Issue #158 — best-effort systemd-resolved status chip, rendered under the
// service + syslog + ssh chips. Only shown when the supervisor has reported
// a value (``override`` sky / ``automatic`` muted / ``failed`` red); a null
// status (non-appliance / pre-#158 / never reported) renders nothing so the
// column stays clean.
function ResolverChip({ row }: { row: ApplianceRow }) {
  const status = row.resolver_status;
  if (!status) return null;
  const style =
    status === "override"
      ? "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-400"
      : status === "failed"
        ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400"
        : "border-muted bg-muted/40 text-muted-foreground";
  const label =
    status === "override"
      ? "DNS: override"
      : status === "failed"
        ? "DNS: apply failed"
        : "DNS: automatic";
  return (
    <span
      className={cn(
        "inline-flex w-fit items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
        style,
      )}
      title={
        status === "override"
          ? "systemd-resolved is pinned to the configured global DNS servers"
          : status === "failed"
            ? "The resolver config failed to apply on this host"
            : "systemd-resolved uses per-link DHCP / NetworkManager DNS"
      }
    >
      {label}
    </span>
  );
}

// Issue #155 — best-effort APT host-config status chip, rendered under the
// other host-config chips. Only shown when the supervisor has reported a
// value: ``synced`` green / ``unmanaged`` muted / everything else (proxy-
// failed / mirror-unreachable / signature-mismatch / no-sources) red. A
// null status (non-appliance / pre-#155 / never reported) renders nothing.
function AptChip({ row }: { row: ApplianceRow }) {
  const status = row.apt_state;
  if (!status) return null;
  const style =
    status === "synced"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
      : status === "unmanaged"
        ? "border-muted bg-muted/40 text-muted-foreground"
        : "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-400";
  const label =
    status === "synced"
      ? "APT: synced"
      : status === "unmanaged"
        ? "APT: unmanaged"
        : `APT: ${status}`;
  return (
    <span
      className={cn(
        "inline-flex w-fit items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
        style,
      )}
      title={
        status === "synced"
          ? "Managed apt config applied + apt-get update succeeded on this host"
          : status === "unmanaged"
            ? "SpatiumDDI isn't managing apt — Debian's baked sources are in effect"
            : "The managed apt config failed to validate/apply on this host"
      }
    >
      {label}
    </span>
  );
}

// #272 Phase 1 — Fleet UI two-table split. One section per bucket
// (Control plane / Service agents). Pending rows pin to the top of
// their section, others below. Empty section renders a dashed
// placeholder so the heading still anchors the bucket visually.
function ApplianceTableSection({
  title,
  subtitle,
  pendingRows,
  otherRows,
  emptyMessage,
  busyId,
  onOpen,
  onApprove,
  onReject,
  onRekey,
  onDelete,
  onReauthorize,
  onPermanentDelete,
  onReplace,
  onClearClusterState,
}: {
  title: string;
  subtitle: string;
  pendingRows: ApplianceRow[];
  otherRows: ApplianceRow[];
  emptyMessage: string;
  busyId: string | null | undefined;
  onOpen: (row: ApplianceRow) => void;
  onApprove: (row: ApplianceRow) => void;
  onReject: (row: ApplianceRow) => void;
  onRekey: (row: ApplianceRow) => void;
  onDelete: (row: ApplianceRow) => void;
  onReauthorize: (row: ApplianceRow) => void;
  onPermanentDelete: (row: ApplianceRow) => void;
  // #272 Phase 9 — only the Control plane section passes this (members
  // can be replaced when dead). Undefined elsewhere → no Replace action.
  onReplace?: (row: ApplianceRow) => void;
  onClearClusterState?: (row: ApplianceRow) => void;
}) {
  const total = pendingRows.length + otherRows.length;
  return (
    <section>
      <div className="mb-2 flex items-baseline justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">{title}</h3>
          <p className="text-xs text-muted-foreground">{subtitle}</p>
        </div>
        <span className="shrink-0 rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
          {total}
        </span>
      </div>
      {total === 0 ? (
        <div className="rounded-md border border-dashed bg-card p-4 text-center text-xs text-muted-foreground">
          {emptyMessage}
        </div>
      ) : (
        <div className="overflow-hidden rounded-md border bg-card">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Hostname</th>
                <th className="px-4 py-3 text-left font-medium">State</th>
                <th className="px-4 py-3 text-left font-medium">Services</th>
                <th className="px-4 py-3 text-left font-medium">
                  Capabilities
                </th>
                <th className="px-4 py-3 text-left font-medium">Slots</th>
                <th className="px-4 py-3 text-left font-medium">Fingerprint</th>
                <th className="px-4 py-3 text-left font-medium">Paired</th>
                <th className="px-4 py-3 text-left font-medium">Last seen</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {pendingRows.map((row) => (
                <ApplianceTableRow
                  key={row.id}
                  row={row}
                  highlight
                  busy={busyId === row.id}
                  onOpen={() => onOpen(row)}
                  onApprove={() => onApprove(row)}
                  onReject={() => onReject(row)}
                  onRekey={() => onRekey(row)}
                  onDelete={() => onDelete(row)}
                  onReauthorize={() => onReauthorize(row)}
                  onPermanentDelete={() => onPermanentDelete(row)}
                  canRevoke={!isControlPlaneRow(row)}
                  onReplace={onReplace ? () => onReplace(row) : undefined}
                  onClearClusterState={
                    onClearClusterState
                      ? () => onClearClusterState(row)
                      : undefined
                  }
                />
              ))}
              {otherRows.map((row) => (
                <ApplianceTableRow
                  key={row.id}
                  row={row}
                  busy={busyId === row.id}
                  onOpen={() => onOpen(row)}
                  onApprove={() => onApprove(row)}
                  onReject={() => onReject(row)}
                  onRekey={() => onRekey(row)}
                  onDelete={() => onDelete(row)}
                  onReauthorize={() => onReauthorize(row)}
                  onPermanentDelete={() => onPermanentDelete(row)}
                  canRevoke={!isControlPlaneRow(row)}
                  onReplace={onReplace ? () => onReplace(row) : undefined}
                  onClearClusterState={
                    onClearClusterState
                      ? () => onClearClusterState(row)
                      : undefined
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ApplianceTableRow({
  row,
  highlight,
  busy,
  onOpen,
  onApprove,
  onReject,
  onRekey,
  onDelete,
  onReauthorize,
  onPermanentDelete,
  onReplace,
  onClearClusterState,
  canRevoke = true,
}: {
  row: ApplianceRow;
  highlight?: boolean;
  busy?: boolean;
  onOpen: () => void;
  onApprove: () => void;
  onReject: () => void;
  onRekey: () => void;
  onDelete: () => void;
  onReauthorize: () => void;
  onPermanentDelete: () => void;
  onReplace?: (() => void) | undefined;
  onClearClusterState?: (() => void) | undefined;
  // #272 — false for the sole control-plane node: revoking it would
  // brick the control plane, so we hide the action (the backend also
  // refuses it). True for everything else.
  canRevoke?: boolean;
}) {
  const badge = stateBadge(row.state);
  const Icon = badge.Icon;
  const caps = capabilityChips(row.capabilities);

  return (
    <tr
      className={cn(
        "cursor-pointer hover:bg-muted/30",
        highlight && "bg-amber-500/5",
      )}
      onClick={onOpen}
    >
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="font-medium">{row.hostname}</span>
          {/* #272 — installer-role chip. Two variants: control-plane
              (Control plane table) + appliance (Service agents).
              Legacy strings still render with a sensible label. */}
          {row.appliance_variant && (
            <span
              className={cn(
                "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
                isControlPlaneRow(row)
                  ? "border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-300"
                  : "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-300",
              )}
              title={
                isControlPlaneRow(row)
                  ? "Control plane — api + db + frontend (enable DNS/DHCP via the role toggle)"
                  : "Appliance — DNS / DHCP agent (pairs with a control plane)"
              }
            >
              {row.appliance_variant}
            </span>
          )}
          <ClusterStatusChip row={row} />
        </div>
        {row.supervisor_version && (
          <div className="text-xs text-muted-foreground">
            supervisor {row.supervisor_version}
          </div>
        )}
      </td>
      <td className="px-4 py-3">
        <span
          className={cn(
            "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs",
            badge.className,
          )}
        >
          <Icon className="h-3 w-3" /> {badge.label}
        </span>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-col gap-1">
          <ServiceChipList row={row} />
          <SyslogChip row={row} />
          <SshKeyChip row={row} />
          <ResolverChip row={row} />
          <AptChip row={row} />
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {caps.length === 0 ? (
            <span className="text-xs text-muted-foreground">—</span>
          ) : (
            caps.map((c) => (
              <span
                key={c.key}
                className="rounded-full bg-muted px-2 py-0.5 font-mono text-xs"
              >
                {c.label}
              </span>
            ))
          )}
          {row.capabilities.has_baked_images && (
            <span
              className="rounded-full bg-sky-500/10 px-2 py-0.5 font-mono text-xs text-sky-700 dark:text-sky-300"
              title="Supervisor reports baked container images on the rootfs — air-gap-ready."
            >
              baked
            </span>
          )}
        </div>
      </td>
      <td className="px-4 py-3">
        <ApplianceSlotsCell row={row} />
      </td>
      <td className="px-4 py-3 font-mono text-xs">
        {shortFingerprint(row.public_key_fingerprint)}
      </td>
      <td className="px-4 py-3 text-xs text-muted-foreground">
        {relativeTime(row.paired_at)}
        {row.paired_from_ip && (
          <div className="font-mono">{row.paired_from_ip}</div>
        )}
      </td>
      <td className="px-4 py-3 text-xs text-muted-foreground">
        {relativeTime(row.last_seen_at)}
      </td>
      <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
        <div className="inline-flex items-center gap-1">
          {row.state === "pending_approval" && (
            <>
              <button
                type="button"
                onClick={onApprove}
                disabled={busy}
                className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-50 dark:text-emerald-300"
                title="Approve + sign the supervisor's cert"
              >
                {busy ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-3 w-3" />
                )}
                Approve
              </button>
              <button
                type="button"
                onClick={onReject}
                className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-xs text-rose-700 hover:bg-rose-500/20 dark:text-rose-300"
                title="Reject — deletes the row, supervisor falls back to bootstrapping"
              >
                <XCircle className="h-3 w-3" />
                Reject
              </button>
            </>
          )}
          {row.state === "approved" && (
            <>
              <button
                type="button"
                onClick={onRekey}
                className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-xs hover:bg-muted"
                title="Issue a fresh cert against the same pubkey"
              >
                <KeyRound className="h-3 w-3" />
                Re-key
              </button>
              {/* #272 Phase 9 — replace a DEAD control-plane member:
                  evict its etcd member + mint a replacement pairing code.
                  Only offered for settled members (cluster_role=member). */}
              {onReplace && row.cluster_role === "member" && (
                <button
                  type="button"
                  onClick={onReplace}
                  className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-xs text-rose-700 hover:bg-rose-500/20 dark:text-rose-300"
                  title="Replace a DEAD member — evict its etcd member + mint a pairing code for a replacement box. Use only when the node is gone for good."
                >
                  <RefreshCw className="h-3 w-3" />
                  Replace…
                </button>
              )}
              {/* #590 — escape hatch for a wedged cluster transition. No
                  transition has a timeout (each converges only on a
                  supervisor report), so a node that died mid-join or a seed
                  that can't reach the kubeapi pins the row in
                  joining/leaving/evicting with no way out. Offered only
                  while the row is actually stuck. */}
              {onClearClusterState && isClusterTransitionStuck(row) && (
                <button
                  type="button"
                  onClick={onClearClusterState}
                  className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs text-amber-700 hover:bg-amber-500/20 dark:text-amber-400"
                  title="Clear a stuck promote / demote / eviction. Bookkeeping only — the node, k3s and etcd are untouched."
                >
                  <RefreshCw className="h-3 w-3" />
                  Clear stuck state…
                </button>
              )}
              {/* #272 — a control-plane cluster member can't be revoked
                  until it's demoted (demote via "Manage control plane
                  cluster…"). Revoking a live etcd member would break
                  quorum. Show the button disabled with a hint rather than
                  hiding it, so the path forward is obvious. */}
              <button
                type="button"
                onClick={canRevoke ? onDelete : undefined}
                disabled={!canRevoke}
                className="inline-flex items-center gap-1 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs text-amber-700 hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-40 dark:text-amber-400"
                title={
                  canRevoke
                    ? "Revoke — flip to revoked state, supervisor tears down service containers. Re-authorize on the same row to recover."
                    : "Demote this node from the control-plane cluster first (Manage control plane cluster…) before revoking."
                }
              >
                <Ban className="h-3 w-3" />
                Revoke
              </button>
            </>
          )}
          {row.state === "revoked" && (
            <>
              <button
                type="button"
                onClick={onReauthorize}
                className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-700 hover:bg-emerald-500/20 dark:text-emerald-300"
                title="Re-authorize — flip back to approved; supervisor resumes on next heartbeat"
              >
                <CheckCircle2 className="h-3 w-3" />
                Re-authorize
              </button>
              <button
                type="button"
                onClick={onPermanentDelete}
                className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1 text-xs text-rose-700 hover:bg-rose-500/20 dark:text-rose-300"
                title="Permanently delete this row — cannot be undone"
              >
                <Trash2 className="h-3 w-3" />
                Delete
              </button>
            </>
          )}
        </div>
      </td>
    </tr>
  );
}

function ApplianceDrilldownModal({
  row,
  onClose,
  onApprove,
  approving,
  onReject,
  onRekey,
  onDelete,
  onRowUpdated,
  onViewUpgradeImages,
}: {
  row: ApplianceRow;
  onClose: () => void;
  onApprove: () => void;
  approving: boolean;
  onReject: () => void;
  onRekey: () => void;
  onDelete: () => void;
  onRowUpdated: (next: ApplianceRow) => void;
  // Closes this modal and switches the Fleet sub-nav to the
  // "Upgrade images" view — wired into the OS-upgrade section's
  // empty state so operators aren't told to look for a section
  // that moved (#199 renamed slot-images → Upgrade images).
  onViewUpgradeImages?: () => void;
}) {
  const caps = row.capabilities ?? {};
  const badge = stateBadge(row.state);
  const Icon = badge.Icon;

  return (
    <Modal title={`Appliance · ${row.hostname}`} onClose={onClose} wide>
      <div className="divide-y divide-border text-sm [&>*]:pt-4 [&>*:first-child]:pt-0 [&>*]:pb-4 [&>*:last-child]:pb-0">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs",
              badge.className,
            )}
          >
            <Icon className="h-3 w-3" /> {badge.label}
          </span>
          {row.supervisor_version && (
            <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs">
              supervisor {row.supervisor_version}
            </span>
          )}
          {caps.has_baked_images && (
            <span className="rounded-md bg-sky-500/10 px-1.5 py-0.5 font-mono text-xs text-sky-700 dark:text-sky-300">
              baked images
              {caps.baked_images_version
                ? ` · ${caps.baked_images_version}`
                : ""}
            </span>
          )}
          {row.state === "approved" && (
            // #59 — capture on this appliance's real NICs. Lands on the
            // Packet Capture tool prefilled with this appliance as vantage.
            // (404s gracefully if the tools.pcap module is off.)
            <Link
              to={`/tools/pcap?vantage=appliance&appliance=${row.id}`}
              className="ml-auto inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs hover:bg-accent"
            >
              <Activity className="h-3 w-3" /> Packet capture
            </Link>
          )}
        </div>

        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Capabilities
          </h3>
          <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
            <CapRow label="DNS — BIND9" on={!!caps.can_run_dns_bind9} />
            <CapRow label="DNS — PowerDNS" on={!!caps.can_run_dns_powerdns} />
            <CapRow
              label="DNS — Technitium"
              on={!!caps.can_run_dns_technitium}
            />
            <CapRow label="DHCP" on={!!caps.can_run_dhcp} />
            <CapRow label="Looking Glass" on={!!caps.can_run_looking_glass} />
            <CapRow label="Observer" on={!!caps.can_run_observer} />
          </div>
          <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
            <FactRow label="CPUs" value={caps.cpu_count} />
            <FactRow
              label="Memory"
              value={
                typeof caps.memory_mb === "number"
                  ? `${(caps.memory_mb / 1024).toFixed(1)} GiB`
                  : undefined
              }
            />
            <FactRow label="Storage" value={caps.storage_type} />
            {/* #1017 — what the node is ACTUALLY running, not what STATE
                asked for. Absent entirely on a supervisor too old to
                report, which is UNKNOWN rather than "at the default". */}
            <FactRow label="MTU" value={mtuFactValue(row)} />
            {/* The refusal reason, and where to read the rest of it.
                Without this the row says an MTU "was refused" and the
                only explanation lives in a log file on the node.

                `?? []` for the same reason the storage block keeps one:
                during a rolling upgrade the frontend and api pods do not
                flip together, so a new bundle can meet a pre-#1017 api
                and get `undefined` here — a bare `.map` unmounts the
                whole drilldown instead of degrading. Coloured by
                `f.severity` rather than hardcoded amber, so a severity
                this build does not understand is not rendered as the
                mildest one. */}
            {(row.mtu_findings ?? []).map((f, i) => (
              <Fragment key={`mtu-finding-${i}`}>
                <dt className="text-muted-foreground">&nbsp;</dt>
                <dd className={storageSeverityClass(f.severity)}>{f.detail}</dd>
              </Fragment>
            ))}
            <FactRow
              label="Host NICs"
              value={
                Array.isArray(caps.host_nics)
                  ? caps.host_nics.join(", ")
                  : undefined
              }
              icon={Network}
            />
          </dl>
        </div>

        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Identity
          </h3>
          <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-xs">
            <dt className="text-muted-foreground">Appliance id</dt>
            <dd className="break-all font-mono">{row.id}</dd>
            <dt className="text-muted-foreground">Pubkey fingerprint</dt>
            <dd className="break-all font-mono">
              {row.public_key_fingerprint}
            </dd>
            <dt className="text-muted-foreground">Paired</dt>
            <dd>
              {row.paired_at ? new Date(row.paired_at).toLocaleString() : "—"}
              {row.paired_from_ip ? ` · from ${row.paired_from_ip}` : ""}
            </dd>
            <dt className="text-muted-foreground">Last seen</dt>
            <dd>
              {row.last_seen_at
                ? new Date(row.last_seen_at).toLocaleString()
                : "—"}
              {row.last_seen_ip ? ` · ${row.last_seen_ip}` : ""}
            </dd>
            {row.approved_at && (
              <>
                <dt className="text-muted-foreground">Approved</dt>
                <dd>{new Date(row.approved_at).toLocaleString()}</dd>
              </>
            )}
          </dl>
        </div>

        {row.state === "approved" && (
          <ApplianceRoleAssignmentSection row={row} onSaved={onRowUpdated} />
        )}

        {row.state === "approved" &&
          Object.keys(row.role_health ?? {}).length > 0 && (
            <ApplianceRoleHealthSection row={row} />
          )}

        {row.state === "approved" && <ApplianceStorageSection row={row} />}

        {row.state === "approved" && <ApplianceRemovableSection row={row} />}

        {row.state === "approved" &&
          Object.keys(row.host_config_health ?? {}).length > 0 && (
            <ApplianceHostConfigHealthSection row={row} />
          )}

        {row.state === "approved" &&
          Object.keys(row.host_migration_health ?? {}).length > 0 && (
            <ApplianceHostMigrationSection row={row} />
          )}

        {row.state === "approved" && (
          <ApplianceClusterHealthSection row={row} />
        )}

        {row.state === "approved" && (
          <ApplianceOsUpgradeSection
            row={row}
            onViewUpgradeImages={onViewUpgradeImages}
          />
        )}

        {row.state === "approved" && (
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Certificate
            </h3>
            <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-xs">
              <dt className="text-muted-foreground">Serial</dt>
              <dd className="break-all font-mono">{row.cert_serial ?? "—"}</dd>
              <dt className="text-muted-foreground">Issued</dt>
              <dd>
                {row.cert_issued_at
                  ? new Date(row.cert_issued_at).toLocaleString()
                  : "—"}
              </dd>
              <dt className="text-muted-foreground">Expires</dt>
              <dd>
                {row.cert_expires_at
                  ? new Date(row.cert_expires_at).toLocaleString()
                  : "—"}
              </dd>
            </dl>
          </div>
        )}

        <div className="flex flex-wrap justify-end gap-2">
          {row.state === "pending_approval" ? (
            <>
              <button
                type="button"
                onClick={onReject}
                className="inline-flex items-center gap-1 rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-700 hover:bg-rose-500/20 dark:text-rose-300"
              >
                <XCircle className="h-3.5 w-3.5" />
                Reject
              </button>
              <button
                type="button"
                onClick={onApprove}
                disabled={approving}
                className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-50 dark:text-emerald-300"
              >
                {approving ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <CheckCircle2 className="h-3.5 w-3.5" />
                )}
                Approve + sign cert
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                onClick={onDelete}
                className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Delete
              </button>
              <button
                type="button"
                onClick={onRekey}
                className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted"
              >
                <KeyRound className="h-3.5 w-3.5" />
                Re-key
              </button>
            </>
          )}
        </div>
      </div>
    </Modal>
  );
}

function CapRow({ label, on }: { label: string; on: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-md border bg-background px-2 py-1.5 text-xs">
      <span
        className={cn(
          "inline-block h-1.5 w-1.5 rounded-full",
          on ? "bg-emerald-500" : "bg-muted-foreground/30",
        )}
      />
      <span className={cn(!on && "text-muted-foreground")}>{label}</span>
    </div>
  );
}

/**
 * #1017 — the cluster is not all on one interface MTU.
 *
 * k3s runs flannel in host-gw mode, which writes plain routes instead of
 * encapsulating, so the pod network inherits the node MTU with no tunnel
 * headroom. A mixed-MTU cluster black-holes pod-to-pod traffic and
 * presents as random timeouts — with nothing anywhere else in the UI that
 * would explain it, which is the whole reason this banner exists.
 *
 * Shares the roster's query key, so it costs no extra request: React
 * Query dedupes by key and `select` gives each caller the slice it wants.
 * Renders nothing when consistent, including when nobody reported — the
 * absence of a reading is not a fault, and every appliance installed
 * before #1017 reports nothing.
 */
/**
 * The amber callout the Fleet tab uses for cluster-level advisories.
 *
 * Extracted because the MTU banner reproduced this exact six-element
 * shape verbatim, twelve lines above the VIP advisory that already had
 * it — two copies of one banner on one screen, which diverge the first
 * time either is restyled.
 */
function FleetAdvisory({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-4 rounded-md border border-amber-500/50 bg-amber-500/10 p-4">
      <div className="flex items-start gap-3">
        <AlertCircle className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-700 dark:text-amber-400" />
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-amber-700 dark:text-amber-400">
            {title}
          </p>
          {children}
        </div>
      </div>
    </div>
  );
}

function MtuFleetAdvisory() {
  const { data: fleet } = useQuery({
    queryKey: ["appliance", "fleet"],
    queryFn: applianceApprovalApi.listFleet,
    select: selectMtuFleet,
  });
  if (!fleet || fleet.consistent || !fleet.detail) return null;
  return (
    <FleetAdvisory title="Nodes are not on the same interface MTU">
      <p className="mt-1 text-sm text-muted-foreground">{fleet.detail}</p>
      <p className="mt-2 text-xs text-muted-foreground">
        The MTU is set at install and applied at boot. Change it with{" "}
        <code className="rounded bg-muted px-1 py-0.5">nmtui</code> on the node,
        then save it into STATE when the console offers to — an edit that is not
        adopted reverts at the next boot.
      </p>
    </FleetAdvisory>
  );
}

/** #1017 — one node's MTU, for the drilldown. Null when it never reported. */
function mtuFactValue(row: ApplianceRow): string | null {
  if (!row.mtu_reported) return null;
  switch (row.mtu_applied) {
    case "applied":
      // `mtu` is read out of an unvalidated JSONB blob, so a torn or
      // malformed sidecar can leave it null while `mtu_applied` still
      // says "applied" — without this the row rendered the string
      // "null".
      return row.mtu == null ? null : `${row.mtu}`;
    case "dropped":
      // Deliberately not just "default": the operator asked for something
      // and is not getting it, and a row reading "default" would hide
      // that behind a word that looks deliberate.
      return `link default — ${row.mtu_requested ?? "the configured value"} was refused`;
    case "n/a":
      // Same reasoning as "dropped" when a value was configured: no
      // profile was written, so it applies to nothing, and rendering a
      // flat "link default" would read as though nothing was ever set.
      return row.mtu_requested
        ? `link default — ${row.mtu_requested} applies to nothing (no managed profile)`
        : "link default (no managed profile)";
    case "default":
      return "link default";
    default:
      return null;
  }
}

function FactRow({
  label,
  value,
  icon: IconComp,
}: {
  label: string;
  value: string | number | undefined | null;
  icon?: typeof Network;
}) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <>
      <dt className="flex items-center gap-1 text-muted-foreground">
        {IconComp ? <IconComp className="h-3 w-3" /> : null}
        {label}
      </dt>
      <dd className="break-all">{value}</dd>
    </>
  );
}

// Silence unused-vars on the input class export — kept for future
// per-row inline edits (notes / tags) without making the import
// disappear on a UI shape revisit.
void inputCls;

// ── Role assignment section (#170 Wave C2) ────────────────────────

const ROLE_OPTIONS: { value: string; label: string; capKey?: string }[] = [
  {
    value: "dns-bind9",
    label: "DNS · BIND9",
    capKey: "can_run_dns_bind9",
  },
  {
    value: "dns-powerdns",
    label: "DNS · PowerDNS",
    capKey: "can_run_dns_powerdns",
  },
  {
    value: "dns-technitium",
    label: "DNS · Technitium",
    capKey: "can_run_dns_technitium",
  },
  { value: "dhcp", label: "DHCP", capKey: "can_run_dhcp" },
  {
    value: "looking-glass",
    label: "Looking Glass",
    capKey: "can_run_looking_glass",
  },
  { value: "observer", label: "Observer", capKey: "can_run_observer" },
];

// Mutually-exclusive DNS engine roles — at most one may be active at a
// time (one DNS daemon per appliance). Used by the role toggle handler
// and every "is a DNS role assigned" check below instead of an
// enumerated pairwise comparison, so a fourth driver is a one-line add.
const DNS_ROLES = new Set(["dns-bind9", "dns-powerdns", "dns-technitium"]);

// ── Service-container watchdog section (#170 Wave E) ───────────
//
// Renders the supervisor's per-service health verdict (refreshed
// every 5 min on the appliance). Each entry carries status +
// ``since`` (when the supervisor first observed this status) +
// container_id, so a regression like "dhcp-kea unhealthy for 12 m"
// surfaces without SSH'ing in.

function formatRelativeSince(iso: string): string {
  const since = new Date(iso).getTime();
  if (!Number.isFinite(since)) return iso;
  const seconds = Math.max(0, Math.round((Date.now() - since) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

const WATCHDOG_STATUS_STYLES: Record<
  "healthy" | "missing" | "unhealthy" | "starting",
  { className: string; label: string; Icon: typeof CheckCircle2 }
> = {
  healthy: {
    className:
      "bg-emerald-500/15 text-emerald-700 border-emerald-500/40 dark:text-emerald-300",
    label: "healthy",
    Icon: CheckCircle2,
  },
  missing: {
    className:
      "bg-rose-500/15 text-rose-700 border-rose-500/40 dark:text-rose-300",
    label: "missing",
    Icon: AlertCircle,
  },
  unhealthy: {
    className:
      "bg-rose-500/15 text-rose-700 border-rose-500/40 dark:text-rose-300",
    label: "unhealthy",
    Icon: AlertCircle,
  },
  starting: {
    className:
      "bg-amber-500/15 text-amber-700 border-amber-500/40 dark:text-amber-300",
    label: "starting",
    Icon: Loader2,
  },
};

function ApplianceRoleHealthSection({ row }: { row: ApplianceRow }) {
  const entries = Object.entries(row.role_health ?? {});
  // Show services in a stable order — alphabetical by service name.
  entries.sort(([a], [b]) => a.localeCompare(b));
  return (
    <div className="border-t pt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Service health
      </h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Supervisor watchdog snapshot — refreshed every 5 min. ``missing`` /
        ``unhealthy`` for more than one cadence means the auto-heal kicker
        didn&apos;t bring the container back; SSH in and check{" "}
        <code>docker logs &lt;service&gt;</code>.
      </p>
      <div className="mt-2 overflow-hidden rounded-md border">
        <table className="w-full text-xs">
          <thead className="bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-3 py-1.5 text-left font-medium">Service</th>
              <th className="px-3 py-1.5 text-left font-medium">Role</th>
              <th className="px-3 py-1.5 text-left font-medium">Status</th>
              <th className="px-3 py-1.5 text-left font-medium">Since</th>
              <th className="px-3 py-1.5 text-left font-medium">Container</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {entries.map(([svc, h]) => {
              const style =
                WATCHDOG_STATUS_STYLES[h.status] ??
                WATCHDOG_STATUS_STYLES.unhealthy;
              const Icon = style.Icon;
              return (
                <tr key={svc}>
                  <td className="px-3 py-1.5 font-mono">{svc}</td>
                  <td className="px-3 py-1.5">{h.role}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                        style.className,
                      )}
                    >
                      <Icon className="h-2.5 w-2.5" />
                      {style.label}
                    </span>
                  </td>
                  <td
                    className="px-3 py-1.5 text-muted-foreground"
                    title={h.since}
                  >
                    {formatRelativeSince(h.since)}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-muted-foreground">
                    {h.container_id ?? "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// #999 Part A — storage redundancy. Renders only when the supervisor
// has actually reported arrays or multipath maps: an ordinary
// single-disk appliance gains nothing, and a supervisor too old to
// collect storage state gets no section rather than a green tick,
// because "we never looked" is not "all clear".
/**
 * #999 Part B — the destructive-action modal.
 *
 * The device path has to be typed back, not a checkbox. A generic "yes"
 * cannot catch the mistake that actually happens here: the operator
 * meant one disk and clicked the row for the other. `mdadm --add`
 * overwrites whatever it is given.
 *
 * The two actions that are REFUSED rather than confirmed (removing the
 * last in-sync member, or the member the bootloader lives on) are not
 * offered as a confirmation at all — the host runner refuses them, and
 * this modal would be the wrong place to decide, because its view of the
 * array is up to one heartbeat old.
 */
function StorageActionModal({
  applianceId,
  action,
  array,
  device,
  onClose,
}: {
  applianceId: string;
  action: StorageActionRequest["action"];
  array: string | null;
  device: string | null;
  onClose: (changed: boolean) => void;
}) {
  // ``add_member`` names a device that is not in the array yet, so the
  // operator supplies it here. Every other action already knows its
  // device (it was clicked).
  const needsDevicePick = action === "add_member" && !device;
  const [picked, setPicked] = useState(device ?? "");
  const effectiveDevice = needsDevicePick ? picked.trim() : (device ?? "");
  const [typed, setTyped] = useState("");
  const [result, setResult] = useState<StorageActionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const destructive =
    action === "fail_member" ||
    action === "remove_member" ||
    action === "add_member";
  const needsDevice = action !== "scrub_start" && action !== "scrub_cancel";

  const run = useMutation({
    mutationFn: () =>
      applianceApi.storageAction(applianceId, {
        action,
        array,
        device: effectiveDevice || null,
        confirm: destructive ? typed : undefined,
      }),
    onSuccess: (r) => {
      setResult(r);
      setError(null);
    },
    onError: (e: unknown) => {
      // The FastAPI detail, not axios's "Request failed with status code
      // 422" — which is what `err.message` always is and never what the
      // operator needs (the #1009 lesson).
      const ax = e as { response?: { data?: { detail?: string } } };
      setError(ax.response?.data?.detail ?? "The action could not be run.");
    },
  });

  const label: Record<string, string> = {
    scrub_start: "Start a consistency scrub",
    scrub_cancel: "Cancel the running scrub",
    fail_member: "Mark this member failed",
    remove_member: "Remove this member from the array",
    add_member: "Add this device to the array",
    mpath_reinstate: "Reinstate this path",
  };

  return (
    <Modal
      onClose={() => onClose(result?.ok === true)}
      title={label[action] ?? action}
    >
      <div className="space-y-3 text-sm">
        <dl className="grid grid-cols-[7rem_1fr] gap-1 text-xs">
          {array && (
            <>
              <dt className="text-muted-foreground">Array</dt>
              <dd className="font-mono break-all">{array}</dd>
            </>
          )}
          {device && (
            <>
              <dt className="text-muted-foreground">Device</dt>
              <dd className="font-mono break-all">{device}</dd>
            </>
          )}
        </dl>

        {needsDevicePick && !result && (
          <label className="block text-xs">
            <span className="text-muted-foreground">
              Device to add (it will be erased)
            </span>
            <input
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
              placeholder="/dev/sdc4"
              value={picked}
              onChange={(e) => setPicked(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
        )}

        {action === "add_member" && (
          <p className="rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1.5 text-xs text-rose-700 dark:text-rose-300">
            This <strong>ERASES {effectiveDevice || "the device"}</strong>.
            mdadm overwrites whatever device it is given.
          </p>
        )}
        {(action === "fail_member" || action === "remove_member") && (
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-300">
            The array loses this copy. Removing the last in-sync member, or the
            one this appliance boots from, is refused by the node rather than
            confirmed here — its view of the array is current and this
            screen&apos;s is up to one heartbeat old.
          </p>
        )}

        {destructive && !result && effectiveDevice && (
          <label className="block text-xs">
            <span className="text-muted-foreground">
              Type <code className="font-mono">{effectiveDevice}</code> to
              confirm
            </span>
            <input
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
        )}

        {error && (
          <p className="rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1.5 text-xs text-rose-700 dark:text-rose-300">
            {error}
          </p>
        )}
        {result && (
          <div
            className={cn(
              "rounded-md border px-2 py-1.5 text-xs",
              result.ok
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                : "border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300",
            )}
          >
            {result.detail}
            {result.output && (
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap font-mono text-[10px] opacity-80">
                {result.output}
              </pre>
            )}
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <HeaderButton
            variant="secondary"
            onClick={() => onClose(result?.ok === true)}
          >
            {result ? "Close" : "Cancel"}
          </HeaderButton>
          {!result && (
            <HeaderButton
              variant={destructive ? "destructive" : "primary"}
              // Every action except the two scrub controls needs a
              // device, and the destructive ones additionally need it
              // typed back.
              disabled={
                run.isPending ||
                (needsDevice && !effectiveDevice) ||
                (destructive && typed !== effectiveDevice)
              }
              onClick={() => run.mutate()}
            >
              {run.isPending ? "Running…" : "Run"}
            </HeaderButton>
          )}
        </div>
      </div>
    </Modal>
  );
}

// ── #989 item 3 — removable (USB) backup disks ──────────────────────
//
// The single-appliance operator with no NAS and no cloud account backs
// up to a USB disk. This is where they plug one in and point a backup
// destination at it.

const REMOVABLE_STATE_CLS: Record<string, string> = {
  mounted: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600",
  // `waiting` is amber-but-benign; `present` is a real fault — the disk
  // is in the port and the mount did not take.
  waiting: "border-amber-500/40 bg-amber-500/10 text-amber-600",
  present: "border-rose-500/40 bg-rose-500/10 text-rose-600",
  blind: "border-rose-500/40 bg-rose-500/10 text-rose-600",
  unreported: "border-border bg-muted/40 text-muted-foreground",
};

/** Why a mount is in the state it is, in words the operator can act on. */
const REMOVABLE_STATE_HELP: Record<string, string> = {
  mounted: "The disk is plugged in and the filesystem is live.",
  waiting:
    "Configured and armed. The disk is not plugged in — it will mount by itself when it is.",
  present:
    "The disk IS plugged in and did not mount. Check the filesystem (a disk yanked without ejecting can come back dirty) and journalctl -u spatiumddi-removable-reload on the node.",
  blind:
    "This node cannot read its removable directory at all — the hostPath mount is missing or lost its propagation. Backups to it will fail even if the disk is fine.",
  unreported: "This node has not reported yet.",
};

function MountDiskModal({
  applianceId,
  disk,
  taken,
  pathTemplate,
  nodeName,
  onClose,
}: {
  applianceId: string;
  disk: RemovableDisk;
  taken: string[];
  pathTemplate: string;
  nodeName: string | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  // Pre-filled from the disk's own label, because that is what the
  // operator wrote on it — but SANITISED, since a label is set on the
  // disk and is neither unique nor constrained to a safe character set,
  // while this name becomes a directory and part of a systemd unit
  // filename.
  const suggested = (disk.label || disk.model || "usb")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32);
  const [name, setName] = useState(suggested || "usb1");
  const [error, setError] = useState<string | null>(null);
  const valid = /^[a-z0-9][a-z0-9_-]{0,31}$/.test(name);
  const collides = taken.includes(name);

  const mutation = useMutation({
    mutationFn: () =>
      applianceApi.mountRemovable(applianceId, { fs_uuid: disk.fs_uuid, name }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance-removable", applianceId] });
      // ["appliance", "fleet"], not ["appliances"] — the latter matches
      // no query in the codebase, so the fleet row (and its
      // host-config chip) stayed stale until the next 15 s tick.
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      onClose();
    },
    onError: (err: unknown) => {
      // Matched on the FastAPI detail, never on err.message — on an
      // AxiosError that is always "Request failed with status code 422"
      // and never the reason (#1009).
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setError(detail ?? "Could not mount the disk.");
    },
  });

  return (
    <Modal onClose={onClose} title="Mount removable disk">
      <div className="space-y-3 text-sm">
        <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
          <div className="font-medium">
            {[disk.vendor, disk.model].filter(Boolean).join(" ") || disk.device}
          </div>
          <div className="mt-0.5 text-muted-foreground">
            {disk.fstype} · {fmtDiskBytes(disk.size_bytes)}
            {disk.label ? ` · label “${disk.label}”` : ""} · UUID {disk.fs_uuid}
          </div>
        </div>
        <label className="block">
          <span className="text-xs font-medium">Name</span>
          <input
            className="mt-1 w-full rounded-md border bg-background px-2 py-1.5 text-sm"
            value={name}
            onChange={(e) => setName(e.target.value.toLowerCase())}
            autoFocus
          />
          <span className="mt-1 block text-[11px] text-muted-foreground">
            Lowercase letters, digits, <code>-</code> or <code>_</code>. It
            becomes a directory on the appliance, so pick something you will
            recognise — you will type it into the backup destination.
          </span>
        </label>
        {valid && !collides && (
          <div className="rounded-md border bg-muted/30 px-3 py-2 text-[11px]">
            <div className="text-muted-foreground">
              Point a <strong>Local volume</strong> backup destination at:
            </div>
            <code className="mt-1 block break-all">
              {pathTemplate.replace("{name}", name)}
            </code>
            {nodeName && (
              <div className="mt-1.5 text-muted-foreground">
                Set the destination&apos;s <strong>Kubernetes node</strong> to{" "}
                <code>{nodeName}</code> — a removable disk is node-local, and
                that is what makes a run scheduled elsewhere say where the disk
                is instead of just &ldquo;nothing is mounted&rdquo;.
              </div>
            )}
          </div>
        )}
        {!valid && name.length > 0 && (
          <p className="text-xs text-destructive">
            Use lowercase letters, digits, <code>-</code> or <code>_</code>,
            starting with a letter or digit, at most 32 characters.
          </p>
        )}
        {collides && (
          <p className="text-xs text-destructive">
            This appliance already has a mount named “{name}”.
          </p>
        )}
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 pt-1">
          <HeaderButton variant="secondary" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            variant="primary"
            disabled={!valid || collides || mutation.isPending}
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending ? "Mounting…" : "Mount"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

function ApplianceRemovableSection({ row }: { row: ApplianceRow }) {
  const qc = useQueryClient();
  const [mounting, setMounting] = useState<RemovableDisk | null>(null);
  const [ejecting, setEjecting] = useState<RemovableMount | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["appliance-removable", row.id],
    queryFn: () => applianceApi.listRemovable(row.id),
    // Polled rather than live: the reading rides the node's heartbeat,
    // so a disk plugged in a moment ago appears on the next tick. This
    // is what makes that arrive without the operator hunting for a
    // Refresh button that could not have helped anyway.
    refetchInterval: 20_000,
  });

  const [ejectError, setEjectError] = useState<string | null>(null);
  const eject = useMutation({
    mutationFn: (name: string) => applianceApi.ejectRemovable(row.id, name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance-removable", row.id] });
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setEjecting(null);
    },
    // Without this a 503 (maintenance mode 503s every mutation), a 404
    // from a second tab, or any 5xx left the modal sitting there with
    // the spinner stopped and no message — after telling the operator
    // "safe to pull once this finishes". Matched on the FastAPI detail,
    // never on err.message, which on an AxiosError is always "Request
    // failed with status code N" (#1009).
    onError: (err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setEjectError(
        detail ?? "Could not eject the disk. It may still be mounted.",
      );
    },
  });

  if (isLoading) return null;
  // Nothing reported and nothing configured: an ordinary appliance with
  // no USB disk gains no clutter, exactly like the storage section.
  if (!data || (!data.reported && data.mounts.length === 0)) return null;
  const mounted = data.mounts.map((m) => m.name);

  return (
    <div className="border-t pt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Removable storage
      </h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Mount a USB disk on this node and point a <strong>Local volume</strong>{" "}
        backup destination at it. The reading comes from this node&apos;s
        heartbeat, so a disk you just plugged in appears within about a minute.
        {data.node_name ? ` Disks here are on node ${data.node_name}.` : ""}
      </p>

      {!data.root_readable && (
        <p className="mt-2 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1.5 text-[11px] text-rose-600">
          This node cannot read <code>/var/lib/spatiumddi/removable</code>. The
          hostPath mount is missing or has lost its{" "}
          <code>mountPropagation: HostToContainer</code>, so backups here will
          fail whatever the disks below say.
        </p>
      )}
      {data.apply_state && (
        <p className="mt-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] text-amber-600">
          The appliance has not applied its removable-mount config yet (
          {data.apply_state}).{" "}
          {/* The runner's own reason, when it wrote one — otherwise the
              operator is told only "not applied" and sent to journalctl. */}
          {data.apply_error ? (
            <>
              The node reported: <em>{data.apply_error}</em>
            </>
          ) : (
            <>
              Check <code>journalctl -u spatiumddi-removable-reload</code> on
              the node.
            </>
          )}
        </p>
      )}

      {data.mounts.length > 0 && (
        <div className="mt-2 overflow-hidden rounded-md border">
          <table className="w-full text-xs">
            <thead className="bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-1.5 text-left font-medium">Name</th>
                <th className="px-3 py-1.5 text-left font-medium">State</th>
                <th className="px-3 py-1.5 text-left font-medium">Free</th>
                <th className="px-3 py-1.5 text-left font-medium">
                  Destination path
                </th>
                <th className="px-3 py-1.5 text-left font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y">
              {data.mounts.map((m) => (
                <tr key={m.name}>
                  <td className="px-3 py-1.5 font-mono">{m.name}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                        REMOVABLE_STATE_CLS[m.state] ??
                          REMOVABLE_STATE_CLS.unreported,
                      )}
                      title={REMOVABLE_STATE_HELP[m.state]}
                    >
                      {m.state}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    {m.state === "mounted"
                      ? `${fmtDiskBytes(m.free_bytes)} of ${fmtDiskBytes(m.total_bytes)}`
                      : "—"}
                  </td>
                  <td className="px-3 py-1.5">
                    <code className="break-all text-[11px]">{m.path}</code>
                  </td>
                  <td className="px-3 py-1.5 text-right">
                    <HeaderButton
                      variant="destructive"
                      onClick={() => setEjecting(m)}
                    >
                      Eject
                    </HeaderButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.reported && (
        <div className="mt-3">
          <div className="text-[11px] font-medium text-muted-foreground">
            Detected disks
          </div>
          {data.disks.length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">
              No USB disk with a filesystem is plugged into this node.
            </p>
          ) : (
            <ul className="mt-1 space-y-1">
              {data.disks.map((d) => {
                const alreadyMounted = data.mounts.some(
                  (m) => m.fs_uuid === d.fs_uuid,
                );
                return (
                  <li
                    key={d.fs_uuid || d.device}
                    className="flex flex-wrap items-center gap-2 rounded-md border px-2 py-1.5 text-[11px]"
                  >
                    <span className="font-medium">
                      {[d.vendor, d.model].filter(Boolean).join(" ") ||
                        d.device ||
                        "USB disk"}
                    </span>
                    <span className="text-muted-foreground">
                      {d.fstype} · {fmtDiskBytes(d.size_bytes)}
                      {d.label ? ` · “${d.label}”` : ""}
                    </span>
                    <span className="ml-auto flex items-center gap-2">
                      {/* Unusable disks are shown DISABLED with the reason,
                          never hidden: a disk that simply does not appear
                          reads as a broken feature (#1026's picker rule). */}
                      {d.reason && (
                        <span className="text-muted-foreground">
                          {d.reason}
                        </span>
                      )}
                      <HeaderButton
                        variant="secondary"
                        disabled={!d.usable || alreadyMounted}
                        title={
                          alreadyMounted
                            ? "Already mounted on this appliance"
                            : (d.reason ?? undefined)
                        }
                        onClick={() => setMounting(d)}
                      >
                        {alreadyMounted ? "Mounted" : "Mount…"}
                      </HeaderButton>
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}

      {mounting && (
        <MountDiskModal
          applianceId={row.id}
          disk={mounting}
          taken={mounted}
          pathTemplate={data.path_template}
          nodeName={data.node_name}
          onClose={() => setMounting(null)}
        />
      )}
      {ejecting && (
        <ConfirmModal
          open
          title={`Eject ${ejecting.name}?`}
          // Deliberately not blocked by a backup target still pointing
          // here. The operator wants their disk back, and refusing would
          // leave them pulling it anyway with the filesystem un-flushed.
          message={
            ejectError ? (
              <span className="text-destructive">{ejectError}</span>
            ) : (
              `The disk is flushed and unmounted, so it is safe to pull once the node ` +
              `reports it gone. Any backup destination pointing at ${ejecting.path} ` +
              `will fail — loudly — until you mount it again.`
            )
          }
          confirmLabel="Eject"
          tone="destructive"
          loading={eject.isPending}
          onConfirm={() => eject.mutate(ejecting.name)}
          onClose={() => {
            setEjectError(null);
            setEjecting(null);
          }}
        />
      )}
    </div>
  );
}

function ApplianceStorageSection({ row }: { row: ApplianceRow }) {
  const qc = useQueryClient();
  const [pending, setPending] = useState<{
    action: StorageActionRequest["action"];
    array: string | null;
    device: string | null;
  } | null>(null);
  const storage = row.cluster_health?.storage;
  const arrays = storage?.md_arrays ?? [];
  const maps = storage?.multipath_maps ?? [];
  if (!row.storage_reported || (arrays.length === 0 && maps.length === 0)) {
    return null;
  }
  const findings = row.storage_findings ?? [];
  const findingFor = (kind: string, name: string) =>
    findings.find((f) => f.kind === kind && f.name === name) ?? null;

  return (
    <div className="border-t pt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Storage redundancy
      </h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Read from the host&apos;s sysfs by the supervisor. A degraded mirror
        keeps serving perfectly — which is exactly why it needs a screen: the
        array state below is derived from member counts, not from the
        kernel&apos;s own <code>array_state</code>, which reports{" "}
        <code>clean</code> for a mirror down to its last disk.
      </p>

      {findings.length > 0 && (
        <ul className="mt-2 space-y-1">
          {findings.map((f, i) => (
            <li
              key={`${f.kind}-${f.name}-${i}`}
              className={cn(
                "rounded-md border px-2 py-1.5 text-[11px]",
                storageSeverityClass(f.severity),
              )}
            >
              {f.detail}
            </li>
          ))}
        </ul>
      )}

      {arrays.length > 0 && (
        <div className="mt-2 overflow-hidden rounded-md border">
          <table className="w-full text-xs">
            <thead className="bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-1.5 text-left font-medium">Array</th>
                <th className="px-3 py-1.5 text-left font-medium">Level</th>
                <th className="px-3 py-1.5 text-left font-medium">State</th>
                <th className="px-3 py-1.5 text-left font-medium">Members</th>
                <th className="px-3 py-1.5 text-left font-medium">Progress</th>
                <th className="px-3 py-1.5 text-left font-medium">Manage</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {arrays.map((a) => (
                <tr key={a.name}>
                  <td className="px-3 py-1.5 font-mono">{a.name}</td>
                  <td className="px-3 py-1.5">{formatMdLevel(a.level)}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                        storageChipClass(
                          findingFor("md", a.name)?.severity ?? null,
                          "md",
                        ),
                      )}
                    >
                      {a.state}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="text-muted-foreground">
                      {a.members_in_sync} of {a.members_expected ?? "?"} in sync
                      {a.members_faulty > 0 && ` · ${a.members_faulty} faulty`}
                      {a.spares > 0 && ` · ${a.spares} spare`}
                    </div>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {a.members.map((m) => (
                        <button
                          key={m.device}
                          type="button"
                          className="rounded bg-muted px-1 font-mono text-[10px] hover:ring-1 hover:ring-ring"
                          title={`${m.device}: ${m.state} — click to fail or remove it`}
                          onClick={() =>
                            setPending({
                              // A member the kernel already calls faulty
                              // is past failing; offer the next step.
                              action: m.state.includes("faulty")
                                ? "remove_member"
                                : "fail_member",
                              array: `/dev/${a.name}`,
                              device: `/dev/${m.device}`,
                            })
                          }
                        >
                          {m.device}
                          <span className="ml-1 opacity-70">{m.state}</span>
                        </button>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-1.5 text-muted-foreground">
                    {a.sync
                      ? `${a.sync.action}${
                          a.sync.percent != null ? ` ${a.sync.percent}%` : ""
                        }${
                          a.sync.eta_seconds != null
                            ? ` · ${formatEta(a.sync.eta_seconds)} left`
                            : ""
                        }`
                      : "—"}
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="flex flex-wrap gap-1">
                      <HeaderButton
                        variant="secondary"
                        onClick={() =>
                          setPending({
                            action: a.sync ? "scrub_cancel" : "scrub_start",
                            array: `/dev/${a.name}`,
                            device: null,
                          })
                        }
                      >
                        {a.sync ? "Cancel scrub" : "Scrub"}
                      </HeaderButton>
                      {/* Offered only when the array is SHORT a member.
                          Adding to a complete array makes a hot spare,
                          which is a different decision from replacing a
                          failed disk and not what this screen is for. */}
                      {a.members_expected != null &&
                        a.members_in_sync < a.members_expected && (
                          <HeaderButton
                            variant="destructive"
                            onClick={() =>
                              setPending({
                                action: "add_member",
                                array: `/dev/${a.name}`,
                                device: "",
                              })
                            }
                          >
                            Add member…
                          </HeaderButton>
                        )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {maps.length > 0 && (
        <div className="mt-2 overflow-hidden rounded-md border">
          <table className="w-full text-xs">
            <thead className="bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-1.5 text-left font-medium">
                  Multipath map
                </th>
                <th className="px-3 py-1.5 text-left font-medium">Paths</th>
                <th className="px-3 py-1.5 text-left font-medium">Devices</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {maps.map((m) => (
                <tr key={m.dm_device}>
                  <td className="px-3 py-1.5 font-mono">
                    {m.name}
                    <span className="ml-1 text-[10px] text-muted-foreground">
                      {m.dm_device}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                        storageChipClass(
                          findingFor("multipath", m.name)?.severity ?? null,
                          "multipath",
                        ),
                      )}
                    >
                      {mpathChipLabel(m)}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="flex flex-wrap gap-1">
                      {m.paths.map((pth) => (
                        <button
                          key={pth.device}
                          type="button"
                          className="rounded bg-muted px-1 font-mono text-[10px] hover:ring-1 hover:ring-ring"
                          title={
                            (pth.device_state == null
                              ? "This path reports no SCSI device state (an NVMe path has none)."
                              : `SCSI device state: ${pth.device_state}`) +
                            " Click to ask multipathd to reinstate it."
                          }
                          onClick={() =>
                            setPending({
                              action: "mpath_reinstate",
                              array: null,
                              device: `/dev/${pth.device}`,
                            })
                          }
                        >
                          {pth.device}
                          <span className="ml-1 opacity-70">
                            {pth.device_state ?? "state unknown"}
                          </span>
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="border-t bg-muted/20 px-3 py-1.5 text-[10px] text-muted-foreground">
            Per-path state is the SCSI device&apos;s, not dm-multipath&apos;s —
            dm&apos;s own verdict needs <code>multipathd</code>. A path listed
            here is present, not necessarily in use.
          </p>
        </div>
      )}

      {pending && (
        <StorageActionModal
          applianceId={row.id}
          action={pending.action}
          array={pending.array}
          device={pending.device}
          onClose={(changed) => {
            setPending(null);
            // Only on a real change: this block reads the appliance
            // row's cluster_health, which the supervisor refreshes on
            // its next heartbeat, so an unconditional invalidate would
            // just repaint the same stale numbers.
            if (changed) {
              void qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
            }
          }}
        />
      )}
    </div>
  );
}

// #387 — per-plane host-config apply health. Renders only when at
// least one host-config plane (ntp / snmp / lldp / syslog / ssh /
// resolver / firewall / timezone) has a desired config that isn't
// applied — i.e. the supervisor's bounded-retry guard is backing off a
// stuck apply. A healthy appliance reports an empty dict, so this
// section quietly hides. Before #387 these stuck applies looped
// silently (the NTP runner failed every ~30 s, flooding thousands of
// .failed sidecars) with nothing surfaced in the UI.
const HOSTCFG_PLANE_LABELS: Record<string, string> = {
  ntp: "NTP (chrony)",
  snmp: "SNMP",
  lldp: "LLDP",
  syslog: "Syslog forwarding",
  ssh: "SSH keys / sshd",
  resolver: "DNS resolver",
  firewall: "Firewall",
  timezone: "Timezone",
  removable: "Removable disks",
  apt: "APT",
  console_mode: "Console mode",
};

function ApplianceHostConfigHealthSection({ row }: { row: ApplianceRow }) {
  const entries = Object.entries(row.host_config_health ?? {});
  entries.sort(([a], [b]) => a.localeCompare(b));
  const anyFailing = entries.some(([, h]) => h.state === "failing");
  return (
    <div className="border-t pt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Host-config apply health
      </h3>
      <p
        className={cn(
          "mt-1 text-xs",
          anyFailing
            ? "text-rose-700 dark:text-rose-300"
            : "text-amber-700 dark:text-amber-400",
        )}
      >
        {anyFailing
          ? "A host-config change keeps failing to apply on this appliance — the supervisor is retrying with backoff. Check the host runner log (e.g. /var/log/spatiumddi/chrony-reload.log) for the cause."
          : "A host-config change is still being applied (retrying)."}
      </p>
      <div className="mt-2 overflow-hidden rounded-md border">
        <table className="w-full text-xs">
          <thead className="bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-3 py-1.5 text-left font-medium">Config</th>
              <th className="px-3 py-1.5 text-left font-medium">State</th>
              <th className="px-3 py-1.5 text-left font-medium">Attempts</th>
              <th className="px-3 py-1.5 text-left font-medium">Last try</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {entries.map(([plane, h]) => {
              const failing = h.state === "failing";
              const Icon = failing ? AlertCircle : Loader2;
              return (
                <tr key={plane}>
                  <td className="px-3 py-1.5">
                    {HOSTCFG_PLANE_LABELS[plane] ?? plane}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                        failing
                          ? "bg-rose-500/15 text-rose-700 border-rose-500/40 dark:text-rose-300"
                          : "bg-amber-500/15 text-amber-700 border-amber-500/40 dark:text-amber-300",
                      )}
                    >
                      <Icon
                        className={cn(
                          "h-2.5 w-2.5",
                          !failing && "animate-spin",
                        )}
                      />
                      {h.state}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-muted-foreground">
                    {h.attempts}
                  </td>
                  <td
                    className="px-3 py-1.5 text-muted-foreground"
                    title={h.at ?? undefined}
                  >
                    {h.at ? formatRelativeSince(h.at) : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// #395 — host-migration reconcile health. Renders only when at least
// one numbered host-patch (e.g. 001-grub-render) failed to apply on
// the most recent firstboot reconcile. A healthy appliance reports an
// empty ``host_migration_health`` dict so this section quietly hides.
// Unlike ``ApplianceHostConfigHealthSection`` (continuous bounded-retry
// fire-guard), host-migration patches are run-once-per-boot — the
// state is always ``failing``; the next reboot automatically retries.
const HOST_MIGRATION_PATCH_LABELS: Record<string, string> = {
  "001-grub-render": "grub.cfg re-render",
  reconcile: "Host-migration reconcile",
};

function ApplianceHostMigrationSection({ row }: { row: ApplianceRow }) {
  const entries = Object.entries(row.host_migration_health ?? {});
  entries.sort(([a], [b]) => a.localeCompare(b));
  const anyFailing = entries.some(([, h]) => h.state === "failing");
  return (
    <div className="border-t pt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Host-migration health
      </h3>
      <p
        className={cn(
          "mt-1 text-xs",
          anyFailing
            ? "text-rose-700 dark:text-rose-300"
            : "text-amber-700 dark:text-amber-400",
        )}
      >
        {anyFailing
          ? "A host-migration patch failed on this appliance — the slot was not committed durable. The next reboot will retry. Check /var/log/spatiumddi/firstboot.log for the cause."
          : "A host-migration patch is still being applied (retrying)."}
      </p>
      <div className="mt-2 overflow-hidden rounded-md border">
        <table className="w-full text-xs">
          <thead className="bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-3 py-1.5 text-left font-medium">Patch</th>
              <th className="px-3 py-1.5 text-left font-medium">State</th>
              <th className="px-3 py-1.5 text-left font-medium">Attempts</th>
              <th className="px-3 py-1.5 text-left font-medium">Last try</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {entries.map(([patch, h]) => {
              const failing = h.state === "failing";
              const Icon = failing ? AlertCircle : Loader2;
              return (
                <tr key={patch}>
                  <td className="px-3 py-1.5">
                    {HOST_MIGRATION_PATCH_LABELS[patch] ?? patch}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                        failing
                          ? "bg-rose-500/15 text-rose-700 border-rose-500/40 dark:text-rose-300"
                          : "bg-amber-500/15 text-amber-700 border-amber-500/40 dark:text-amber-300",
                      )}
                    >
                      <Icon
                        className={cn(
                          "h-2.5 w-2.5",
                          !failing && "animate-spin",
                        )}
                      />
                      {h.state}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-muted-foreground">
                    {h.attempts}
                  </td>
                  <td
                    className="px-3 py-1.5 text-muted-foreground"
                    title={h.at ?? undefined}
                  >
                    {h.at ? formatRelativeSince(h.at) : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Issue #183 Phase 4 — k3s cluster-health summary + restart action.
// Renders only when the appliance has heartbeat-reported cluster
// state (legacy compose appliances ship an empty cluster_health
// dict, so this section quietly hides).
function ApplianceClusterHealthSection({ row }: { row: ApplianceRow }) {
  // Hooks must run unconditionally — declare state up front, then bail
  // later if cluster_health is empty.
  // #890 — the restart was a single button hardcoded to
  // ``deploy/dns-bind9``, so a node running PowerDNS, Technitium or Kea
  // had no restart at all. The picker lists what the appliance runs.
  const [restartOpen, setRestartOpen] = useState(false);
  const [restartResult, setRestartResult] = useState<string | null>(null);
  const [revealOpen, setRevealOpen] = useState(false);
  const [cidrEditorOpen, setCidrEditorOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);

  const ch = row.cluster_health ?? {};
  const ready = ch.kubeapi_ready === true;
  const nodesTotal = ch.nodes_total;
  const nodesReady = ch.nodes_ready;
  const podsTotal = ch.pods_total;
  const podsByPhase = ch.pods_by_phase ?? {};

  // Hide on pre-#183 / legacy compose appliances where the supervisor
  // never reports cluster_health.
  if (Object.keys(ch).length === 0) {
    return null;
  }

  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        k3s cluster health
      </h3>
      <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-xs">
        <dt className="text-muted-foreground">Kubeapi</dt>
        <dd>
          <span
            className={cn(
              "rounded-full px-1.5 py-0.5 font-mono text-[10px]",
              ready
                ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                : "bg-rose-500/10 text-rose-700 dark:text-rose-300",
            )}
          >
            {ready ? "ready" : "unreachable"}
          </span>
          {row.k3s_version && (
            <span className="ml-2 font-mono text-[11px] text-muted-foreground">
              {row.k3s_version}
            </span>
          )}
        </dd>
        {nodesTotal !== undefined && (
          <>
            <dt className="text-muted-foreground">Nodes</dt>
            <dd className="font-mono">
              {nodesReady ?? 0} / {nodesTotal} ready
            </dd>
          </>
        )}
        {podsTotal !== undefined && (
          <>
            <dt className="text-muted-foreground">Pods (spatium)</dt>
            <dd>
              <span className="font-mono">{podsTotal}</span>
              {Object.entries(podsByPhase).length > 0 && (
                <span className="ml-2 font-mono text-[11px] text-muted-foreground">
                  {Object.entries(podsByPhase)
                    .map(([phase, count]) => `${phase} ${count}`)
                    .join(" · ")}
                </span>
              )}
            </dd>
          </>
        )}
        {row.k3s_api_cert_expires_at && (
          <>
            <dt className="text-muted-foreground">API cert</dt>
            <dd>
              <CertExpiryChip iso={row.k3s_api_cert_expires_at} />
            </dd>
          </>
        )}
        <dt className="text-muted-foreground">Direct access</dt>
        <dd>
          {row.kubeapi_expose_cidrs.length === 0 ? (
            <span className="text-[11px] text-muted-foreground">
              proxy-only
            </span>
          ) : (
            <span className="font-mono text-[11px]">
              {row.kubeapi_expose_cidrs.join(", ")}
            </span>
          )}
          <button
            type="button"
            onClick={() => setCidrEditorOpen(true)}
            className="ml-2 text-[11px] text-primary underline decoration-dotted underline-offset-2 hover:text-foreground"
          >
            Edit
          </button>
        </dd>
      </dl>
      <p className="mt-2 text-[11px] text-muted-foreground">
        Direct kubeapi proxy via the supervisor's mTLS channel — actions are
        sub-second on a healthy appliance.
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => {
            setRestartResult(null);
            setRestartOpen(true);
          }}
          disabled={!ready}
          title="Rollout-restart a workload on this appliance's k3s"
          className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw className="h-3 w-3" />
          Restart workload…
        </button>
        <button
          type="button"
          onClick={() => setRevealOpen(true)}
          disabled={!row.kubeconfig_set}
          title={
            row.kubeconfig_set
              ? "Reveal + download the admin kubeconfig (password-gated)"
              : "Supervisor hasn't shipped a kubeconfig yet"
          }
          className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
        >
          <KeyRound className="h-3 w-3" />
          Reveal kubeconfig
        </button>
        <button
          type="button"
          onClick={() => setLogsOpen(true)}
          disabled={!ready}
          title="View pod logs (snapshot via the kubeapi proxy)"
          className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
        >
          <FileText className="h-3 w-3" />
          Pod logs
        </button>
        {restartResult && (
          <span className="text-[11px] text-emerald-700 dark:text-emerald-300">
            {restartResult}
          </span>
        )}
      </div>
      {restartOpen && (
        <RestartWorkloadModal
          appliance={row}
          onClose={() => setRestartOpen(false)}
          onRestarted={(label) => {
            setRestartResult(`rollout-restart issued for ${label}`);
            setRestartOpen(false);
          }}
        />
      )}
      {revealOpen && (
        <RevealKubeconfigModal
          appliance={row}
          onClose={() => setRevealOpen(false)}
        />
      )}
      {cidrEditorOpen && (
        <KubeapiCidrEditorModal
          appliance={row}
          onClose={() => setCidrEditorOpen(false)}
        />
      )}
      {logsOpen && (
        <PodLogsModal appliance={row} onClose={() => setLogsOpen(false)} />
      )}
    </div>
  );
}

// Issue #183 Phase 8 — pod log viewer. Snapshot mode (no follow)
// because the Phase 4 kubeapi proxy is request/response. Operator
// picks a pod from the dropdown; backend fetches the last N lines
// via the proxy and we render in a textarea. Refresh button to
// re-fetch.
function PodLogsModal({
  appliance,
  onClose,
}: {
  appliance: ApplianceRow;
  onClose: () => void;
}) {
  const podsQuery = useQuery({
    queryKey: ["appliance", "fleet", appliance.id, "k8s-pods"],
    queryFn: () => applianceApprovalApi.k8sListPods(appliance.id),
    staleTime: 10_000,
  });
  const [selectedPod, setSelectedPod] = useState<string>("");
  const [selectedContainer, setSelectedContainer] = useState<string>("");
  const [tailLines, setTailLines] = useState<number>(500);

  // Auto-select the first pod when the list loads; keep the
  // operator's choice sticky after they change it.
  useEffect(() => {
    if (!selectedPod && podsQuery.data?.pods.length) {
      setSelectedPod(podsQuery.data.pods[0].name);
    }
  }, [podsQuery.data, selectedPod]);

  const selectedPodInfo = podsQuery.data?.pods.find(
    (p) => p.name === selectedPod,
  );
  // Reset container picker when the pod changes — first container
  // is the natural default.
  useEffect(() => {
    if (
      selectedPodInfo &&
      !selectedPodInfo.containers.includes(selectedContainer)
    ) {
      setSelectedContainer(selectedPodInfo.containers[0] ?? "");
    }
  }, [selectedPodInfo, selectedContainer]);

  const logsQuery = useQuery({
    queryKey: [
      "appliance",
      "fleet",
      appliance.id,
      "k8s-logs",
      selectedPod,
      selectedContainer,
      tailLines,
    ],
    queryFn: () =>
      applianceApprovalApi.k8sGetPodLogs(appliance.id, selectedPod, {
        container: selectedContainer || undefined,
        tail_lines: tailLines,
      }),
    enabled: !!selectedPod,
    staleTime: 0,
  });

  return (
    <Modal title={`Pod logs · ${appliance.hostname}`} onClose={onClose} wide>
      <div className="space-y-2 text-sm">
        <p className="text-xs text-muted-foreground">
          Snapshot via the kubeapi proxy (Phase 4 channel) — same as{" "}
          <code>kubectl logs --tail={tailLines}</code>. For continuous
          follow-mode, ssh to the appliance + run <code>kubectl logs -f</code>{" "}
          directly.
        </p>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[2fr_1fr_1fr] sm:items-end">
          <label className="text-xs">
            Pod
            <select
              value={selectedPod}
              onChange={(e) => setSelectedPod(e.target.value)}
              disabled={podsQuery.isLoading}
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs"
            >
              {podsQuery.isLoading && <option>Loading…</option>}
              {(podsQuery.data?.pods ?? []).map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name} ({p.phase}
                  {p.ready ? "·ready" : ""})
                </option>
              ))}
              {!podsQuery.isLoading &&
                (podsQuery.data?.pods?.length ?? 0) === 0 && (
                  <option value="">(no pods)</option>
                )}
            </select>
          </label>
          {selectedPodInfo && selectedPodInfo.containers.length > 1 && (
            <label className="text-xs">
              Container
              <select
                value={selectedContainer}
                onChange={(e) => setSelectedContainer(e.target.value)}
                className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs"
              >
                {selectedPodInfo.containers.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="text-xs">
            Tail lines
            <select
              value={tailLines}
              onChange={(e) => setTailLines(Number(e.target.value))}
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs"
            >
              <option value={100}>100</option>
              <option value={500}>500</option>
              <option value={1000}>1000</option>
              <option value={5000}>5000</option>
            </select>
          </label>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => logsQuery.refetch()}
            disabled={!selectedPod || logsQuery.isFetching}
            className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            {logsQuery.isFetching ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <RefreshCw className="h-3 w-3" />
            )}
            Refresh
          </button>
          {logsQuery.error && (
            <span className="text-[11px] text-rose-700 dark:text-rose-300">
              {formatApiError(logsQuery.error)}
            </span>
          )}
        </div>
        <pre className="h-[50vh] overflow-auto whitespace-pre rounded-md border bg-muted/30 p-2 font-mono text-[11px] leading-tight">
          {logsQuery.isFetching && !logsQuery.data
            ? "Loading…"
            : logsQuery.data || "(empty)"}
        </pre>
      </div>
    </Modal>
  );
}

// Issue #183 Phase 6 — cert-expiry chip. Colour scales with
// days-remaining: emerald > 30 d, amber 7-30 d, rose < 7 d, red on
// already-expired. k3s rotates the cert automatically on
// k3s.service restart so the red state is rarely reachable in
// practice.
function CertExpiryChip({ iso }: { iso: string }) {
  const expiresAt = new Date(iso);
  const now = new Date();
  const days = Math.floor(
    (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24),
  );
  let cls: string;
  let label: string;
  if (days < 0) {
    cls = "bg-rose-500/10 text-rose-700 dark:text-rose-300";
    label = `expired ${-days}d ago`;
  } else if (days < 7) {
    cls = "bg-rose-500/10 text-rose-700 dark:text-rose-300";
    label = `expires in ${days}d`;
  } else if (days < 30) {
    cls = "bg-amber-500/10 text-amber-700 dark:text-amber-300";
    label = `expires in ${days}d`;
  } else {
    cls = "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
    label = `${days}d remaining`;
  }
  return (
    <span
      className={cn("rounded-full px-1.5 py-0.5 font-mono text-[10px]", cls)}
      title={`k3s API server cert expires ${expiresAt.toLocaleString()}`}
    >
      {label}
    </span>
  );
}

// Issue #183 Phase 6 — CIDR allowlist editor. Empty list = proxy-
// only (the recommended posture). Operators with sub-millisecond
// local-network kubectl needs add their CIDRs; the supervisor's
// firewall renderer picks them up on the next heartbeat + emits one
// ``ip saddr {…} tcp dport 6443 accept`` rule.
function KubeapiCidrEditorModal({
  appliance,
  onClose,
}: {
  appliance: ApplianceRow;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [text, setText] = useState(appliance.kubeapi_expose_cidrs.join("\n"));
  const save = useMutation({
    mutationFn: () => {
      const cidrs = text
        .split("\n")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      return applianceApprovalApi.updateKubeapiCidrs(appliance.id, cidrs);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      onClose();
    },
  });
  return (
    <Modal
      title={`Direct kubeapi access · ${appliance.hostname}`}
      onClose={onClose}
    >
      <div className="space-y-3 text-sm">
        <p className="text-xs text-muted-foreground">
          One CIDR or IP per line. Each entry opens this appliance's tcp/6443
          kubeapi port to that source range — bypassing the supervisor's mTLS
          proxy for sub-millisecond local-network <code>kubectl</code>. Leave
          empty for proxy-only (the recommended posture; kubeapi stays on
          127.0.0.1 and only the supervisor's outbound channel can drive it).
        </p>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={6}
          placeholder="10.0.0.0/8&#10;192.168.1.50"
          className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
        />
        {save.error && (
          <p className="text-xs text-rose-700 dark:text-rose-300">
            {formatApiError(save.error)}
          </p>
        )}
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => save.mutate()}
            disabled={save.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-50"
          >
            {save.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5" />
            )}
            Save
          </button>
        </div>
      </div>
    </Modal>
  );
}

// #890 — pick a workload to rollout-restart on this appliance's k3s.
// Replaces the single hardcoded "Restart bind9" button, which meant a
// node running PowerDNS, Technitium or Kea had no restart at all and a
// control-plane seed with DNS off had a button that would have errored.
// The list comes from the appliance itself through the supervisor's
// kubeapi proxy, so it can't drift from what is actually deployed.
function RestartWorkloadModal({
  appliance,
  onClose,
  onRestarted,
}: {
  appliance: ApplianceRow;
  onClose: () => void;
  onRestarted: (label: string) => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const workloads = useQuery({
    queryKey: ["appliance", "k8s-workloads", appliance.id],
    queryFn: () => applianceApprovalApi.k8sWorkloads(appliance.id),
  });
  const restart = useMutation({
    mutationFn: (w: ApplianceWorkload) =>
      applianceApprovalApi.k8sRolloutRestart(appliance.id, {
        kind: w.kind,
        namespace: w.namespace,
        name: w.name,
      }),
    onSuccess: (_res, w) => onRestarted(`${w.kind.toLowerCase()}/${w.name}`),
  });

  const rows = workloads.data?.workloads ?? [];
  const chosen = rows.find((w) => `${w.kind}/${w.name}` === selected) ?? null;

  return (
    <Modal
      title={`Restart a workload on ${appliance.hostname}`}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        {workloads.isLoading && (
          <p className="text-xs text-muted-foreground">
            Asking the appliance what it runs…
          </p>
        )}
        {workloads.error && (
          <p className="text-xs text-rose-700 dark:text-rose-300">
            {formatApiError(workloads.error)}
          </p>
        )}
        {/* Per-kind failures, not a whole-call failure: a cluster with an
            RBAC gap on StatefulSets should still let you restart the
            Deployments you came here for. */}
        {(workloads.data?.errors ?? []).map((e) => (
          <p key={e} className="text-[11px] text-amber-700 dark:text-amber-300">
            {e}
          </p>
        ))}
        {!workloads.isLoading && rows.length === 0 && !workloads.error && (
          <p className="text-xs text-muted-foreground">
            No SpatiumDDI workloads found in the spatium namespace.
          </p>
        )}
        {rows.length > 0 && (
          <div className="max-h-72 overflow-y-auto rounded-md border">
            <table className="w-full text-xs">
              <thead className="bg-muted/40 text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-2 py-1.5 text-left font-medium">
                    Workload
                  </th>
                  <th className="px-2 py-1.5 text-left font-medium">Kind</th>
                  <th className="px-2 py-1.5 text-left font-medium">Ready</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {rows.map((w) => {
                  const id = `${w.kind}/${w.name}`;
                  return (
                    <tr
                      key={id}
                      onClick={() => setSelected(id)}
                      className={cn(
                        "cursor-pointer",
                        selected === id ? "bg-primary/10" : "hover:bg-muted/50",
                      )}
                    >
                      <td className="px-2 py-1.5">
                        <div className="font-medium">{w.name}</div>
                        <div className="text-[10px] text-muted-foreground">
                          {w.image}
                        </div>
                      </td>
                      <td className="px-2 py-1.5 text-muted-foreground">
                        {w.kind}
                      </td>
                      <td className="px-2 py-1.5 font-mono">
                        {w.ready}/{w.desired}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {restart.error && (
          <p className="text-xs text-rose-700 dark:text-rose-300">
            {formatApiError(restart.error)}
          </p>
        )}
        <p className="text-[11px] text-muted-foreground">
          Rollout restart replaces pods one at a time, so a workload with more
          than one replica keeps serving through it.
        </p>
        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => chosen && restart.mutate(chosen)}
            disabled={!chosen || restart.isPending}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {restart.isPending && (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            )}
            Restart
          </button>
        </div>
      </div>
    </Modal>
  );
}

// Issue #183 Phase 5 — password-gated reveal + download for the
// appliance's admin kubeconfig. Mirrors Settings → Security ↘ Reveal
// SNMP community / agent bootstrap keys.
function RevealKubeconfigModal({
  appliance,
  onClose,
}: {
  appliance: ApplianceRow;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [shown, setShown] = useState<string | null>(null);
  const reveal = useMutation({
    mutationFn: () =>
      applianceApprovalApi.revealKubeconfig(
        appliance.id,
        password || undefined,
        totp || undefined,
      ),
    onSuccess: (data) => {
      setShown(data.kubeconfig ?? "");
    },
  });
  function download() {
    if (!shown) return;
    const blob = new Blob([shown], { type: "application/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${appliance.hostname}.kubeconfig`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <Modal
      title={`Reveal kubeconfig · ${appliance.hostname}`}
      onClose={onClose}
    >
      <div className="space-y-3 text-sm">
        <p className="text-xs text-muted-foreground">
          Re-confirm to reveal the admin kubeconfig the supervisor shipped for
          this appliance — with your password (local accounts) or an
          authenticator code (SSO). The reveal is audit-logged. The downloaded
          file works against the appliance from its current network; for
          cross-network use, edit the <code>server:</code> line to a reachable
          address.
        </p>
        {!shown && (
          <>
            <ReauthFields
              password={password}
              onPassword={setPassword}
              totp={totp}
              onTotp={setTotp}
              autoFocus
            />
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => reveal.mutate()}
                disabled={
                  (!password.trim() && !totp.trim()) || reveal.isPending
                }
                className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-50"
              >
                {reveal.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <KeyRound className="h-3.5 w-3.5" />
                )}
                Reveal
              </button>
            </div>
            {reveal.error && (
              <p className="text-xs text-rose-700 dark:text-rose-300">
                {formatApiError(reveal.error)}
              </p>
            )}
          </>
        )}
        {shown !== null && (
          <>
            {shown ? (
              <>
                <textarea
                  readOnly
                  value={shown}
                  rows={14}
                  className="w-full rounded-md border bg-muted/30 px-2 py-1 font-mono text-[11px]"
                />
                <div className="flex items-center justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => navigator.clipboard.writeText(shown)}
                    className="rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted"
                  >
                    Copy
                  </button>
                  <button
                    type="button"
                    onClick={download}
                    className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 text-xs hover:bg-primary/20"
                  >
                    Download {appliance.hostname}.kubeconfig
                  </button>
                </div>
              </>
            ) : (
              <p className="text-xs text-muted-foreground">
                Supervisor hasn't shipped a kubeconfig yet — wait for the next
                heartbeat after k3s.service is up.
              </p>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}

function ApplianceRoleAssignmentSection({
  row,
  onSaved,
}: {
  row: ApplianceRow;
  onSaved: (next: ApplianceRow) => void;
}) {
  const qc = useQueryClient();
  const caps = row.capabilities ?? {};
  const [roles, setRoles] = useState<Set<string>>(
    () => new Set(row.assigned_roles ?? []),
  );
  const [dnsGroupId, setDnsGroupId] = useState<string | null>(
    row.assigned_dns_group_id ?? null,
  );
  const [dhcpGroupId, setDhcpGroupId] = useState<string | null>(
    row.assigned_dhcp_group_id ?? null,
  );
  // #170 Wave C3 — operator-pasted nft fragment. Empty string clears
  // it server-side (the model column flips to NULL); the supervisor's
  // renderer skips the override block when nothing is set.
  const [firewallExtra, setFirewallExtra] = useState<string>(
    row.firewall_extra ?? "",
  );
  // Transient ``✓ Saved`` indicator next to the Save button. Cleared
  // after 2.5 s so the affirmative feedback doesn't linger forever.
  const [savedAt, setSavedAt] = useState<number | null>(null);
  useEffect(() => {
    if (savedAt === null) return;
    const t = setTimeout(() => setSavedAt(null), 2500);
    return () => clearTimeout(t);
  }, [savedAt]);
  // When the parent feeds us a refreshed row (after approve / save /
  // re-key) re-baseline the form state so ``dirty`` reads correctly.
  // Using JSON-stringified role list as the effect dep keeps Set
  // identity changes from causing infinite re-renders.
  const rolesKey = (row.assigned_roles ?? []).slice().sort().join(",");
  useEffect(() => {
    setRoles(new Set(row.assigned_roles ?? []));
    setDnsGroupId(row.assigned_dns_group_id ?? null);
    setDhcpGroupId(row.assigned_dhcp_group_id ?? null);
    setFirewallExtra(row.firewall_extra ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    row.id,
    rolesKey,
    row.assigned_dns_group_id,
    row.assigned_dhcp_group_id,
    row.firewall_extra,
  ]);

  // Use the SAME canonical keys the rest of the app invalidates on group
  // create/edit (["dns-groups"] / ["dhcp-groups"]) — the old tuple keys
  // ["dns","groups"] / ["dhcp","groups"] never matched those invalidations,
  // so a freshly-created group didn't appear here until a full reload (#367).
  const dnsGroupsQuery = useQuery({
    queryKey: ["dns-groups"],
    queryFn: dnsApi.listGroups,
    staleTime: 60_000,
  });
  const dhcpGroupsQuery = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
    staleTime: 60_000,
  });

  const save = useMutation({
    mutationFn: () =>
      applianceApprovalApi.updateRoles(row.id, {
        roles: Array.from(roles),
        dns_group_id: dnsGroupId,
        dhcp_group_id: dhcpGroupId,
        firewall_extra: firewallExtra,
      }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      // Belt-and-braces (#367): refresh the group pickers after a role
      // assign so a group created moments earlier is guaranteed current,
      // regardless of the 60s staleTime above.
      qc.invalidateQueries({ queryKey: ["dns-groups"] });
      qc.invalidateQueries({ queryKey: ["dhcp-groups"] });
      setSavedAt(Date.now());
      onSaved(updated);
    },
  });

  function toggleRole(role: string) {
    setRoles((current) => {
      const next = new Set(current);
      if (next.has(role)) {
        next.delete(role);
      } else {
        // Mutually-exclusive DNS engines — selecting one clears every
        // other dns-* role so the operator can't submit an invalid combo.
        if (DNS_ROLES.has(role)) {
          for (const r of DNS_ROLES) next.delete(r);
        }
        next.add(role);
      }
      return next;
    });
  }

  const dnsRoleActive = Array.from(roles).some((r) => DNS_ROLES.has(r));
  const dhcpRoleActive = roles.has("dhcp");
  // ``dirty`` compares the live form state against the latest
  // server-side row (the row prop refreshes after save), not the
  // snapshot taken at first mount — otherwise the Save button would
  // stay enabled after a successful save until the operator closes
  // the modal.
  const dirty =
    JSON.stringify(Array.from(roles).sort()) !==
      JSON.stringify((row.assigned_roles ?? []).slice().sort()) ||
    dnsGroupId !== (row.assigned_dns_group_id ?? null) ||
    dhcpGroupId !== (row.assigned_dhcp_group_id ?? null) ||
    firewallExtra !== (row.firewall_extra ?? "");

  // Live preview of the role-derived firewall profile name + opened
  // service ports. Mirrors the supervisor's firewall_renderer.py
  // logic so operators see what will actually land on the host.
  const firewallProfile = (() => {
    const hasDns = Array.from(roles).some((r) => DNS_ROLES.has(r));
    const hasDhcp = roles.has("dhcp");
    if (hasDns && hasDhcp) return "dns-and-dhcp";
    if (hasDns) return "dns-only";
    if (hasDhcp) return "dhcp-only";
    return "idle";
  })();
  const firewallOpenPorts: string[] = [];
  if (Array.from(roles).some((r) => DNS_ROLES.has(r))) {
    firewallOpenPorts.push("UDP/53", "TCP/53");
  }
  if (roles.has("dhcp")) {
    firewallOpenPorts.push("UDP/67", "UDP/68", "UDP/547");
  }

  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Role assignment
      </h3>
      <p className="mt-1 text-xs text-muted-foreground">
        Pick a subset of roles the supervisor brings up. DNS engines are
        mutually exclusive — one per appliance. The supervisor reads this on its
        next heartbeat (≤ 30s) and starts / stops the matching service
        containers.
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {ROLE_OPTIONS.map((opt) => {
          const cap = opt.capKey
            ? (caps[opt.capKey as keyof SupervisorCapabilities] as
                | boolean
                | undefined)
            : true;
          const disabled = !cap;
          const active = roles.has(opt.value);
          return (
            <button
              key={opt.value}
              type="button"
              disabled={disabled}
              onClick={() => toggleRole(opt.value)}
              title={
                disabled
                  ? `Supervisor doesn't advertise ${opt.capKey}=true; cannot assign.`
                  : undefined
              }
              className={cn(
                "rounded-md border px-2 py-1 text-xs",
                active
                  ? "border-primary bg-primary/10 text-foreground"
                  : "border-input bg-background text-muted-foreground hover:bg-muted",
                disabled && "cursor-not-allowed opacity-40",
              )}
            >
              {opt.label}
            </button>
          );
        })}
      </div>

      {dnsRoleActive && (
        <div className="mt-3">
          <label className="text-xs text-muted-foreground">DNS group</label>
          <select
            value={dnsGroupId ?? ""}
            onChange={(e) => setDnsGroupId(e.target.value || null)}
            className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs"
          >
            <option value="">(unassigned)</option>
            {dnsGroupsQuery.data?.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>
      )}
      {dhcpRoleActive && (
        <div className="mt-3">
          <label className="text-xs text-muted-foreground">DHCP group</label>
          <select
            value={dhcpGroupId ?? ""}
            onChange={(e) => setDhcpGroupId(e.target.value || null)}
            className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-xs"
          >
            <option value="">(unassigned)</option>
            {dhcpGroupsQuery.data?.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name} ({g.network_mode ?? "host"})
              </option>
            ))}
          </select>
        </div>
      )}

      {/* #170 Phase E2 — banner conflicts the operator should action
          before the role they just picked would actually bind on the
          host. We map the role chip to the port(s) it needs + only
          show the warning when there's a conflict on a port the
          chosen role would bind. */}
      <PortConflictBanner row={row} roles={roles} />

      {/* #593 — the supervisor blocked a firewall drop-in that would have
          firewalled this node out of its own etcd cluster. Always shown when
          present: it means the appliance row disagrees with what k3s reports,
          so the node is running a stale ruleset until an operator reconciles. */}
      <FirewallRefusalBanner row={row} />

      {/* #170 Wave D follow-up — outcome of the supervisor's last
          docker-compose apply. Red banner with stderr-first-line on
          failure. Green-tinted chip on ready. */}
      <RoleSwitchStateBanner row={row} />

      {/* #170 Wave C3 — firewall preview + operator-override textarea.
          The preview mirrors the supervisor's firewall_renderer.py
          output for the currently-selected roles so the operator can
          tell what nft drop-in will land before saving. */}
      <div className="mt-4 rounded-md border bg-muted/30 p-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-medium">Firewall profile</div>
          <span className="rounded-full bg-muted px-2 py-0.5 font-mono text-[10px]">
            {firewallProfile}
          </span>
        </div>
        <p className="mt-1 text-[11px] text-muted-foreground">
          Always open: <code>tcp/22</code> · <code>icmp echo</code> · loopback.
          {firewallOpenPorts.length > 0 ? (
            <>
              {" "}
              Per-role:{" "}
              {firewallOpenPorts.map((p, i) => (
                <span key={p}>
                  {i > 0 ? " · " : ""}
                  <code>{p}</code>
                </span>
              ))}
              .
            </>
          ) : (
            " No per-role ports (idle)."
          )}
        </p>
        <label className="mt-3 block text-xs text-muted-foreground">
          Operator override (raw nft fragment)
        </label>
        <textarea
          value={firewallExtra}
          onChange={(e) => setFirewallExtra(e.target.value)}
          placeholder={`# e.g. allow SNMP from monitoring subnet\n# udp dport 161 ip saddr 10.0.0.0/24 accept`}
          rows={4}
          className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono text-[11px]"
        />
        <p className="mt-1 text-[11px] text-muted-foreground">
          Appended verbatim after the role-driven block. Supervisor runs{" "}
          <code>nft -c -f</code> dry-run before live-swap — a syntactically
          invalid value is rejected on the host without leaving the firewall
          half-rendered.
        </p>
      </div>

      <div className="mt-3 flex items-center gap-2">
        <button
          type="button"
          disabled={!dirty || save.isPending}
          onClick={() => save.mutate()}
          className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 text-xs text-foreground disabled:cursor-not-allowed disabled:opacity-50"
        >
          {save.isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : null}
          Save role assignment
        </button>
        {savedAt !== null && !save.isPending && (
          <span className="inline-flex items-center gap-1 text-xs text-emerald-700 dark:text-emerald-300">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Saved
          </span>
        )}
        {save.error && (
          <span className="text-xs text-rose-700 dark:text-rose-300">
            {formatApiError(save.error)}
          </span>
        )}
      </div>
    </div>
  );
}

// ── OS upgrade + reboot section (#170 Wave D1) ────────────────────

function slotLabel(slot: string | null): string {
  if (slot === "slot_a") return "A";
  if (slot === "slot_b") return "B";
  return "—";
}

// Normalise a per-slot version string. The supervisor's sidecar uses
// ``"unstamped"`` / ``"unreadable"`` / ``"unknown"`` for slots whose
// /etc/spatiumddi/appliance-release can't be read; render those as
// ``"—"`` since the actual content isn't useful to the operator.
function slotVersionLabel(version: string | null | undefined): string {
  if (!version) return "—";
  if (
    version === "unstamped" ||
    version === "unreadable" ||
    version === "unknown"
  ) {
    return "—";
  }
  return version;
}

// Pick the per-slot version off the row by slot name. Keeps the
// callers small + flat (one ternary instead of mismatched lookups).
function rowSlotVersion(
  row: Pick<ApplianceRow, "slot_a_version" | "slot_b_version">,
  slot: "slot_a" | "slot_b",
): string {
  return slotVersionLabel(
    slot === "slot_a" ? row.slot_a_version : row.slot_b_version,
  );
}

// Compact two-line slot column for the appliances list. One line per
// slot, each carrying the version + a tiny chip for the booted /
// default role. Hidden entirely on docker / k8s rows where the A/B
// partition layout doesn't exist.
function ApplianceSlotsCell({ row }: { row: ApplianceRow }) {
  if (row.deployment_kind && row.deployment_kind !== "appliance") {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  if (!row.slot_a_version && !row.slot_b_version) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  return (
    <div className="flex flex-col gap-0.5 text-xs">
      {(["slot_a", "slot_b"] as const).map((slot) => {
        const isBooted = row.current_slot === slot;
        const isDefault = row.durable_default === slot;
        return (
          <div key={slot} className="flex items-center gap-1.5">
            <span className="font-mono text-muted-foreground">
              {slotLabel(slot)}
            </span>
            <span className="font-mono">{rowSlotVersion(row, slot)}</span>
            {isBooted && (
              <span className="rounded-full bg-emerald-500/10 px-1.5 py-0 text-[10px] font-medium uppercase text-emerald-700 dark:text-emerald-300">
                run
              </span>
            )}
            {isDefault && !isBooted && (
              <span className="rounded-full bg-blue-500/10 px-1.5 py-0 text-[10px] font-medium uppercase text-blue-700 dark:text-blue-300">
                def
              </span>
            )}
          </div>
        );
      })}
      {row.is_trial_boot && (
        <span className="rounded-full bg-amber-500/10 px-1.5 py-0 text-[10px] font-medium uppercase text-amber-700 dark:text-amber-300">
          trial boot
        </span>
      )}
      {row.k3s_version && (
        <span
          className="rounded-full bg-sky-500/10 px-1.5 py-0 font-mono text-[10px] text-sky-700 dark:text-sky-300"
          title={
            row.cluster_health?.kubeapi_ready
              ? `k3s ready · ${row.cluster_health?.nodes_ready ?? 0}/${row.cluster_health?.nodes_total ?? 0} nodes`
              : "k3s baked, kubeapi unreachable"
          }
        >
          k3s {row.k3s_version}
        </span>
      )}
    </div>
  );
}

// Per-slot card shown in the Fleet drilldown's OS & lifecycle
// section — two of these render side-by-side (slot A on the left,
// slot B on the right) carrying the version installed on the slot
// + role badges + action buttons. Mirrors the local-appliance OS
// Image card's ``SlotCardView`` styling so the visual language is
// the same on both surfaces.
//
// Action buttons fire the heartbeat-pickup pipeline:
//   * "Boot once"     → POST /set-next-boot      (grub-reboot, one-shot)
//   * "Set as default" → POST /set-default-slot   (grub-set-default,
//                                                  durable)
function ApplianceSlotCard({
  row,
  slot,
  onSetNextBoot,
  onSetDefault,
  busyNextBoot,
  busyDefault,
}: {
  row: ApplianceRow;
  slot: "slot_a" | "slot_b";
  onSetNextBoot: () => void;
  onSetDefault: () => void;
  busyNextBoot: boolean;
  busyDefault: boolean;
}) {
  const isBooted = row.current_slot === slot;
  const isDefault = row.durable_default === slot;
  const isTrial = isBooted && row.is_trial_boot;
  const desiredNext = row.desired_next_boot_slot === slot;
  const desiredDefault = row.desired_default_slot === slot;
  const otherSlot = slot === "slot_a" ? "slot_b" : "slot_a";

  // Outer card colouring follows the most-relevant role so the pair
  // has visual rhythm at a glance.
  const borderClass = isTrial
    ? "border-amber-500/50 bg-amber-500/5"
    : isBooted
      ? "border-emerald-500/40 bg-emerald-500/5"
      : "border-border bg-muted/40";

  // One-line subtext explaining the slot's role in plain English.
  let subtext: string;
  if (isTrial) {
    subtext = `Trial boot — reverts to slot ${slotLabel(row.durable_default)} on next reboot unless committed.`;
  } else if (isBooted && isDefault) {
    subtext = "Active · this is where the appliance boots.";
  } else if (isDefault && !isBooted) {
    subtext = "Durable default · next normal reboot lands here.";
  } else if (isBooted) {
    subtext = "Active · trial state without durable backing.";
  } else {
    subtext = "Inactive · candidate for upgrades or trial boot.";
  }

  const version = rowSlotVersion(row, slot);

  return (
    <div
      className={cn(
        "flex flex-col rounded-md border p-2.5 text-xs",
        borderClass,
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="font-mono font-semibold">Slot {slotLabel(slot)}</div>
        <div className="flex flex-wrap items-center gap-1">
          {isBooted && (
            <span className="inline-flex items-center rounded-md bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-emerald-700 dark:text-emerald-300">
              Booted
            </span>
          )}
          {isDefault && (
            <span className="inline-flex items-center rounded-md bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-blue-700 dark:text-blue-300">
              Default
            </span>
          )}
          {isTrial && (
            <span className="inline-flex items-center rounded-md bg-yellow-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-yellow-700 dark:text-yellow-300">
              Trial
            </span>
          )}
        </div>
      </div>
      <div className="mt-1 font-mono text-[11px] text-muted-foreground">
        {version}
      </div>
      <div className="mt-1 text-[11px] text-muted-foreground">{subtext}</div>

      {/* Pending-intent banner. Auto-clears server-side once the
          supervisor reports the requested state landed. */}
      {(desiredNext || desiredDefault) && (
        <div className="mt-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-700 dark:text-amber-300">
          {desiredNext && (
            <div>
              Boot-once requested · supervisor will arm on next heartbeat.
            </div>
          )}
          {desiredDefault && (
            <div>
              Set-as-default requested · supervisor will commit on next
              heartbeat.
            </div>
          )}
        </div>
      )}

      {/* Action buttons. Only render the option that's meaningful:
          - "Boot once" only when this is NOT the running slot
            (one-shot grub-reboot into the other slot)
          - "Set as default" only when this slot isn't already the
            durable default. Doubles as the trial-commit affordance. */}
      <div className="mt-2 flex flex-wrap gap-1.5">
        {!isBooted && (
          <button
            type="button"
            onClick={onSetNextBoot}
            disabled={busyNextBoot || desiredNext}
            title={`Boot slot ${slotLabel(slot)} on the next reboot (one-shot — auto-reverts to slot ${slotLabel(otherSlot)} after that boot unless committed).`}
            className="inline-flex items-center gap-1 rounded-md border border-input bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busyNextBoot ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <RotateCcw className="h-3 w-3" />
            )}
            Boot once
          </button>
        )}
        {!isDefault && (
          <button
            type="button"
            onClick={onSetDefault}
            disabled={busyDefault || desiredDefault}
            title={
              isTrial
                ? `Commit this trial boot as durable (grub-set-default ${slot}).`
                : `Make slot ${slotLabel(slot)} the durable default boot.`
            }
            className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 text-[11px] text-emerald-700 hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50 dark:text-emerald-300"
          >
            {busyDefault ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <CheckCircle2 className="h-3 w-3" />
            )}
            {isTrial ? "Approve trial" : "Set as default"}
          </button>
        )}
      </div>
    </div>
  );
}

// #386 Part C — the ordered phases a slot upgrade walks through, for the
// Fleet drilldown's status stepper. ``done`` / ``failed`` are terminal
// states carried on ``last_upgrade_state``, not stepper rows.
const UPGRADE_STEPS: { key: ApplianceUpgradeStep; label: string }[] = [
  { key: "queued", label: "Queued" },
  { key: "downloading", label: "Downloading image" },
  { key: "verifying", label: "Verifying checksum" },
  { key: "writing", label: "Writing to inactive slot" },
  { key: "bootloader", label: "Updating bootloader" },
  { key: "arming", label: "Arming next-boot" },
  { key: "reboot-pending", label: "Reboot to boot the new slot" },
];

function UpgradeLogTail({ text }: { text: string }) {
  return (
    <details className="mt-2">
      <summary className="cursor-pointer select-none text-muted-foreground hover:text-foreground">
        <FileText className="mr-1 inline h-3 w-3" />
        Show upgrade log
      </summary>
      <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded bg-muted/60 p-2 font-mono text-[10px] leading-tight">
        {text}
      </pre>
    </details>
  );
}

/**
 * #386 Part C — full upgrade status for the Fleet drilldown. Driven by
 * the supervisor-shipped ``last_upgrade_progress`` (per-phase step + %)
 * + ``last_upgrade_log_tail`` + ``last_upgrade_state``. Renders three
 * shapes: a red failure card (with the reason + log), a live stepper
 * while an apply is downloading / writing / etc., and a green
 * "staged — reboot to finish" card once next-boot is armed.
 */
function UpgradeStatusPanel({
  row,
  onCancel,
  cancelPending,
  onReboot,
}: {
  row: ApplianceRow;
  onCancel: () => void;
  cancelPending: boolean;
  onReboot: () => void;
}) {
  const progress = row.last_upgrade_progress;
  const state = row.last_upgrade_state;
  const failed = state === "failed" || progress?.step === "failed";
  const target = row.desired_appliance_version;
  // A supervisor older than the #386 (2026.06.12) upgrade-progress telemetry
  // never reports last_upgrade_progress, so without this the panel sits on
  // "pending" forever even after the trigger fired. Detect it from the
  // reported version (CalVer sorts lexicographically) and say so honestly
  // rather than promising a fire "in ≤30s" that already happened.
  const supVer = row.supervisor_version ?? row.installed_appliance_version;
  const predatesProgress =
    !!supVer && /^\d{4}\.\d{2}\.\d{2}/.test(supVer) && supVer < "2026.06.12";

  if (failed) {
    return (
      <div className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/5 p-3 text-xs">
        <div className="flex items-center gap-2">
          <AlertCircle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
          <span className="font-medium">Upgrade failed</span>
          {target && (
            <code className="ml-auto rounded bg-muted px-1.5 py-0.5 text-[10px]">
              → {target}
            </code>
          )}
        </div>
        <p className="mt-1 text-rose-700 dark:text-rose-300">
          {progress?.detail || "The slot apply failed."} See the log for the
          cause, fix it, then re-apply.
        </p>
        {row.last_upgrade_log_tail && (
          <UpgradeLogTail text={row.last_upgrade_log_tail} />
        )}
        <button
          type="button"
          onClick={onCancel}
          disabled={cancelPending}
          className="mt-2 inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:opacity-50"
        >
          {cancelPending ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <XCircle className="h-3 w-3" />
          )}
          Clear failed upgrade
        </button>
      </div>
    );
  }

  const rebootPending = progress?.step === "reboot-pending" || state === "done";
  // Where are we? -1 = desired set but no progress reported yet (the
  // supervisor hasn't fired the trigger). Otherwise the index of the
  // current phase in UPGRADE_STEPS.
  const stepIndex = progress
    ? UPGRADE_STEPS.findIndex((s) => s.key === progress.step)
    : -1;
  // #421 — complementary stuck hint. A live runner re-stamps the
  // in-flight marker every ~60s, so the supervisor reaps a dead/stalled
  // apply to "failed" within ~5 min (→ the red card above). If we're
  // STILL amber well past that, the supervisor's own backstop isn't
  // running (e.g. the supervisor is down) — say "looks stuck" rather than
  // spin a spinner forever. The Cancel button below already lets the
  // operator clear + re-apply. Never trips on a live apply: the stamp
  // keeps advancing so this stays small regardless of apply duration.
  const inFlightMs =
    state === "in-flight" && row.last_upgrade_state_at
      ? Date.now() - new Date(row.last_upgrade_state_at).getTime()
      : 0;
  const looksStuck = !rebootPending && inFlightMs > 6 * 60_000;

  return (
    <div
      className={cn(
        "mt-3 rounded-md border p-3 text-xs",
        rebootPending
          ? "border-emerald-500/40 bg-emerald-500/5"
          : "border-amber-500/40 bg-amber-500/5",
      )}
    >
      <div className="flex items-center gap-2">
        {rebootPending ? (
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
        ) : (
          <Loader2 className="h-3.5 w-3.5 animate-spin text-amber-600 dark:text-amber-400" />
        )}
        <span className="font-medium">
          {rebootPending
            ? "Upgrade staged — reboot to finish"
            : stepIndex === -1
              ? "Upgrade pending"
              : "Upgrade in progress"}
        </span>
        {target && (
          <code className="ml-auto rounded bg-muted px-1.5 py-0.5 text-[10px]">
            → {target}
          </code>
        )}
      </div>

      {stepIndex === -1 &&
        (predatesProgress ? (
          <p className="mt-1 text-muted-foreground">
            This appliance&rsquo;s supervisor (<code>{supVer}</code>) predates
            live upgrade-progress reporting, so this dashboard can&rsquo;t show
            the trigger&rsquo;s status &mdash; the upgrade may already have
            fired. Verify on the host (<code>spatium-upgrade-slot status</code>,{" "}
            <code>journalctl -u spatiumddi-slot-upgrade</code>) or apply the
            slot image by hand, then reboot. Live progress appears here once the
            appliance is on &ge; 2026.06.12.
          </p>
        ) : (
          <p className="mt-1 text-muted-foreground">
            Supervisor will fire the slot-upgrade trigger on its next heartbeat
            (&le; 30 s). If it stays here, check{" "}
            <code>journalctl -u spatiumddi-slot-upgrade</code> on the host.
          </p>
        ))}

      <ol className="mt-2 space-y-1">
        {UPGRADE_STEPS.map((s, i) => {
          const done =
            i < stepIndex || (rebootPending && s.key !== "reboot-pending");
          const active = !rebootPending && i === stepIndex;
          const rebootCta = rebootPending && s.key === "reboot-pending";
          return (
            <li key={s.key} className="flex items-center gap-2">
              {done ? (
                <CheckCircle2 className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
              ) : active ? (
                <Loader2 className="h-3 w-3 animate-spin text-amber-600 dark:text-amber-400" />
              ) : rebootCta ? (
                <Power className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <span className="inline-block h-3 w-3 rounded-full border border-muted-foreground/40" />
              )}
              <span
                className={cn(
                  done || rebootCta
                    ? "text-foreground"
                    : active
                      ? "font-medium text-foreground"
                      : "text-muted-foreground",
                )}
              >
                {s.label}
              </span>
              {active && progress?.pct != null && (
                <span className="ml-auto tabular-nums text-muted-foreground">
                  {progress.pct}%
                </span>
              )}
            </li>
          );
        })}
      </ol>

      {progress?.detail && !rebootPending && (
        <p
          className="mt-2 truncate text-muted-foreground"
          title={progress.detail}
        >
          {progress.detail}
        </p>
      )}
      {progress?.step === "downloading" && progress.pct != null && (
        <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full bg-amber-500 transition-all"
            style={{ width: `${Math.min(100, Math.max(0, progress.pct))}%` }}
          />
        </div>
      )}

      {looksStuck && (
        <p className="mt-2 flex items-start gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-[11px] text-amber-800 dark:text-amber-200">
          <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" />
          <span>
            In progress for {Math.round(inFlightMs / 60_000)} min — a real apply
            finishes in seconds to minutes. It looks stuck. Check the host (
            <code>journalctl -u spatiumddi-slot-upgrade</code>,{" "}
            <code>spatium-upgrade-slot status</code>), or cancel and re-apply.
          </span>
        </p>
      )}

      {row.last_upgrade_log_tail && (
        <UpgradeLogTail text={row.last_upgrade_log_tail} />
      )}

      <div className="mt-2 flex flex-wrap gap-2">
        {rebootPending && (
          <button
            type="button"
            onClick={onReboot}
            className="inline-flex items-center gap-1 rounded-md border border-emerald-500/50 bg-emerald-500/10 px-2 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-500/20 dark:text-emerald-300"
          >
            <Power className="h-3 w-3" /> Reboot to boot new slot
          </button>
        )}
        {target && (
          <button
            type="button"
            onClick={onCancel}
            disabled={cancelPending}
            className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:opacity-50"
          >
            {cancelPending ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <XCircle className="h-3 w-3" />
            )}
            Cancel pending upgrade
          </button>
        )}
      </div>
    </div>
  );
}

function ApplianceOsUpgradeSection({
  row,
  onViewUpgradeImages,
}: {
  row: ApplianceRow;
  onViewUpgradeImages?: () => void;
}) {
  const qc = useQueryClient();
  const [sourceKind, setSourceKind] = useState<"url" | "uploaded">("uploaded");
  const [tag, setTag] = useState("");
  const [imageUrl, setImageUrl] = useState("");
  const [slotImageId, setSlotImageId] = useState<string>("");
  const [rebootConfirm, setRebootConfirm] = useState(false);

  const isApplianceHost =
    row.deployment_kind === "appliance" || row.deployment_kind === null;
  const upgradeInFlight = row.desired_appliance_version !== null;
  // #386 Part C — show the full status panel whenever there's upgrade
  // activity: a pending/in-flight desired version, or a terminal
  // in-flight/failed state the supervisor is still reporting.
  const showUpgradeStatus =
    upgradeInFlight ||
    row.last_upgrade_state === "in-flight" ||
    row.last_upgrade_state === "failed";

  // Staged upgrade images — fetched only when the operator picks the
  // ``uploaded`` source, so non-air-gapped flows skip the round trip.
  const uploadedQuery = useQuery({
    queryKey: ["appliance", "upgrade-images"],
    queryFn: applianceUpgradeImagesApi.list,
    staleTime: 30_000,
    enabled: isApplianceHost,
  });

  // When the operator picks an uploaded image, auto-fill the version
  // tag from the row's appliance_version. Saves them re-typing it +
  // keeps the supervisor's auto-clear logic aligned with the bytes.
  function pickUploadedImage(id: string) {
    setSlotImageId(id);
    const image = uploadedQuery.data?.find((i) => i.id === id);
    if (image) setTag(image.appliance_version);
  }

  // #1026 — an image built for another architecture would download,
  // verify, write and then not boot. The server refuses it (422) and
  // the host runner refuses it again on the real bytes; this is the
  // third gate, and the only one that saves the operator the round
  // trip.
  //
  // DISABLED IN PLACE rather than filtered out of the list. An image an
  // operator uploaded a minute ago silently missing from the picker
  // reads as a bug in the upload, which is exactly the wrong place to
  // send them looking. Both unknowns fall through as selectable: null
  // means we do not know, and refusing on "do not know" would block
  // every image staged before this field existed.
  function imageArchMismatch(img: UpgradeImage): boolean {
    return (
      !!row.architecture &&
      !!img.architecture &&
      row.architecture !== img.architecture
    );
  }

  const scheduleUpgrade = useMutation({
    mutationFn: () =>
      applianceApprovalApi.scheduleUpgrade(
        row.id,
        tag.trim(),
        sourceKind === "url"
          ? { kind: "url", url: imageUrl.trim() }
          : { kind: "uploaded", slot_image_id: slotImageId },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setTag("");
      setImageUrl("");
      setSlotImageId("");
    },
  });
  const clearUpgrade = useMutation({
    mutationFn: () => applianceApprovalApi.clearUpgrade(row.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appliance", "fleet"] }),
  });
  const setNextBoot = useMutation({
    mutationFn: (slot: "slot_a" | "slot_b") =>
      applianceApprovalApi.setNextBootSlot(row.id, slot),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appliance", "fleet"] }),
  });
  const setDefault = useMutation({
    mutationFn: (slot: "slot_a" | "slot_b") =>
      applianceApprovalApi.setDefaultSlot(row.id, slot),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["appliance", "fleet"] }),
  });
  const reboot = useMutation({
    mutationFn: () => applianceApprovalApi.scheduleReboot(row.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setRebootConfirm(false);
    },
  });

  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        OS &amp; lifecycle
      </h3>
      <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-xs">
        <dt className="text-muted-foreground">Deployment</dt>
        <dd>
          <span className="rounded-full bg-muted px-1.5 py-0.5 font-mono text-[10px]">
            {row.deployment_kind ?? "unknown"}
          </span>
        </dd>
        <dt className="text-muted-foreground">Last upgrade</dt>
        <dd>
          {row.last_upgrade_state ? (
            <span
              className={cn(
                "rounded-full px-1.5 py-0.5 font-mono text-[10px]",
                row.last_upgrade_state === "done" ||
                  row.last_upgrade_state === "ready"
                  ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                  : row.last_upgrade_state === "failed"
                    ? "bg-rose-500/10 text-rose-700 dark:text-rose-300"
                    : "bg-amber-500/10 text-amber-700 dark:text-amber-300",
              )}
            >
              {row.last_upgrade_state}
            </span>
          ) : (
            "—"
          )}
          {row.last_upgrade_state_at && (
            <span className="ml-2 text-muted-foreground">
              {new Date(row.last_upgrade_state_at).toLocaleString()}
            </span>
          )}
        </dd>
      </dl>

      {/* Per-slot version + boot-control cards. Two cards side-by-
          side carry the version installed on each A/B slot plus
          action buttons that ride the heartbeat-pickup pipeline. */}
      {isApplianceHost && (
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {(["slot_a", "slot_b"] as const).map((slot) => (
            <ApplianceSlotCard
              key={slot}
              row={row}
              slot={slot}
              onSetNextBoot={() => setNextBoot.mutate(slot)}
              onSetDefault={() => setDefault.mutate(slot)}
              busyNextBoot={
                setNextBoot.isPending && setNextBoot.variables === slot
              }
              busyDefault={
                setDefault.isPending && setDefault.variables === slot
              }
            />
          ))}
        </div>
      )}
      {(setNextBoot.error || setDefault.error) && (
        <p className="mt-1 text-xs text-rose-700 dark:text-rose-300">
          {((setNextBoot.error ?? setDefault.error) as Error).message}
        </p>
      )}

      {!isApplianceHost ? (
        <p className="mt-3 text-xs text-muted-foreground">
          OS slot upgrades + host reboot are only available on the SpatiumDDI
          appliance OS. Use the docker compose / helm upgrade flow for{" "}
          <code>{row.deployment_kind}</code> deployments.
        </p>
      ) : showUpgradeStatus ? (
        <UpgradeStatusPanel
          row={row}
          onCancel={() => clearUpgrade.mutate()}
          cancelPending={clearUpgrade.isPending}
          onReboot={() => setRebootConfirm(true)}
        />
      ) : (
        <div className="mt-3 space-y-2">
          {/* Source picker — uploaded image (air-gap-friendly) vs
              external URL (lab / direct internet appliances). */}
          <div className="flex gap-1 text-xs">
            <button
              type="button"
              onClick={() => setSourceKind("uploaded")}
              className={cn(
                "rounded-md border px-2 py-1",
                sourceKind === "uploaded"
                  ? "border-primary bg-primary/10"
                  : "border-input bg-background text-muted-foreground hover:bg-muted",
              )}
            >
              From uploaded image
            </button>
            <button
              type="button"
              onClick={() => setSourceKind("url")}
              className={cn(
                "rounded-md border px-2 py-1",
                sourceKind === "url"
                  ? "border-primary bg-primary/10"
                  : "border-input bg-background text-muted-foreground hover:bg-muted",
              )}
            >
              From external URL
            </button>
          </div>
          {sourceKind === "uploaded" ? (
            <>
              <select
                value={slotImageId}
                onChange={(e) => pickUploadedImage(e.target.value)}
                className="w-full rounded-md border bg-background px-2 py-1 text-xs"
              >
                <option value="">(pick an uploaded image)</option>
                {(uploadedQuery.data ?? []).map((img) => (
                  <option
                    key={img.id}
                    value={img.id}
                    disabled={imageArchMismatch(img)}
                  >
                    {img.filename} · v{img.appliance_version} ·{" "}
                    {img.architecture ?? "arch unknown"} ·{" "}
                    {(img.size_bytes / (1024 * 1024)).toFixed(0)} MiB
                    {imageArchMismatch(img)
                      ? ` — needs ${row.architecture}`
                      : ""}
                  </option>
                ))}
              </select>
              {uploadedQuery.data && uploadedQuery.data.length === 0 && (
                <p className="text-[11px] text-muted-foreground">
                  No upgrade images uploaded yet.{" "}
                  {onViewUpgradeImages ? (
                    <button
                      type="button"
                      onClick={onViewUpgradeImages}
                      className="font-medium text-primary underline-offset-2 hover:underline"
                    >
                      Go to Upgrade images →
                    </button>
                  ) : (
                    <>
                      Open <strong>Fleet → Upgrade images</strong> to upload or
                      import one.
                    </>
                  )}
                </p>
              )}
              <input
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                placeholder="target version (auto-filled from the picked image)"
                className="w-full rounded-md border bg-background px-2 py-1 text-xs"
              />
            </>
          ) : (
            <div className="flex flex-col gap-1.5 sm:flex-row">
              <input
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                placeholder="target version (e.g. 2026.06.01-1)"
                className="flex-1 rounded-md border bg-background px-2 py-1 text-xs"
              />
              <input
                value={imageUrl}
                onChange={(e) => setImageUrl(e.target.value)}
                placeholder="slot raw.xz URL"
                className="flex-[2] rounded-md border bg-background px-2 py-1 text-xs"
              />
            </div>
          )}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => scheduleUpgrade.mutate()}
              disabled={
                !tag.trim() ||
                scheduleUpgrade.isPending ||
                (sourceKind === "url" && !imageUrl.trim()) ||
                (sourceKind === "uploaded" && !slotImageId)
              }
              className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-50"
            >
              {scheduleUpgrade.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <HardDrive className="h-3.5 w-3.5" />
              )}
              Schedule OS upgrade
            </button>
            {scheduleUpgrade.error && (
              <span className="text-xs text-rose-700 dark:text-rose-300">
                {formatApiError(scheduleUpgrade.error)}
              </span>
            )}
          </div>
          <p className="text-[11px] text-muted-foreground">
            Stamps <code>desired_appliance_version</code> on the appliance row.
            The supervisor reads it on its next heartbeat + writes the
            slot-upgrade trigger; the host runner dd&apos;s the image to the
            inactive slot + reboots into it (auto-revert if{" "}
            <code>/health/live</code> fails).
          </p>
        </div>
      )}

      {isApplianceHost && (
        <div className="mt-3 flex items-center gap-2 border-t pt-3">
          {row.reboot_requested ? (
            <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-700 dark:text-amber-300">
              reboot queued
            </span>
          ) : null}
          <button
            type="button"
            onClick={() => setRebootConfirm(true)}
            disabled={row.reboot_requested}
            className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Power className="h-3.5 w-3.5" />
            Reboot host
          </button>
          {reboot.error && (
            <span className="text-xs text-rose-700 dark:text-rose-300">
              {formatApiError(reboot.error)}
            </span>
          )}
        </div>
      )}

      {rebootConfirm && (
        <ConfirmModal
          open
          title="Reboot appliance host?"
          message={
            <>
              <p className="text-sm">
                Reboot <strong>{row.hostname}</strong>? The supervisor will pick
                this up on its next heartbeat (≤ 30 s) and the host will drop
                offline for ~30–60 s while it restarts.
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                Use sparingly. Service containers will be brought back up by the
                supervisor on the next boot.
              </p>
            </>
          }
          confirmLabel="Reboot"
          tone="destructive"
          loading={reboot.isPending}
          onConfirm={() => reboot.mutate()}
          onClose={() => setRebootConfirm(false)}
          requireCheckboxLabel={`I understand ${row.hostname} will go offline for ~30–60 s`}
        />
      )}
    </div>
  );
}

// #1026 — a release that publishes an image for both architectures is
// TWO importable rows sharing one tag, so the picker's value has to
// carry the architecture as well. Keyed on both rather than on an array
// index, which would silently re-point at a different release the
// moment the list refreshed underneath the operator.
function availableKey(r: AvailableUpgradeImage): string {
  return `${r.tag}\u0000${r.architecture}`;
}

function splitAvailableKey(key: string): [string, string | undefined] {
  const [tag, arch] = key.split("\u0000");
  return [tag, arch || undefined];
}

// ── UpgradeImageManager (#170 follow-up; GitHub import + air-gap
// upload — #199) ──────────────────────────────────────────────────

type UpgradeSourceMode = "github" | "upload";

function UpgradeImageManager() {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [sha256, setSha256] = useState("");
  const [applianceVersion, setApplianceVersion] = useState("");
  // #1026 — declared, like the version beside it. Empty means UNKNOWN
  // and is a legitimate answer: the control-plane gate then does not
  // block, and ``spatium-upgrade-slot`` still re-checks the real
  // decompressed image against the node's own uname before it writes.
  const [architecture, setArchitecture] = useState("");
  const [notes, setNotes] = useState("");
  const [progress, setProgress] = useState<{
    loaded: number;
    total: number;
  } | null>(null);
  // GitHub-import picker state.
  const [selectedTag, setSelectedTag] = useState("");
  // ``null`` = auto-detect once the ``available`` query resolves:
  // GitHub if reachable + has matching releases, else air-gap upload.
  const [mode, setMode] = useState<UpgradeSourceMode | null>(null);
  // Upgrade images are heavy (typically ~700 MiB raw.xz) and a misclick
  // wipes the only on-server copy of an air-gap-cached release — gate
  // the delete behind a typed-confirm modal.
  const [deleteTarget, setDeleteTarget] = useState<UpgradeImage | null>(null);

  const imagesQuery = useQuery({
    queryKey: ["appliance", "upgrade-images"],
    queryFn: applianceUpgradeImagesApi.list,
    staleTime: 30_000,
  });

  // Connected-install picker source. Empty / unreachable ⇒ the UI
  // auto-defaults to the air-gap upload tab.
  const availableQuery = useQuery({
    queryKey: ["appliance", "upgrade-images", "available"],
    queryFn: applianceUpgradeImagesApi.listAvailable,
    staleTime: 60_000,
  });
  const available = availableQuery.data?.available ?? [];
  const githubReachable = availableQuery.data?.github_reachable ?? false;
  const effectiveMode: UpgradeSourceMode =
    mode ?? (githubReachable && available.length > 0 ? "github" : "upload");

  // Default-select the newest available tag once the list lands.
  useEffect(() => {
    if (!selectedTag && available.length > 0)
      setSelectedTag(availableKey(available[0]));
  }, [available, selectedTag]);

  const upload = useMutation({
    mutationFn: () =>
      applianceUpgradeImagesApi.upload(
        file!,
        sha256.trim().toLowerCase(),
        applianceVersion.trim(),
        notes.trim() || undefined,
        (loaded, total) => setProgress({ loaded, total }),
        architecture || undefined,
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "upgrade-images"] });
      setFile(null);
      setSha256("");
      setApplianceVersion("");
      setArchitecture("");
      setNotes("");
      setProgress(null);
    },
    onError: () => setProgress(null),
  });

  const importGithub = useMutation({
    mutationFn: () => {
      const [tag, arch] = splitAvailableKey(selectedTag);
      return applianceUpgradeImagesApi.importFromGithub(tag, arch);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "upgrade-images"] });
    },
  });

  const remove = useMutation({
    mutationFn: (id: string) => applianceUpgradeImagesApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance", "upgrade-images"] });
      setDeleteTarget(null);
    },
  });

  return (
    <div className="space-y-3 text-xs">
      <p className="text-muted-foreground">
        Connected installs import the upgrade image straight from a GitHub
        release — the control plane downloads + verifies it for you. Air-gapped
        installs download the <code>.raw.xz</code> + its <code>.sha256</code>{" "}
        sidecar out-of-band and upload it here. Either way the backend verifies
        the SHA-256 before storing, and the appliance pulls through the control
        plane via an authenticated internal URL when an OS upgrade is scheduled.
      </p>

      {/* Source toggle — auto-defaults to GitHub when reachable. */}
      <div className="inline-flex rounded-md border p-0.5">
        <button
          type="button"
          onClick={() => setMode("github")}
          className={cn(
            "rounded px-3 py-1",
            effectiveMode === "github"
              ? "bg-primary/10 font-medium text-primary"
              : "text-muted-foreground hover:bg-muted",
          )}
        >
          Pick from GitHub Releases
        </button>
        <button
          type="button"
          onClick={() => setMode("upload")}
          className={cn(
            "rounded px-3 py-1",
            effectiveMode === "upload"
              ? "bg-primary/10 font-medium text-primary"
              : "text-muted-foreground hover:bg-muted",
          )}
        >
          Upload (air-gap)
        </button>
      </div>

      {effectiveMode === "github" ? (
        <div className="rounded-md border p-3">
          {availableQuery.isLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking GitHub
              releases…
            </div>
          ) : !githubReachable ? (
            <p className="text-muted-foreground">
              GitHub isn&apos;t reachable from the control plane. Use the{" "}
              <strong>Upload (air-gap)</strong> tab instead.
            </p>
          ) : available.length === 0 ? (
            <p className="text-muted-foreground">
              No recent GitHub release carries an importable appliance upgrade
              image yet.
            </p>
          ) : (
            <div className="space-y-3">
              <div>
                <label className="text-muted-foreground">Release</label>
                <select
                  value={selectedTag}
                  onChange={(e) => setSelectedTag(e.target.value)}
                  className="mt-1 w-full rounded-md border bg-background px-2 py-1"
                >
                  {available.map((r) => (
                    <option key={availableKey(r)} value={availableKey(r)}>
                      {r.tag}
                      {` · ${r.architecture}`}
                      {r.is_prerelease ? " (pre-release)" : ""}
                      {r.is_installed ? " · installed" : ""}
                      {r.size_bytes
                        ? ` · ${(r.size_bytes / (1024 * 1024)).toFixed(0)} MiB`
                        : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => importGithub.mutate()}
                  disabled={!selectedTag || importGithub.isPending}
                  className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {importGithub.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <DownloadCloud className="h-3.5 w-3.5" />
                  )}
                  Import
                </button>
                {importGithub.isPending && (
                  <span className="text-[11px] text-muted-foreground">
                    Downloading + verifying on the control plane — this can take
                    a few minutes for a ~700 MiB image.
                  </span>
                )}
                {importGithub.error && (
                  <span className="text-rose-700 dark:text-rose-300">
                    {formatApiError(importGithub.error)}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="rounded-md border p-3">
          <div className="grid gap-2 sm:grid-cols-2">
            <div>
              <label className="text-muted-foreground">.raw.xz file</label>
              <input
                type="file"
                accept=".xz,.raw.xz,application/octet-stream"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                className="mt-1 block w-full text-xs"
              />
              {file && (
                <p className="mt-1 text-[11px] text-muted-foreground">
                  {file.name} · {(file.size / (1024 * 1024)).toFixed(1)} MiB
                </p>
              )}
            </div>
            <div>
              <label className="text-muted-foreground">Appliance version</label>
              <input
                value={applianceVersion}
                onChange={(e) => setApplianceVersion(e.target.value)}
                placeholder="e.g. 2026.06.01-1"
                className="mt-1 w-full rounded-md border bg-background px-2 py-1"
              />
            </div>
            <div>
              <label className="text-muted-foreground">Architecture</label>
              <select
                value={architecture}
                onChange={(e) => setArchitecture(e.target.value)}
                className="mt-1 w-full rounded-md border bg-background px-2 py-1"
              >
                <option value="">Unknown (don't check)</option>
                <option value="amd64">amd64 (x86-64)</option>
                <option value="arm64">arm64 (AArch64)</option>
              </select>
              <p className="mt-1 text-[11px] text-muted-foreground">
                From the asset name you downloaded. Lets the control plane
                refuse this image for a node of the other architecture before
                scheduling; the appliance re-checks the real image either way.
              </p>
            </div>
            <div className="sm:col-span-2">
              <label className="text-muted-foreground">SHA-256 (hex)</label>
              <input
                value={sha256}
                onChange={(e) => setSha256(e.target.value)}
                placeholder="paste from the .sha256 sidecar (64 lowercase hex chars)"
                className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="text-muted-foreground">Notes (optional)</label>
              <input
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="e.g. RC1 — verified by ops on 2026-06-01"
                className="mt-1 w-full rounded-md border bg-background px-2 py-1"
              />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <button
              type="button"
              onClick={() => upload.mutate()}
              disabled={
                !file ||
                sha256.trim().length !== 64 ||
                !applianceVersion.trim() ||
                upload.isPending
              }
              className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {upload.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Upload className="h-3.5 w-3.5" />
              )}
              Upload
            </button>
            {progress && progress.total > 0 && (
              <span className="text-[11px] text-muted-foreground">
                {((progress.loaded / progress.total) * 100).toFixed(0)}% ·{" "}
                {(progress.loaded / (1024 * 1024)).toFixed(1)} /{" "}
                {(progress.total / (1024 * 1024)).toFixed(1)} MiB
              </span>
            )}
            {upload.error && (
              <span className="text-rose-700 dark:text-rose-300">
                {formatApiError(upload.error)}
              </span>
            )}
          </div>
        </div>
      )}

      {imagesQuery.isLoading ? (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
        </div>
      ) : (imagesQuery.data ?? []).length === 0 ? (
        <p className="text-muted-foreground">No uploaded upgrade images yet.</p>
      ) : (
        <table className="w-full">
          <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-2 py-1 text-left">Filename</th>
              <th className="px-2 py-1 text-left">Version</th>
              <th className="px-2 py-1 text-left">Size</th>
              <th className="px-2 py-1 text-left">SHA-256</th>
              <th className="px-2 py-1 text-left">Uploaded</th>
              <th className="px-2 py-1 text-right"></th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {(imagesQuery.data ?? []).map((img: UpgradeImage) => (
              <tr key={img.id}>
                <td className="px-2 py-1">
                  <div className="font-medium">{img.filename}</div>
                  {img.notes && (
                    <div className="text-[11px] text-muted-foreground">
                      {img.notes}
                    </div>
                  )}
                </td>
                <td className="px-2 py-1 font-mono">{img.appliance_version}</td>
                <td className="px-2 py-1 font-mono">
                  {(img.size_bytes / (1024 * 1024)).toFixed(0)} MiB
                </td>
                <td className="px-2 py-1 font-mono">
                  {img.sha256.slice(0, 12)}…{img.sha256.slice(-6)}
                </td>
                <td className="px-2 py-1">{relativeTime(img.uploaded_at)}</td>
                <td className="px-2 py-1 text-right">
                  <button
                    type="button"
                    onClick={() => setDeleteTarget(img)}
                    className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-0.5 hover:bg-muted"
                  >
                    <Trash2 className="h-3 w-3" />
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {deleteTarget && (
        <ConfirmModal
          open
          title="Delete upgrade image?"
          message={
            <>
              <p className="text-sm">
                Delete the staged <code>.raw.xz</code> for{" "}
                <strong>{deleteTarget.appliance_version}</strong>? The on-server
                copy is removed and any in-flight OS upgrade pointing at it will
                fail with a 404 on the next fetch. Re-staging it (upload or
                GitHub import) is operator-effort — typically a few hundred MiB.
              </p>
              {deleteTarget.notes && (
                <p className="mt-2 text-xs text-muted-foreground">
                  Notes:{" "}
                  <span className="text-foreground">{deleteTarget.notes}</span>
                </p>
              )}
              <p className="mt-2 text-xs text-muted-foreground">
                SHA-256:{" "}
                <code className="text-foreground">
                  {deleteTarget.sha256.slice(0, 12)}…
                  {deleteTarget.sha256.slice(-6)}
                </code>
              </p>
            </>
          }
          confirmLabel="Delete"
          tone="destructive"
          loading={remove.isPending}
          onConfirm={() => remove.mutate(deleteTarget.id)}
          onClose={() => setDeleteTarget(null)}
        />
      )}
    </div>
  );
}

// ── PortConflictBanner (#170 Phase E2) ──────────────────────────

// Map a role-chip token to the heartbeat-body keys it would bind.
// Mirrors the supervisor's role_orchestrator probe list so the banner
// only fires when there's a conflict on a port the operator's picked
// role would actually need.
const _ROLE_PORT_KEYS: Record<string, string[]> = {
  "dns-bind9": ["udp_53", "tcp_53"],
  "dns-powerdns": ["udp_53", "tcp_53"],
  "dns-technitium": ["udp_53", "tcp_53"],
  dhcp: ["udp_67"],
  "looking-glass": ["tcp_179"],
};

function _formatPortKey(key: string): string {
  // udp_53 → "UDP/53", tcp_53 → "TCP/53"
  const [proto, port] = key.split("_", 2);
  return `${proto.toUpperCase()}/${port}`;
}

function PortConflictBanner({
  row,
  roles,
}: {
  row: ApplianceRow;
  roles: Set<string>;
}) {
  const conflicts = row.port_conflicts ?? {};
  // Surface only conflicts on a port a currently-picked role would
  // bind. Operators on idle appliances don't care about a stray UDP/53
  // listener; they care once they assign a DNS role.
  const relevant: { key: string; users: string }[] = [];
  for (const role of roles) {
    for (const key of _ROLE_PORT_KEYS[role] ?? []) {
      if (conflicts[key] && !relevant.some((r) => r.key === key)) {
        relevant.push({ key, users: conflicts[key] });
      }
    }
  }
  if (relevant.length === 0) return null;
  return (
    <div className="mt-4 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs">
      <div className="flex items-start gap-2">
        <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-rose-700 dark:text-rose-300" />
        <div>
          <p className="font-medium text-rose-700 dark:text-rose-300">
            Host port conflict — supervisor pre-flight failed
          </p>
          <p className="mt-1 text-muted-foreground">
            The supervisor probed{" "}
            {relevant.map((r, i) => (
              <span key={r.key}>
                {i > 0 ? ", " : ""}
                <code className="text-foreground">{_formatPortKey(r.key)}</code>
              </span>
            ))}{" "}
            and found a competing listener on the host. The service
            container&apos;s bind will silently lose to that daemon. SSH in +
            stop the conflicting process before applying the role assignment.
          </p>
          <ul className="mt-2 space-y-0.5 text-[11px]">
            {relevant.map((r) => (
              <li key={r.key} className="font-mono">
                {_formatPortKey(r.key)} → {r.users}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

// ── FirewallRefusalBanner (#593) ────────────────────────────────

/**
 * The supervisor refused to apply a firewall drop-in that would have closed
 * etcd's raft peer port on this node while k3s still labels it an etcd member.
 *
 * This is a row-vs-reality divergence: the control plane believes the node is
 * not a cluster member and keeps re-rendering a peer-less body from that belief.
 * The supervisor blocks it (a stale peer rule only over-permits to real cluster
 * members; applying the body would drop a voting member out of raft), but the
 * divergence itself only an operator can fix — hence a persistent banner rather
 * than a log line nobody reads.
 */
function FirewallRefusalBanner({ row }: { row: ApplianceRow }) {
  const state = row.firewall_state ?? {};
  if (state.state !== "refused_self_partition") return null;
  const source =
    state.source === "control-plane"
      ? "the control plane's rendered firewall"
      : "the locally rendered firewall";
  return (
    <div className="mt-4 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
      <div className="flex items-start gap-2">
        <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-700 dark:text-amber-300" />
        <div>
          <p className="font-medium text-amber-700 dark:text-amber-300">
            Firewall blocked — it would have partitioned this node from etcd
          </p>
          <p className="mt-1 text-muted-foreground">
            The supervisor rejected {source} because it did not open etcd&apos;s
            peer port, while k3s still reports this node as an etcd member. The
            node is running its last-good ruleset. This means this
            appliance&apos;s stored cluster role disagrees with the live cluster
            — re-check its role assignment, or clear a stuck cluster transition.
          </p>
          {state.reason ? (
            <p className="mt-2 font-mono text-[11px] text-muted-foreground">
              {state.reason}
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}

// ── RoleSwitchStateBanner (#170 Wave D follow-up) ───────────────

function RoleSwitchStateBanner({ row }: { row: ApplianceRow }) {
  const state = row.role_switch_state;
  // Null / idle = nothing to surface (operator hasn't assigned a
  // role yet, or the supervisor cleared the state). ``ready`` is the
  // happy path — a soft green chip; we don't need to shout.
  if (!state || state === "idle") return null;
  if (state === "ready") {
    return (
      <div className="mt-3 inline-flex items-center gap-2 rounded-full bg-emerald-500/10 px-3 py-1 text-xs text-emerald-700 dark:text-emerald-300">
        <CheckCircle2 className="h-3.5 w-3.5" />
        Service containers up — supervisor reports{" "}
        <code className="font-mono">role_switch_state=ready</code>.
      </div>
    );
  }
  // ``failed`` — operator needs to know what broke.
  return (
    <div className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs">
      <div className="flex items-start gap-2">
        <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-rose-700 dark:text-rose-300" />
        <div>
          <p className="font-medium text-rose-700 dark:text-rose-300">
            Service lifecycle apply failed
          </p>
          <p className="mt-1 text-muted-foreground">
            The supervisor's <code>docker compose</code> against the assigned
            role(s) returned a non-zero exit. The previous container state
            remains; SSH into the appliance to triage, or fix the underlying
            cause + the next heartbeat will retry automatically.
          </p>
          {row.role_switch_reason && (
            <p className="mt-2 font-mono text-[11px] text-foreground">
              {row.role_switch_reason}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
