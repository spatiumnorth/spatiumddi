import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  RefreshCcw,
  ShieldAlert,
  ToggleLeft,
} from "lucide-react";
import {
  featureModulesApi,
  formatApiError,
  type FeatureModuleEntry,
} from "@/lib/api";
import {
  APPROVAL_QUEUED_MESSAGE,
  CHANGE_REQUEST_QUERY_KEY,
  handleApprovalQueued,
} from "@/lib/approvalQueue";
import { NEEDS_SUPERADMIN, usePermissions } from "@/hooks/usePermissions";
import { resolveEnabled } from "@/hooks/useFeatureModules";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { useSessionState } from "@/lib/useSessionState";
import { cn } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { Toggle } from "@/components/ui/toggle";
import { BreakGlassModal } from "./BreakGlassModal";

// The module whose disable is gated by the #62 self-governance lock. Enabling
// it can opt into the lock; disabling it (when the lock is on) routes through
// the two-person approval queue.
const APPROVALS_MODULE_ID = "governance.approvals";

const headerCls =
  "flex shrink-0 items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50";

// Two tabs: Integrations, and everything else.
//
// The split is derived from the catalog, NOT from a hardcoded list of
// group names. It used to be a list, and it silently fell behind: the
// catalog grew DNS, DHCP, IPAM, Appliance and UI groups, none of which
// were named on either tab, so six modules — both DNS toggles, DHCP
// import, NetBox import, Fleet Firewall and Saved views — rendered on
// neither tab and were untoggleable anywhere in the product. That is
// load-bearing now: #1069 hides most modules from the sidebar on the
// argument that THIS page lists every one of them, so a group that can
// go missing here falsifies the argument. Derived, it cannot.
type TabId = "features" | "integrations";
const INTEGRATIONS_GROUP = "Integrations";
const TABS: { id: TabId; label: string }[] = [
  { id: "features", label: "Features" },
  { id: "integrations", label: "Integrations" },
];

/** Settings → Features.
 *
 * Operator-controlled visibility for whole sidebar / REST / MCP
 * surfaces. Toggling a row immediately persists (no batch Save) and
 * busts the React Query cache for both the sidebar and this page so
 * the disabled module disappears in real time.
 *
 * Default policy on a fresh install (#1069): a module ships ON only
 * if it is core IPAM / DNS / DHCP workflow, a zero-footprint UI
 * convenience, or a hand-invoked read-only diagnostic — 14 of 53
 * today. Everything else ships OFF and is turned on when wanted.
 * This page IS the discovery surface: it lists every module with its
 * description whether or not it is enabled, which is why the sidebar
 * no longer has to. The shipped value lives in the backend catalog
 * (``default_enabled`` in app/services/feature_modules.py).
 *
 * A row whose current state differs from its default is marked, so an
 * operator can see at a glance what they have changed.
 *
 * Layout: compact two-column grid — module identity on the left,
 * toggle on the right. Bottom padding leaves room for the floating
 * Copilot button so the last row's checkbox isn't covered.
 */
export function FeaturesPage() {
  const qc = useQueryClient();
  const { isSuperadmin } = usePermissions();
  const [activeTab, setActiveTab] = useSessionState<TabId>(
    "features-page-tab",
    "features",
  );
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["feature-modules"],
    queryFn: featureModulesApi.list,
  });

  // #62 self-governance lock state — drives the lock banner + the
  // "submitted for approval" path when disabling governance.approvals while
  // the lock is on. Only superadmins can read it; viewers skip the query.
  const { data: lockState } = useQuery({
    queryKey: ["approvals-lock"],
    queryFn: featureModulesApi.getApprovalsLock,
    enabled: isSuperadmin,
  });
  const lockOn = lockState?.approvals_protect_controls ?? false;

  // Transient feedback: when a control-disable is queued for approval rather
  // than executed inline (#62), show the queued message instead of toggling.
  const [queuedNotice, setQueuedNotice] = useState<string | null>(null);
  // Enable-time opt-in modal for governance.approvals (protect_controls).
  const [enableApprovalsModal, setEnableApprovalsModal] = useState(false);
  // Module the operator is about to switch OFF, pending confirmation.
  const [disableTarget, setDisableTarget] = useState<FeatureModuleEntry | null>(
    null,
  );
  const [toggleError, setToggleError] = useState<string | null>(null);
  // Break-glass force-disable affordance (superadmin escape hatch).
  const [breakGlass, setBreakGlass] = useState(false);

  const toggleMutation = useMutation({
    mutationFn: ({
      id,
      enabled,
      protectControls,
    }: {
      id: string;
      enabled: boolean;
      protectControls?: boolean;
    }) => featureModulesApi.toggle(id, enabled, protectControls),
    onSuccess: (resp) => {
      // #62: disabling governance.approvals while the lock is on returns 202
      // with a ChangeRequestQueued envelope instead of disabling inline.
      if (handleApprovalQueued(resp)) {
        setQueuedNotice(APPROVAL_QUEUED_MESSAGE);
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
        // The module is unchanged (still enabled) — re-sync so the toggle
        // snaps back to its real server state.
        qc.invalidateQueries({ queryKey: ["feature-modules"] });
        return;
      }
      setQueuedNotice(null);
      qc.invalidateQueries({ queryKey: ["feature-modules"] });
      // The lock can flip on at enable-time (protect_controls) — re-read it.
      qc.invalidateQueries({ queryKey: ["approvals-lock"] });
      // ``GET /settings`` reports each integration_*_enabled from its
      // feature module (#2196), and the Dashboard reads it there. Bust
      // that cache too so an open Dashboard catches the change without a
      // manual refresh.
      qc.invalidateQueries({ queryKey: ["settings"] });
    },
    // Without this a refusal is silent. Disabling core.dns / core.dhcp 422s
    // while the subsystem still owns servers, zones or scopes (#1068), and
    // that response body is the only place the counts are reported — the
    // toggle would otherwise just snap back with no explanation.
    onError: (err) => {
      setToggleError(formatApiError(err, "Could not change this feature."));
      qc.invalidateQueries({ queryKey: ["feature-modules"] });
    },
  });

  // Route a module toggle. governance.approvals gets special handling:
  //  - enabling → open the protect_controls opt-in modal first;
  //  - disabling → fire the toggle (the 202 path handles the locked case).
  const handleToggle = (m: FeatureModuleEntry, next: boolean) => {
    setQueuedNotice(null);
    setToggleError(null);
    if (m.id === APPROVALS_MODULE_ID && next) {
      setEnableApprovalsModal(true);
      return;
    }
    // Turning something OFF is the direction that removes surface area, so
    // it is confirmed and explained. Turning it back ON is not: it only
    // ever restores, and a prompt there would be friction for nothing.
    if (!next) {
      setDisableTarget(m);
      return;
    }
    toggleMutation.mutate({ id: m.id, enabled: next });
  };

  // #1068 — every module by id, so a row can look its parents up. Built
  // from the unfiltered list rather than the active tab's slice: a parent
  // can sit in a different group from its child (security.dnsbl is under
  // Security, core.dns under DNS), and on the Integrations tab it would
  // not be in the slice at all.
  const byId = useMemo(
    () => new Map((data ?? []).map((m) => [m.id, m])),
    [data],
  );

  // Resolved ancestry, not just the direct parent's own flag. With a
  // depth-2 chain (A requires B requires C, C off) checking only B's
  // ``enabled`` reports A as fine, so the row would render a live-looking
  // toggle that changes nothing. ``resolveEnabled`` is the same function
  // the sidebar and the server use, so all three agree.
  const resolved = useMemo(() => resolveEnabled(data ?? []), [data]);

  // Modules that would switch off with `id` — transitive, so a future
  // depth-2 chain is reported in full rather than one level of it. Only
  // modules that are currently ON are listed: naming a feature that is
  // already off as something you are about to lose is just noise.
  const dependentsOf = (id: string): FeatureModuleEntry[] => {
    const all = data ?? [];
    const doomed = new Set([id]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const m of all) {
        if (doomed.has(m.id)) continue;
        if (m.requires.some((parent) => doomed.has(parent))) {
          doomed.add(m.id);
          grew = true;
        }
      }
    }
    return all.filter(
      (m) => m.id !== id && doomed.has(m.id) && resolved.has(m.id),
    );
  };

  const grouped = useMemo(() => {
    if (!data) return [] as [string, FeatureModuleEntry[]][];
    const visible = data.filter((m) =>
      activeTab === "integrations"
        ? m.group === INTEGRATIONS_GROUP
        : m.group !== INTEGRATIONS_GROUP,
    );
    // Group order follows the catalog's own order (the API returns
    // MODULES order), rather than alphabetical or a list kept here that
    // could disagree with it. Every group the catalog defines gets a
    // section, so nothing can be dropped by omission.
    const buckets: Record<string, FeatureModuleEntry[]> = {};
    const order: string[] = [];
    for (const m of visible) {
      if (!buckets[m.group]) {
        buckets[m.group] = [];
        order.push(m.group);
      }
      buckets[m.group].push(m);
    }
    return order.map((g) => [g, buckets[g]] as [string, FeatureModuleEntry[]]);
  }, [data, activeTab]);

  const enabledCount = data?.filter((m) => m.enabled).length ?? 0;
  const totalCount = data?.length ?? 0;

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <ToggleLeft className="h-5 w-5 flex-shrink-0 text-primary" />
          <div className="min-w-0">
            <h1 className="text-lg font-semibold">Features & Integrations</h1>
            <p className="text-xs text-muted-foreground">
              Hide platform features your deployment doesn't use. Disabled
              modules disappear from the sidebar, the REST API, and the AI
              copilot's tool surface.
            </p>
          </div>
        </div>
        <div className="shrink-0 text-xs text-muted-foreground">
          {enabledCount} of {totalCount} enabled
        </div>
        <button
          type="button"
          onClick={() => refetch()}
          disabled={isFetching}
          className={headerCls}
          title="Reload from server"
        >
          <RefreshCcw
            className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
          />
          Refresh
        </button>
      </div>

      {/* Tabs — each tab shows a different slice of the catalog. */}
      <div className="flex shrink-0 items-center gap-1 border-b px-4 pt-2">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setActiveTab(t.id)}
            className={cn(
              "rounded-t-md border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              activeTab === t.id
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* #62 self-governance lock banner — visible only on the Features tab to
       *  superadmins when the lock is on. Explains why disabling Approval
       *  workflows now needs a second operator + offers the break-glass
       *  escape hatch. */}
      {activeTab === "features" && isSuperadmin && lockOn && (
        <div className="mx-4 mt-3 flex flex-wrap items-start gap-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
          <ShieldAlert className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-600 dark:text-amber-400" />
          <div className="min-w-0 flex-1">
            <p className="font-medium text-amber-700 dark:text-amber-300">
              Self-governance lock is ON
            </p>
            <p className="text-xs text-muted-foreground">
              Disabling <strong>Approval workflows</strong> (or weakening a
              policy, or turning this lock off) now requires a{" "}
              <em>second superadmin</em> to approve via the Change Requests
              queue. Strengthening moves stay single-person. If you're locked
              out with no second superadmin, use break-glass to force the change
              immediately — it's audited and alarmed.
            </p>
          </div>
          <HeaderButton
            variant="destructive"
            icon={AlertTriangle}
            onClick={() => setBreakGlass(true)}
            className="shrink-0"
          >
            Break glass…
          </HeaderButton>
        </div>
      )}

      {/* Queued-for-approval feedback (#62 control-disable). */}
      {queuedNotice && (
        <div className="mx-4 mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">
          {queuedNotice} See the <strong>Change Requests</strong> queue.
        </div>
      )}

      {/* #1068 — a refused toggle. Disabling core.dns / core.dhcp 422s while
       *  the subsystem still owns servers, zones or scopes, and the response
       *  body names the counts; without this the toggle just snapped back. */}
      {toggleError && (
        <div className="mx-4 mt-3 flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-700 dark:text-red-300">
          <span className="flex-1">{toggleError}</span>
          <button
            type="button"
            onClick={() => setToggleError(null)}
            className="shrink-0 rounded px-1 text-xs underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {isLoading && (
        <div className="p-4 text-sm text-muted-foreground">Loading…</div>
      )}

      {/* Layout strategy:
       *   - "wide" groups (≥3 modules) take a full row and lay their
       *     modules out in up to 3 columns internally.
       *   - "narrow" groups (≤2 modules) cluster: consecutive narrows
       *     pack 3-per-row into a shared cluster row so 1-item
       *     sections like AI / Compliance / Tools sit side-by-side
       *     instead of stacking with three rows of dead space on the
       *     right. When the buffer fills mid-stream because a wide
       *     group interrupts, we flush the buffer first.
       *   - Inside a clustered section, internal column count is
       *     forced to 1 — the section is already only ~1/3 of the page
       *     wide, so multi-column inside would crush the descriptions.
       *   - pb-24 keeps the last row above the floating Copilot
       *     button.
       */}
      <div className="flex-1 space-y-3 overflow-auto p-4 pb-24">
        {(() => {
          type Block =
            | {
                kind: "wide";
                group: string;
                modules: FeatureModuleEntry[];
              }
            | {
                kind: "cluster";
                items: { group: string; modules: FeatureModuleEntry[] }[];
              };
          const blocks: Block[] = [];
          let buffer: { group: string; modules: FeatureModuleEntry[] }[] = [];
          const flush = () => {
            if (buffer.length) {
              blocks.push({ kind: "cluster", items: buffer });
              buffer = [];
            }
          };
          for (const [group, modules] of grouped) {
            if (modules.length >= 3) {
              flush();
              blocks.push({ kind: "wide", group, modules });
            } else {
              buffer.push({ group, modules });
            }
          }
          flush();

          const renderSection = (
            group: string,
            modules: FeatureModuleEntry[],
            clustered: boolean,
          ) => {
            // Clustered sections live in ~1/3 page width — keep them
            // single-column internally so the description never gets
            // squeezed into a single chip-width line.
            const cols = clustered ? 1 : Math.min(3, modules.length);
            const fillerCount =
              cols > 0 ? (cols - (modules.length % cols)) % cols : 0;
            const colsClass =
              cols === 3
                ? "md:grid-cols-3"
                : cols === 2
                  ? "md:grid-cols-2"
                  : "";
            return (
              <section
                key={group}
                className="overflow-hidden rounded-md border bg-background"
              >
                <header className="border-b bg-muted/30 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {group}
                </header>
                <div
                  className={cn(
                    "grid grid-cols-1 gap-px bg-border/40",
                    colsClass,
                  )}
                >
                  {modules.map((m) => {
                    const isOverridden = m.enabled !== m.default_enabled;
                    // #1068 — a module under a disabled parent still reports
                    // enabled=true (that is its own state), but resolves off
                    // everywhere it matters. Say so, and make the toggle
                    // inert: flipping it here would appear to do nothing.
                    const blockedBy = m.requires.filter(
                      (parentId) =>
                        byId.has(parentId) && !resolved.has(parentId),
                    );
                    const isBlocked = blockedBy.length > 0;
                    const blockedLabel = blockedBy
                      .map((parentId) => byId.get(parentId)?.label ?? parentId)
                      .join(", ");
                    return (
                      <div
                        key={m.id}
                        className="flex items-start gap-3 bg-background px-3 py-2 hover:bg-muted/40"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-baseline gap-x-2">
                            <span className="text-sm font-medium">
                              {m.label}
                            </span>
                            <code className="font-mono text-[10px] text-muted-foreground/70">
                              {m.id}
                            </code>
                            {isOverridden && (
                              <span
                                className="rounded bg-amber-500/15 px-1 py-px text-[9px] font-medium text-amber-700 dark:text-amber-400"
                                title={`Default: ${m.default_enabled ? "on" : "off"}`}
                              >
                                overridden
                              </span>
                            )}
                            {isBlocked && (
                              <span
                                className="rounded bg-muted px-1 py-px text-[9px] font-medium text-muted-foreground"
                                title={`${blockedLabel} is disabled, so this feature is off regardless of the toggle.`}
                              >
                                requires {blockedLabel}
                              </span>
                            )}
                          </div>
                          <p className="mt-0.5 text-xs leading-snug text-muted-foreground">
                            {m.description}
                          </p>
                        </div>
                        <div className="mt-0.5">
                          <Toggle
                            label={`${m.enabled ? "Disable" : "Enable"} ${m.label}`}
                            checked={m.enabled && !isBlocked}
                            disabled={
                              toggleMutation.isPending ||
                              isBlocked ||
                              // #1341 — turning a module on or off takes a
                              // superadmin (PATCH /admin/feature-modules).
                              !isSuperadmin
                            }
                            title={isSuperadmin ? undefined : NEEDS_SUPERADMIN}
                            onChange={(v) => handleToggle(m, v)}
                          />
                        </div>
                      </div>
                    );
                  })}
                  {Array.from({ length: fillerCount }).map((_, idx) => (
                    <div
                      key={`filler-${idx}`}
                      className="hidden bg-background md:block"
                      aria-hidden
                    />
                  ))}
                </div>
              </section>
            );
          };

          return blocks.map((block, idx) => {
            if (block.kind === "wide") {
              return renderSection(block.group, block.modules, false);
            }
            return (
              <div
                key={`cluster-${idx}`}
                className="grid grid-cols-1 gap-3 md:grid-cols-3"
              >
                {block.items.map(({ group, modules }) =>
                  renderSection(group, modules, true),
                )}
              </div>
            );
          });
        })()}
        {!isLoading && grouped.length === 0 && (
          <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
            No modules in this tab.
          </div>
        )}
      </div>

      {/* #1068 — confirm + explain before any module is switched OFF. The
       *  question operators actually have is "will I lose my data", so the
       *  modal leads with the answer (no) rather than with a warning. */}
      <ConfirmModal
        open={disableTarget !== null}
        title={`Turn off ${disableTarget?.label ?? ""}?`}
        tone="destructive"
        confirmLabel={`Turn off ${disableTarget?.label ?? ""}`}
        loading={toggleMutation.isPending}
        requireCheckboxLabel={
          disableTarget && CORE_SUBSYSTEM_IDS.has(disableTarget.id)
            ? `I understand the whole ${disableTarget.label} section will be hidden and its API will stop responding.`
            : undefined
        }
        message={
          disableTarget ? (
            <DisableModuleMessage
              module={disableTarget}
              dependents={dependentsOf(disableTarget.id)}
            />
          ) : null
        }
        onConfirm={() => {
          if (!disableTarget) return;
          toggleMutation.mutate({ id: disableTarget.id, enabled: false });
          setDisableTarget(null);
        }}
        onClose={() => setDisableTarget(null)}
      />

      {/* #62 enable-time opt-in: when turning ON Approval workflows, offer to
       *  also turn on the self-governance lock in the same call. */}
      {enableApprovalsModal && (
        <EnableApprovalsModal
          onClose={() => setEnableApprovalsModal(false)}
          onConfirm={(protectControls) => {
            setEnableApprovalsModal(false);
            toggleMutation.mutate({
              id: APPROVALS_MODULE_ID,
              enabled: true,
              protectControls,
            });
          }}
          pending={toggleMutation.isPending}
        />
      )}

      {/* #62 break-glass escape hatch — force-disable Approval workflows. */}
      {breakGlass && (
        <BreakGlassModal
          kind="disable_module"
          onClose={() => setBreakGlass(false)}
          onDone={() => {
            setQueuedNotice(null);
            qc.invalidateQueries({ queryKey: ["approvals-lock"] });
          }}
        />
      )}
    </div>
  );
}

// ── Enable-time opt-in for the self-governance lock (#62) ───────────────────
//
// Surfaced when a superadmin turns ON Approval workflows. The checkbox feeds
// ``protect_controls`` into the toggle call — enabling the lock in the same
// request (strengthening → single-person, no approval needed). Leaving it
// unchecked enables the module without the lock; it can be turned on later.

// Core subsystems (#1068). These get the extra acknowledgement checkbox:
// they are the only modules whose toggle removes a whole sidebar section,
// its dashboard tab, its REST surface and its background jobs at once.
const CORE_SUBSYSTEM_IDS = new Set(["core.dns", "core.dhcp"]);

/**
 * What disabling a module actually does, written out for the operator.
 *
 * The headline is deliberately the reassurance rather than the warning,
 * because it is the question people actually have and the answer is
 * unambiguous: a feature module is a visibility and scheduling switch, not
 * a delete. Nothing in `set_module_enabled` touches a domain table — it
 * upserts one row in `feature_module` — so every zone, scope, lease and
 * reservation is exactly where it was when the module comes back on.
 */
function DisableModuleMessage({
  module,
  dependents,
}: {
  module: FeatureModuleEntry;
  dependents: FeatureModuleEntry[];
}) {
  const isCore = CORE_SUBSYSTEM_IDS.has(module.id);
  return (
    <div className="space-y-3 text-sm">
      <p>
        <span className="font-medium text-foreground">No data is deleted.</span>{" "}
        Disabling a feature hides it — it does not remove anything. Every record
        it manages stays in the database untouched, and turning the feature back
        on restores the surface exactly as it was.
      </p>
      <div>
        <p className="font-medium text-foreground">While it is off:</p>
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-muted-foreground">
          <li>its sidebar section and dashboard panels are hidden</li>
          <li>
            its API endpoints answer <code className="text-xs">404</code>, so
            scripts and integrations calling them will fail
          </li>
          <li>
            its scheduled background jobs stop, and its alert rules stop
            evaluating — any alert of its that is currently open is resolved
          </li>
          <li>its Operator Copilot tools disappear from the tool list</li>
        </ul>
      </div>
      {isCore && (
        <div>
          <p className="font-medium text-foreground">
            What keeps running anyway:
          </p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-muted-foreground">
            <li>
              already-registered agents keep serving from their current config —
              disabling the subsystem here does not stop DNS or DHCP on the wire
            </li>
            <li>new agents cannot register until it is re-enabled</li>
          </ul>
        </div>
      )}
      {dependents.length > 0 && (
        <div>
          <p className="font-medium text-foreground">
            {dependents.length} dependent feature
            {dependents.length === 1 ? "" : "s"} will switch off with it:
          </p>
          <p className="mt-1 text-muted-foreground">
            {dependents.map((d) => d.label).join(", ")}. Their own settings are
            kept, and they come back when this one does.
          </p>
        </div>
      )}
    </div>
  );
}

function EnableApprovalsModal({
  onClose,
  onConfirm,
  pending,
}: {
  onClose: () => void;
  onConfirm: (protectControls: boolean) => void;
  pending: boolean;
}) {
  const [protectControls, setProtectControls] = useState(false);
  return (
    <Modal title="Enable Approval workflows" onClose={onClose} wide>
      <div className="space-y-4 text-sm">
        <p className="text-muted-foreground">
          Risky operations (deletes, bulk changes, factory reset) that a policy
          covers will require a second eligible operator to approve before they
          run.
        </p>
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            className="mt-0.5 cursor-pointer"
            checked={protectControls}
            onChange={(e) => setProtectControls(e.target.checked)}
          />
          <span>
            <span className="font-medium">
              Require two-person approval to disable this
            </span>
            <span className="mt-0.5 block text-xs text-muted-foreground">
              Turns on the self-governance lock: from now on, disabling Approval
              workflows (or weakening a policy, or turning the lock back off)
              also needs a second superadmin to approve. A superadmin can always
              force the change in an emergency via break-glass (audited).
            </span>
          </span>
        </label>
        <div className="flex justify-end gap-2">
          <HeaderButton
            variant="secondary"
            onClick={onClose}
            disabled={pending}
          >
            Cancel
          </HeaderButton>
          <HeaderButton
            variant="primary"
            onClick={() => onConfirm(protectControls)}
            disabled={pending}
          >
            {pending ? "Enabling…" : "Enable"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}
