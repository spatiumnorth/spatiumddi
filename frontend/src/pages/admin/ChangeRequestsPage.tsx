/**
 * ChangeRequestsPage — the two-person approval queue (#62).
 *
 * Surfaces the ``change_request`` rows queued by the approval gate. A
 * covered risky operation (delete / bulk / factory-reset) that a policy
 * decided needs a second operator lands here in ``pending``; a *different*
 * eligible approver drives it to a terminal state.
 *
 * Three tabs:
 *  - **Queue** — pending requests with Approve / Reject (note) / Cancel.
 *  - **History** — terminal requests (executed / rejected / … ).
 *  - **Policies** — operator-tunable ``approval_policy`` rules (superadmin).
 *
 * Gating is server-side (every endpoint re-enforces the two-person spine);
 * this only drives affordance *visibility*: Approve/Reject need
 * ``approve,change_request``; Cancel needs requester-or-superadmin; the
 * Policies tab needs superadmin. The whole page is reached only when the
 * default-off ``governance.approvals`` module is on (the Sidebar nav entry
 * + backend ``require_module`` both gate it).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AxiosResponse } from "axios";
import {
  Ban,
  Check,
  CheckCircle2,
  Clock,
  GitPullRequest,
  Pencil,
  Plus,
  ThumbsDown,
  Trash2,
  XCircle,
} from "lucide-react";
import {
  APPROVAL_POLICY_ACTIONS,
  type ApprovalPolicy,
  type ApprovalPolicyWrite,
  type ChangeRequest,
  type ChangeRequestQueued,
  type ChangeRequestState,
  authApi,
  changeRequestsApi,
  formatApiError,
} from "@/lib/api";
import {
  APPROVAL_QUEUED_MESSAGE,
  CHANGE_REQUEST_QUERY_KEY,
  handleApprovalQueued,
} from "@/lib/approvalQueue";
import { featureModulesApi } from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { ShieldAlert, AlertTriangle } from "lucide-react";
import { BreakGlassModal } from "./BreakGlassModal";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// Terminal lifecycle states render in History; pending lives in the Queue.
const TERMINAL_STATES: ChangeRequestState[] = [
  "executed",
  "rejected",
  "failed",
  "expired",
  "cancelled",
];

type StateMeta = {
  label: string;
  className: string;
  Icon: typeof Check;
};

// Mirrors the FleetTab status palette: emerald=good, rose=bad, amber=in-flight.
function stateBadge(state: ChangeRequestState): StateMeta {
  switch (state) {
    case "pending":
      return {
        label: "pending",
        className:
          "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30",
        Icon: Clock,
      };
    case "approved":
      return {
        label: "approved",
        className:
          "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30",
        Icon: Check,
      };
    case "executed":
      return {
        label: "executed",
        className:
          "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30",
        Icon: CheckCircle2,
      };
    case "rejected":
      return {
        label: "rejected",
        className:
          "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30",
        Icon: ThumbsDown,
      };
    case "failed":
      return {
        label: "failed",
        className:
          "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30",
        Icon: XCircle,
      };
    case "expired":
      return {
        label: "expired",
        className: "bg-muted text-muted-foreground border-border",
        Icon: Clock,
      };
    case "cancelled":
      return {
        label: "cancelled",
        className: "bg-muted text-muted-foreground border-border",
        Icon: Ban,
      };
  }
}

function StateChip({ state }: { state: ChangeRequestState }) {
  const { label, className, Icon } = stateBadge(state);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium",
        className,
      )}
    >
      <Icon className="h-3 w-3" /> {label}
    </span>
  );
}

function UserChip({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-foreground">
      {label}
    </span>
  );
}

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// ── Decision modal (approve / reject with an optional note) ─────────────────
//
// ConfirmModal carries only checkbox + password — no free-text field — so
// the note-bearing decision uses the shared draggable Modal directly.

// The server's bound on a decision note (`max_length=2000`); the box stops at
// it so an over-long note is never sent and refused as "decision_note: ..." (#3835).
const DECISION_NOTE_MAX = 2000;

function DecisionModal({
  cr,
  mode,
  onClose,
}: {
  cr: ChangeRequest;
  mode: "approve" | "reject";
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const [confirmed, setConfirmed] = useState(mode === "reject");
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      mode === "approve"
        ? changeRequestsApi.approve(cr.id, note || undefined)
        : changeRequestsApi.reject(cr.id, note || undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["change-requests"] });
      onClose();
    },
    onError: (err) =>
      setError(formatApiError(err, `Failed to ${mode} the request.`)),
  });

  const title =
    mode === "approve" ? "Approve change request" : "Reject change request";

  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="space-y-4">
        <div className="rounded-md border bg-muted/20 p-3 text-sm">
          <div className="mb-1 flex items-center gap-2">
            <span className="font-mono text-xs">{cr.operation}</span>
            <StateChip state={cr.state} />
          </div>
          <p className="text-xs text-muted-foreground">
            Requested by <UserChip label={cr.requested_by_display} /> on{" "}
            {fmtTime(cr.created_at)}
          </p>
          <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded bg-background p-2 text-[11px]">
            {cr.preview_text}
          </pre>
        </div>

        {mode === "approve" && (
          <p className="text-xs text-amber-600 dark:text-amber-400">
            On approve this operation re-runs its preview (stale-state guard),
            then executes under <strong>your</strong> identity. The audit log
            records both you and the requester.
          </p>
        )}

        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Decision note {mode === "reject" ? "" : "(optional)"}
          </label>
          <textarea
            className={cn(inputCls, "min-h-[64px] resize-y")}
            maxLength={DECISION_NOTE_MAX}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder={
              mode === "approve"
                ? "Why this is OK to run…"
                : "Why this is being declined…"
            }
          />
        </div>

        {mode === "approve" && (
          <label className="flex items-start gap-2 text-xs">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <span>
              I understand this executes the operation immediately under my
              identity.
            </span>
          </label>
        )}

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2">
          <HeaderButton variant="secondary" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            variant={mode === "approve" ? "primary" : "destructive"}
            icon={mode === "approve" ? Check : ThumbsDown}
            disabled={!confirmed || mutation.isPending}
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending
              ? "Working…"
              : mode === "approve"
                ? "Approve & execute"
                : "Reject"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

// ── Change-request row ──────────────────────────────────────────────────────

function RequestRow({
  cr,
  canApprove,
  canCancel,
  onDecide,
  onCancel,
}: {
  cr: ChangeRequest;
  canApprove: boolean;
  canCancel: boolean;
  onDecide: (cr: ChangeRequest, mode: "approve" | "reject") => void;
  onCancel: (cr: ChangeRequest) => void;
}) {
  const isPending = cr.state === "pending";
  return (
    <tr className="border-b align-top">
      <td className="px-3 py-2">
        <StateChip state={cr.state} />
      </td>
      <td className="px-3 py-2">
        <div className="font-mono text-xs">{cr.operation}</div>
        <div className="text-[11px] text-muted-foreground">
          {cr.resource_type}
          {cr.resource_display ? ` · ${cr.resource_display}` : ""}
        </div>
        {cr.error && (
          <div className="mt-1 text-[11px] text-destructive break-words">
            {cr.error}
          </div>
        )}
      </td>
      <td className="px-3 py-2 text-xs">
        <UserChip label={cr.requested_by_display} />
        {cr.decided_by_display && (
          <>
            {" → "}
            <UserChip label={cr.decided_by_display} />
          </>
        )}
        {cr.decision_note && (
          <div className="mt-1 italic text-muted-foreground break-words">
            “{cr.decision_note}”
          </div>
        )}
      </td>
      <td className="px-3 py-2 text-[11px] text-muted-foreground whitespace-nowrap">
        {fmtTime(cr.created_at)}
        {isPending && (
          <div className="text-amber-600 dark:text-amber-400">
            expires {fmtTime(cr.expires_at)}
          </div>
        )}
      </td>
      <td className="px-3 py-2 text-right whitespace-nowrap">
        {isPending && (
          <div className="inline-flex gap-1">
            {canApprove && (
              <>
                <HeaderButton
                  variant="primary"
                  icon={Check}
                  onClick={() => onDecide(cr, "approve")}
                >
                  Approve
                </HeaderButton>
                <HeaderButton
                  variant="destructive"
                  icon={ThumbsDown}
                  onClick={() => onDecide(cr, "reject")}
                >
                  Reject
                </HeaderButton>
              </>
            )}
            {canCancel && (
              <HeaderButton
                variant="secondary"
                icon={Ban}
                onClick={() => onCancel(cr)}
              >
                Cancel
              </HeaderButton>
            )}
          </div>
        )}
      </td>
    </tr>
  );
}

function RequestTable({
  rows,
  canApprove,
  isRequester,
  isSuperadmin,
  onDecide,
  onCancel,
  emptyText,
}: {
  rows: ChangeRequest[];
  canApprove: boolean;
  isRequester: (cr: ChangeRequest) => boolean;
  isSuperadmin: boolean;
  onDecide: (cr: ChangeRequest, mode: "approve" | "reject") => void;
  onCancel: (cr: ChangeRequest) => void;
  emptyText: string;
}) {
  if (rows.length === 0) {
    return (
      <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
        {emptyText}
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className={cn("w-full min-w-[760px] text-sm", zebraBodyCls)}>
        <thead className="border-b bg-muted/40 text-left text-xs text-muted-foreground">
          <tr>
            <th className="px-3 py-2 font-medium">State</th>
            <th className="px-3 py-2 font-medium">Operation</th>
            <th className="px-3 py-2 font-medium">Requester → Approver</th>
            <th className="px-3 py-2 font-medium">Created</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {rows.map((cr) => (
            <RequestRow
              key={cr.id}
              cr={cr}
              // The server refuses an approver's decision on their own
              // request (#3834); only Cancel is offered on it.
              canApprove={canApprove && !isRequester(cr)}
              canCancel={isRequester(cr) || isSuperadmin}
              onDecide={onDecide}
              onCancel={onCancel}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Policy editor ───────────────────────────────────────────────────────────

function PolicyEditor({
  existing,
  onClose,
  onQueued,
}: {
  existing: ApprovalPolicy | null;
  onClose: () => void;
  /** Fired when a weakening edit was queued for approval (#62) instead of
   *  mutating inline. */
  onQueued?: () => void;
}) {
  const qc = useQueryClient();
  const locked = existing?.is_builtin ?? false;
  const [name, setName] = useState(existing?.name ?? "");
  const [resourceType, setResourceType] = useState(
    existing?.resource_type ?? "",
  );
  const [action, setAction] = useState(existing?.action ?? "delete");
  const [minCount, setMinCount] = useState<string>(
    existing?.min_count != null ? String(existing.min_count) : "",
  );
  const [ttlHours, setTtlHours] = useState<string>(
    String(existing?.ttl_hours ?? 168),
  );
  const [enabled, setEnabled] = useState(existing?.enabled ?? false);
  const [appliesToSuperadmin, setAppliesToSuperadmin] = useState(
    existing?.applies_to_superadmin ?? true,
  );
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation<
    // createPolicy returns the unwrapped row; updatePolicy returns the full
    // axios response so the #62 lock's 202 envelope is observable. Both shapes
    // flow through handleApprovalQueued (unwrapped rows have no `status`, so
    // they read as "executed inline").
    ApprovalPolicy | AxiosResponse<ApprovalPolicy | ChangeRequestQueued>,
    unknown,
    void
  >({
    mutationFn: () => {
      const body: ApprovalPolicyWrite = {
        name: name.trim(),
        resource_type: resourceType.trim(),
        action,
        min_count: minCount.trim() === "" ? null : Number(minCount),
        enabled,
        applies_to_superadmin: appliesToSuperadmin,
        ttl_hours: Number(ttlHours) || 168,
      };
      // createPolicy already returns the unwrapped row; updatePolicy returns
      // the full axios response so the #62 self-governance lock's 202
      // approval-queue envelope (weakening a policy while the lock is on) is
      // observable.
      return existing
        ? changeRequestsApi.updatePolicy(existing.id, body)
        : changeRequestsApi.createPolicy(body);
    },
    onSuccess: (resp) => {
      // #62: a weakening edit (disable / lower applies_to_superadmin) returns
      // 202 + a pending change_request when the lock is on instead of mutating
      // inline. Surface the queued state rather than closing silently.
      if (handleApprovalQueued(resp)) {
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
        qc.invalidateQueries({ queryKey: ["change-requests", "policies"] });
        onQueued?.();
        onClose();
        return;
      }
      qc.invalidateQueries({ queryKey: ["change-requests", "policies"] });
      onClose();
    },
    onError: (err) => setError(formatApiError(err, "Failed to save policy.")),
  });

  return (
    <Modal
      title={existing ? "Edit approval policy" : "New approval policy"}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        {locked && (
          <p className="text-xs text-muted-foreground">
            Built-in policy — only the threshold, TTL, and toggles are tunable.
          </p>
        )}
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            className={inputCls}
            value={name}
            disabled={locked}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Resource type
            </label>
            <input
              className={inputCls}
              value={resourceType}
              disabled={locked}
              placeholder="subnet / dns_zone / *"
              onChange={(e) => setResourceType(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Action
            </label>
            <select
              className={inputCls}
              value={action}
              disabled={locked}
              onChange={(e) => setAction(e.target.value)}
            >
              {APPROVAL_POLICY_ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Threshold (min rows)
            </label>
            <input
              className={inputCls}
              type="number"
              min={1}
              value={minCount}
              placeholder="always"
              onChange={(e) => setMinCount(e.target.value)}
            />
            <p className="text-[11px] text-muted-foreground/80">
              Blank = require approval regardless of count.
            </p>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              TTL (hours)
            </label>
            <input
              className={inputCls}
              type="number"
              min={1}
              value={ttlHours}
              onChange={(e) => setTtlHours(e.target.value)}
            />
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enabled
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={appliesToSuperadmin}
            onChange={(e) => setAppliesToSuperadmin(e.target.checked)}
          />
          Applies to superadmin
          <span className="text-[11px] text-muted-foreground">
            (a rule superadmin bypasses isn't a two-person rule)
          </span>
        </label>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2">
          <HeaderButton variant="secondary" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            variant="primary"
            disabled={mutation.isPending}
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending ? "Saving…" : "Save"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

function PoliciesTab() {
  const qc = useQueryClient();
  const { data: policies = [], isLoading } = useQuery({
    queryKey: ["change-requests", "policies"],
    queryFn: changeRequestsApi.listPolicies,
  });
  // #62 self-governance lock state — drives the banner + the queued path on
  // policy weakening + the break-glass affordance.
  const { data: lockState } = useQuery({
    queryKey: ["approvals-lock"],
    queryFn: featureModulesApi.getApprovalsLock,
  });
  const lockOn = lockState?.approvals_protect_controls ?? false;

  const [editing, setEditing] = useState<ApprovalPolicy | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<ApprovalPolicy | null>(null);
  const [queuedNotice, setQueuedNotice] = useState<string | null>(null);
  // Break-glass for a specific policy weakening (delete it now).
  const [breakGlass, setBreakGlass] = useState<ApprovalPolicy | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => changeRequestsApi.deletePolicy(id),
    onSuccess: (resp) => {
      // #62: deleting a policy while the lock is on returns 202 + a pending
      // change_request instead of deleting inline.
      if (handleApprovalQueued(resp)) {
        setQueuedNotice(APPROVAL_QUEUED_MESSAGE);
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
      }
      qc.invalidateQueries({ queryKey: ["change-requests", "policies"] });
      setDeleting(null);
    },
  });

  return (
    <div className="space-y-3">
      {lockOn && (
        <div className="flex flex-wrap items-start gap-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
          <ShieldAlert className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-600 dark:text-amber-400" />
          <div className="min-w-0 flex-1">
            <p className="font-medium text-amber-700 dark:text-amber-300">
              Self-governance lock is ON
            </p>
            <p className="text-xs text-muted-foreground">
              Weakening a policy — <strong>disabling</strong> it,{" "}
              <strong>deleting</strong> it, or turning off{" "}
              <em>Applies to superadmin</em> — now needs a second superadmin to
              approve via the Queue. Strengthening edits stay single-person. Use
              break-glass (per-row) to force a weakening change immediately if
              you're locked out.
            </p>
          </div>
        </div>
      )}
      {queuedNotice && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">
          {queuedNotice} See the Queue tab.
        </div>
      )}
      <div className="flex justify-end">
        <HeaderButton
          variant="primary"
          icon={Plus}
          onClick={() => setCreating(true)}
        >
          New policy
        </HeaderButton>
      </div>
      {isLoading ? (
        <p className="text-xs text-muted-foreground">Loading…</p>
      ) : policies.length === 0 ? (
        <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
          No approval policies yet.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className={cn("w-full min-w-[760px] text-sm", zebraBodyCls)}>
            <thead className="border-b bg-muted/40 text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Resource</th>
                <th className="px-3 py-2 font-medium">Action</th>
                <th className="px-3 py-2 font-medium">Threshold</th>
                <th className="px-3 py-2 font-medium">TTL</th>
                <th className="px-3 py-2 font-medium">Enabled</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className="border-b">
                  <td className="px-3 py-2">
                    {p.name}
                    {p.is_builtin && (
                      <span className="ml-1.5 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        built-in
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {p.resource_type}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{p.action}</td>
                  <td className="px-3 py-2">{p.min_count ?? "always"}</td>
                  <td className="px-3 py-2">{p.ttl_hours}h</td>
                  <td className="px-3 py-2">
                    {p.enabled ? (
                      <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                        <Check className="h-3 w-3" /> on
                      </span>
                    ) : (
                      <span className="text-muted-foreground">off</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right whitespace-nowrap">
                    <div className="inline-flex gap-1">
                      <HeaderButton
                        variant="secondary"
                        icon={Pencil}
                        onClick={() => setEditing(p)}
                      >
                        Edit
                      </HeaderButton>
                      {!p.is_builtin && (
                        <HeaderButton
                          variant="destructive"
                          icon={Trash2}
                          onClick={() => setDeleting(p)}
                        >
                          Delete
                        </HeaderButton>
                      )}
                      {/* #62: when the lock is on, deleting/disabling routes
                       *  through approval. Break-glass forces it now. */}
                      {lockOn && !p.is_builtin && (
                        <HeaderButton
                          variant="destructive"
                          icon={AlertTriangle}
                          title="Force-delete this policy now (break-glass)"
                          onClick={() => setBreakGlass(p)}
                        >
                          Break glass
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

      {(creating || editing) && (
        <PolicyEditor
          existing={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onQueued={() => setQueuedNotice(APPROVAL_QUEUED_MESSAGE)}
        />
      )}

      <ConfirmModal
        open={deleting !== null}
        title="Delete approval policy"
        tone="destructive"
        confirmLabel={lockOn ? "Submit for approval" : "Delete"}
        loading={deleteMutation.isPending}
        message={
          <span>
            Delete the policy <strong>{deleting?.name}</strong>? Operations it
            covered will no longer require a second approver.
            {lockOn && (
              <span className="mt-2 block text-amber-600 dark:text-amber-400">
                The self-governance lock is on — this will be queued for a
                second superadmin to approve rather than deleted immediately.
              </span>
            )}
          </span>
        }
        onConfirm={() => deleting && deleteMutation.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      />

      {breakGlass && (
        <BreakGlassModal
          kind="delete_policy"
          policyId={breakGlass.id}
          policyName={breakGlass.name}
          onClose={() => setBreakGlass(null)}
          onDone={() =>
            qc.invalidateQueries({ queryKey: ["change-requests", "policies"] })
          }
        />
      )}
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export function ChangeRequestsPage() {
  const { can, isSuperadmin } = usePermissions();
  const canApprove = can("approve", "change_request");
  const myUserId = useMyUserId();

  const [tab, setTab] = useState<"queue" | "history" | "policies">("queue");
  const [decision, setDecision] = useState<{
    cr: ChangeRequest;
    mode: "approve" | "reject";
  } | null>(null);
  const [cancelTarget, setCancelTarget] = useState<ChangeRequest | null>(null);

  const qc = useQueryClient();

  const queueQuery = useQuery({
    queryKey: ["change-requests", "pending"],
    queryFn: () => changeRequestsApi.list({ state: "pending", limit: 500 }),
    // Adaptive poll (FleetTab pattern): tighter while anything is pending.
    refetchInterval: (q) => ((q.state.data?.length ?? 0) > 0 ? 5000 : 20000),
  });

  const historyQuery = useQuery({
    queryKey: ["change-requests", "history"],
    queryFn: () => changeRequestsApi.list({ limit: 200 }),
    enabled: tab === "history",
  });

  const historyRows = useMemo(
    () =>
      (historyQuery.data ?? []).filter((r) =>
        TERMINAL_STATES.includes(r.state),
      ),
    [historyQuery.data],
  );

  const cancelMutation = useMutation({
    mutationFn: (id: string) => changeRequestsApi.cancel(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["change-requests"] });
      setCancelTarget(null);
    },
  });

  const isRequester = (cr: ChangeRequest) =>
    cr.requested_by_user_id != null && cr.requested_by_user_id === myUserId;

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-6xl space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="flex items-center gap-2 text-xl font-semibold">
              <GitPullRequest className="h-5 w-5" /> Change Requests
            </h1>
            <p className="max-w-2xl text-xs text-muted-foreground">
              Risky operations (deletes, bulk changes, factory reset) that a
              policy queued for a second eligible operator. A requester can't
              approve their own request — a different operator holding{" "}
              <span className="font-mono">approve,change_request</span> plus the
              operation's own permission approves, and it executes under the
              approver's identity after a stale-state re-check.
            </p>
          </div>
        </div>

        <div className="flex gap-1 border-b">
          {(["queue", "history", isSuperadmin ? "policies" : null] as const)
            .filter((t): t is "queue" | "history" | "policies" => t !== null)
            .map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={cn(
                  "border-b-2 px-3 py-1.5 text-sm capitalize",
                  tab === t
                    ? "border-primary font-medium text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground",
                )}
              >
                {t}
                {t === "queue" && (queueQuery.data?.length ?? 0) > 0 && (
                  <span className="ml-1.5 rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                    {queueQuery.data?.length}
                  </span>
                )}
              </button>
            ))}
        </div>

        {tab === "queue" &&
          (queueQuery.isLoading ? (
            <p className="text-xs text-muted-foreground">Loading…</p>
          ) : (
            <RequestTable
              rows={queueQuery.data ?? []}
              canApprove={canApprove}
              isRequester={isRequester}
              isSuperadmin={isSuperadmin}
              onDecide={(cr, mode) => setDecision({ cr, mode })}
              onCancel={setCancelTarget}
              emptyText="Nothing waiting for approval."
            />
          ))}

        {tab === "history" &&
          (historyQuery.isLoading ? (
            <p className="text-xs text-muted-foreground">Loading…</p>
          ) : (
            <RequestTable
              rows={historyRows}
              canApprove={false}
              isRequester={isRequester}
              isSuperadmin={isSuperadmin}
              onDecide={(cr, mode) => setDecision({ cr, mode })}
              onCancel={setCancelTarget}
              emptyText="No decided requests yet."
            />
          ))}

        {tab === "policies" && isSuperadmin && <PoliciesTab />}
      </div>

      {decision && (
        <DecisionModal
          cr={decision.cr}
          mode={decision.mode}
          onClose={() => setDecision(null)}
        />
      )}

      <ConfirmModal
        open={cancelTarget !== null}
        title="Cancel change request"
        confirmLabel="Withdraw request"
        loading={cancelMutation.isPending}
        message={
          <span>
            Withdraw this pending request for{" "}
            <span className="font-mono">{cancelTarget?.operation}</span>? The
            operation will not run.
          </span>
        }
        onConfirm={() => cancelTarget && cancelMutation.mutate(cancelTarget.id)}
        onClose={() => setCancelTarget(null)}
      />
    </div>
  );
}

// The "is this my request?" check (Cancel affordance) needs the caller's
// own user id — ``GET /auth/me`` returns it.
function useMyUserId(): string | null {
  const query = useQuery({
    queryKey: ["auth-me"],
    queryFn: authApi.me,
    staleTime: 5 * 60 * 1000,
  });
  return query.data?.id ?? null;
}

export default ChangeRequestsPage;
