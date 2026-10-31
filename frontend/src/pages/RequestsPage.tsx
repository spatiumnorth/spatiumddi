/**
 * Self-service request portal (#696).
 *
 * #62's Change Requests page is the approval engine as a *brake* — an admin
 * surface for reviewing risky deletes. This is the same lifecycle pointed the
 * other way, and it is deliberately NOT an admin page: a requester is an
 * ordinary user asking for an IP, a subnet, a DNS record or a DHCP
 * reservation they cannot create themselves.
 *
 * Two audiences, one page:
 *   - a requester sees "My requests" and the New request button;
 *   - an approver (holder of `approve,change_request`) additionally sees
 *     everyone's, and gets Approve / Reject on pending rows.
 *
 * The server decides which of those applies — the list endpoint force-scopes a
 * caller who cannot approve to their own rows regardless of what the UI asks
 * for — so nothing here is load-bearing for authorization.
 *
 * The request form is rendered from the `args_schema` the catalog endpoint
 * returns, which is the JSON Schema of the backing operation's own args model.
 * That means the form fields ARE the server's contract: adding a field to an
 * operation surfaces it here with no frontend change, and the two can't drift.
 */
import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  authApi,
  requestsApi,
  type ChangeRequestState,
  type ProvisioningRequest,
  type ResourceOptionsResponse,
  type RequestKind,
  type RequestKindId,
  formatApiError,
} from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { closePopupOnEscape } from "@/components/ui/use-draggable-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { ListEmpty } from "@/components/ui/list-read-error";
import { pollUnlessRefused } from "@/lib/refusal";
import {
  Ban,
  Check,
  CheckCircle2,
  Clock,
  Inbox,
  Plus,
  ThumbsDown,
  XCircle,
} from "lucide-react";

type StateMeta = {
  label: string;
  className: string;
  Icon: typeof Clock;
};

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
        label: "provisioned",
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

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function errMessage(e: unknown, fallback: string): string {
  return formatApiError(e, fallback);
}

// ── New-request modal ──────────────────────────────────────────────────────

type FieldSpec = {
  name: string;
  title: string;
  description?: string;
  type: string;
  required: boolean;
  enum?: string[];
  // #759 — RBAC resource_type of the resource this field references
  // (server-annotated via x-resource); drives the searchable picker.
  resource?: string;
};

/**
 * Flatten a JSON Schema's top-level properties into render-able fields.
 *
 * Deliberately shallow: every catalog operation's args model is a flat set of
 * scalars, so a general JSON-Schema form renderer would be far more machinery
 * than the four kinds need. A nested field would render as a JSON textarea
 * (the `default` branch), which is honest rather than silently wrong — and if
 * a future kind needs real nesting, that's the signal to reach for a proper
 * renderer.
 */
function fieldsFrom(kind: RequestKind): FieldSpec[] {
  const props = kind.args_schema?.properties ?? {};
  const required = new Set(kind.args_schema?.required ?? []);
  return Object.entries(props).map(([name, raw]) => {
    const spec = raw as Record<string, unknown>;
    // Pydantic emits optional fields as anyOf[type, null]; take the first
    // non-null branch so the input renders as its real type.
    let type = typeof spec.type === "string" ? (spec.type as string) : "string";
    const anyOf = spec.anyOf as Array<Record<string, unknown>> | undefined;
    if (!spec.type && Array.isArray(anyOf)) {
      const concrete = anyOf.find((b) => b.type && b.type !== "null");
      if (concrete && typeof concrete.type === "string") type = concrete.type;
    }
    return {
      name,
      title: typeof spec.title === "string" ? spec.title : name,
      description:
        typeof spec.description === "string" ? spec.description : undefined,
      type,
      required: required.has(name),
      enum: Array.isArray(spec.enum) ? (spec.enum as string[]) : undefined,
      resource:
        typeof spec["x-resource"] === "string"
          ? (spec["x-resource"] as string)
          : undefined,
    };
  });
}

/**
 * Searchable, permission-filtered picker for an `x-resource` field (#759).
 *
 * Backed by `/requests/resource-options`, which returns only rows the caller
 * holds a read grant for — the raw admin list endpoints would leak the whole
 * estate to a Requester. Server-side search + capped results, so a mature
 * install's hundreds of subnets/zones never render as one giant <select>.
 * The submitted value is the UUID; the user only ever sees labels.
 */
function ResourcePicker({
  resource,
  value,
  onChange,
}: {
  resource: string;
  value: string;
  onChange: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  const [open, setOpen] = useState(false);
  const [selectedLabel, setSelectedLabel] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 250);
    return () => clearTimeout(t);
  }, [search]);

  const { data, isFetching } = useQuery<ResourceOptionsResponse>({
    queryKey: ["resource-options", resource, debounced],
    queryFn: () => requestsApi.resourceOptions(resource, debounced),
    enabled: open,
    staleTime: 30_000,
  });
  const options = data?.options ?? [];

  if (value && selectedLabel) {
    return (
      <div className="flex w-full min-w-0 items-center gap-1.5 rounded-md border border-border bg-background px-2 py-1.5 text-sm">
        <span className="truncate">{selectedLabel}</span>
        <button
          type="button"
          aria-label="Clear selection"
          className="ml-auto shrink-0 text-muted-foreground hover:text-foreground"
          onClick={() => {
            onChange("");
            setSelectedLabel(null);
            setSearch("");
          }}
        >
          ✕
        </button>
      </div>
    );
  }

  return (
    <div
      className="relative"
      // An Esc on an option reached with Tab is the list's too (#3157).
      onKeyDown={(e) => closePopupOnEscape(e, open, () => setOpen(false))}
    >
      <input
        className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
        placeholder="Type to search…"
        value={search}
        onChange={(e) => {
          setSearch(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => closePopupOnEscape(e, open, () => setOpen(false))}
      />
      {open ? (
        <div className="absolute z-50 mt-1 max-h-56 w-full overflow-y-auto rounded-md border border-border bg-background shadow-lg">
          {options.length === 0 ? (
            <div className="px-2 py-1.5 text-xs text-muted-foreground">
              {isFetching
                ? "Searching…"
                : data?.truncated
                  ? "Large list — keep typing to narrow the search"
                  : "No matches you can read"}
            </div>
          ) : (
            options.map((o) => (
              <button
                type="button"
                key={o.id}
                className="block w-full px-2 py-1.5 text-left text-sm hover:bg-muted"
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  onChange(o.id);
                  setSelectedLabel(
                    o.sublabel ? `${o.label} — ${o.sublabel}` : o.label,
                  );
                  setOpen(false);
                }}
              >
                <span>{o.label}</span>
                {o.sublabel ? (
                  <span className="ml-1.5 text-xs text-muted-foreground">
                    {o.sublabel}
                  </span>
                ) : null}
              </button>
            ))
          )}
          {options.length > 0 && data?.truncated ? (
            <div className="border-t border-border px-2 py-1 text-[11px] text-muted-foreground">
              More may exist — keep typing to narrow
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function NewRequestModal({
  kinds,
  onClose,
}: {
  kinds: RequestKind[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [kindId, setKindId] = useState<RequestKindId | "">("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);

  const kind = kinds.find((k) => k.kind === kindId);
  const fields = useMemo(() => (kind ? fieldsFrom(kind) : []), [kind]);

  const submit = useMutation({
    mutationFn: async () => {
      if (!kind) throw new Error("Pick what you need first");
      // Coerce to the JSON types the args model expects. Blank optional
      // fields are dropped rather than sent as "" — the server's model would
      // reject an empty string where it wants a number or nothing at all.
      const args: Record<string, unknown> = {};
      for (const f of fields) {
        const raw = (values[f.name] ?? "").trim();
        if (raw === "") continue;
        if (f.type === "integer" || f.type === "number") {
          const n = Number(raw);
          if (Number.isNaN(n)) throw new Error(`${f.title} must be a number`);
          args[f.name] = n;
        } else if (f.type === "boolean") {
          args[f.name] = raw === "true";
        } else {
          args[f.name] = raw;
        }
      }
      return requestsApi.submit({
        kind: kind.kind,
        args,
        justification: justification.trim() || null,
      });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["provisioning-requests"] });
      onClose();
    },
    onError: (e) => setError(errMessage(e, "Could not submit the request")),
  });

  return (
    <Modal title="New request" onClose={onClose} wide>
      <div className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            What do you need?
          </label>
          <select
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            value={kindId}
            onChange={(e) => {
              setKindId(e.target.value as RequestKindId);
              setValues({});
              setError(null);
            }}
          >
            <option value="">Select…</option>
            {kinds.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.label}
              </option>
            ))}
          </select>
          {kind ? (
            <p className="mt-1 text-xs text-muted-foreground">
              {kind.description}
            </p>
          ) : null}
        </div>

        {fields.length > 0 ? (
          <div className="grid gap-3 sm:grid-cols-2">
            {fields.map((f) => (
              <div key={f.name} className="min-w-0">
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  {f.title}
                  {f.required ? (
                    <span className="ml-0.5 text-rose-500">*</span>
                  ) : null}
                </label>
                {f.resource ? (
                  <ResourcePicker
                    resource={f.resource}
                    value={values[f.name] ?? ""}
                    onChange={(id) =>
                      setValues((v) => ({ ...v, [f.name]: id }))
                    }
                  />
                ) : f.enum ? (
                  <select
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
                    value={values[f.name] ?? ""}
                    onChange={(e) =>
                      setValues((v) => ({ ...v, [f.name]: e.target.value }))
                    }
                  >
                    <option value="">—</option>
                    {f.enum.map((o) => (
                      <option key={o} value={o}>
                        {o}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
                    value={values[f.name] ?? ""}
                    onChange={(e) =>
                      setValues((v) => ({ ...v, [f.name]: e.target.value }))
                    }
                  />
                )}
                {f.description ? (
                  <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                    {f.description}
                  </p>
                ) : null}
              </div>
            ))}
          </div>
        ) : null}

        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Why do you need this?
          </label>
          <textarea
            rows={3}
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            placeholder="Context for whoever reviews this — what it's for, how long you need it."
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
          />
        </div>

        {error ? (
          <p className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1.5 text-xs text-rose-600 dark:text-rose-400">
            {error}
          </p>
        ) : null}

        <p className="text-xs text-muted-foreground">
          Submitting changes nothing yet. Your request goes to an approver who
          can create this; if they approve, it is provisioned then.
        </p>

        <div className="flex justify-end gap-2">
          <HeaderButton variant="secondary" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            variant="primary"
            disabled={!kind || submit.isPending}
            onClick={() => {
              setError(null);
              submit.mutate();
            }}
          >
            {submit.isPending ? "Submitting…" : "Submit request"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

// ── Decision modal (approve / reject / cancel with an optional note) ────────

function DecisionModal({
  request,
  action,
  onClose,
}: {
  request: ProvisioningRequest;
  action: "approve" | "reject" | "cancel";
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const title =
    action === "approve"
      ? "Approve and provision"
      : action === "reject"
        ? "Reject request"
        : "Withdraw request";

  const mutation = useMutation({
    mutationFn: () => {
      const n = note.trim() || undefined;
      if (action === "approve") return requestsApi.approve(request.id, n);
      if (action === "reject") return requestsApi.reject(request.id, n);
      return requestsApi.cancel(request.id, n);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["provisioning-requests"] });
      onClose();
    },
    onError: (e) => setError(errMessage(e, `Could not ${action} the request`)),
  });

  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="space-y-3">
        <div className="rounded border border-border bg-muted/40 p-2">
          <p className="text-xs font-medium">{request.resource_display}</p>
          <pre className="mt-1 whitespace-pre-wrap break-words text-[11px] leading-snug text-muted-foreground">
            {request.preview_text}
          </pre>
        </div>
        {request.justification ? (
          <div>
            <p className="text-[11px] font-medium text-muted-foreground">
              Requester's justification
            </p>
            <p className="whitespace-pre-wrap break-words text-xs">
              {request.justification}
            </p>
          </div>
        ) : null}
        {action === "approve" ? (
          <p className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-300">
            Approving provisions this now, under your identity. You must hold
            the permission to create it yourself — the server re-checks before
            it runs.
          </p>
        ) : null}
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Note (optional)
          </label>
          <textarea
            rows={2}
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
        {error ? (
          <p className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1.5 text-xs text-rose-600 dark:text-rose-400">
            {error}
          </p>
        ) : null}
        <div className="flex justify-end gap-2">
          <HeaderButton variant="secondary" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            variant={action === "approve" ? "primary" : "destructive"}
            disabled={mutation.isPending}
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending ? "Working…" : title}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

export default function RequestsPage() {
  const { can, isSuperadmin } = usePermissions();
  const [showNew, setShowNew] = useState(false);
  const [decision, setDecision] = useState<{
    request: ProvisioningRequest;
    action: "approve" | "reject" | "cancel";
  } | null>(null);
  const [stateFilter, setStateFilter] = useState<ChangeRequestState | "">(
    "pending",
  );

  // Approvers get the whole queue and the decision buttons. The server
  // enforces this independently — this only decides what to render.
  // ``can`` already returns true for superadmins, so the explicit check is
  // only for readability at the call sites below.
  const canApprove = isSuperadmin || can("approve", "change_request");
  const canSubmit = isSuperadmin || can("write", "provisioning_request");

  // Own-row detection for the Withdraw affordance. Cached under the shared
  // ["me"] key other pages already use, so this adds no extra request.
  const me = useQuery({ queryKey: ["me"], queryFn: authApi.me });
  const myUserId = me.data?.id;

  const catalog = useQuery({
    queryKey: ["provisioning-requests", "catalog"],
    queryFn: requestsApi.catalog,
    enabled: canSubmit,
  });

  const list = useQuery({
    queryKey: ["provisioning-requests", "list", stateFilter],
    queryFn: () => requestsApi.list(stateFilter ? { state: stateFilter } : {}),
    refetchInterval: pollUnlessRefused(30000),
  });

  const rows = list.data ?? [];

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold">Requests</h1>
          <p className="text-sm text-muted-foreground">
            {canApprove
              ? "Requests waiting on an approver. Approving provisions the resource under your identity."
              : !canSubmit
                ? "Requests made through the self-service portal."
                : "Ask for an IP, subnet, DNS record or DHCP reservation. An approver reviews it before anything is created."}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <select
            className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
            value={stateFilter}
            onChange={(e) =>
              setStateFilter(e.target.value as ChangeRequestState | "")
            }
          >
            <option value="">All states</option>
            <option value="pending">Pending</option>
            <option value="executed">Provisioned</option>
            <option value="rejected">Rejected</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
            <option value="expired">Expired</option>
          </select>
          <HeaderButton variant="secondary" onClick={() => void list.refetch()}>
            Refresh
          </HeaderButton>
          {canSubmit ? (
            <HeaderButton variant="primary" onClick={() => setShowNew(true)}>
              <Plus className="h-4 w-4" /> New request
            </HeaderButton>
          ) : null}
        </div>
      </div>

      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full min-w-[52rem] text-sm">
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Request</th>
              <th className="px-3 py-2 text-left font-medium">State</th>
              <th className="px-3 py-2 text-left font-medium">Requester</th>
              <th className="px-3 py-2 text-left font-medium">Submitted</th>
              <th className="px-3 py-2 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {list.isLoading ? (
              <tr>
                <td
                  colSpan={5}
                  className="px-3 py-8 text-center text-muted-foreground"
                >
                  Loading…
                </td>
              </tr>
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-10 text-center">
                  <Inbox className="mx-auto mb-2 h-6 w-6 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">
                    <ListEmpty error={list.error} what="requests">
                      No requests
                      {stateFilter ? ` in state "${stateFilter}"` : ""}.
                    </ListEmpty>
                  </p>
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr key={r.id} className="align-top">
                  <td className="px-3 py-2">
                    <p className="font-medium">{r.resource_display}</p>
                    <p className="whitespace-pre-wrap break-words text-xs text-muted-foreground">
                      {r.preview_text}
                    </p>
                    {r.justification ? (
                      <p className="mt-1 break-words text-xs italic text-muted-foreground">
                        “{r.justification}”
                      </p>
                    ) : null}
                    {/* A failed request must say why — a request that
                        silently vanishes is the failure mode that destroys
                        trust in a portal (#696). */}
                    {r.error ? (
                      <p className="mt-1 break-words rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-1 text-xs text-rose-600 dark:text-rose-400">
                        {r.error}
                      </p>
                    ) : null}
                  </td>
                  <td className="px-3 py-2">
                    <StateChip state={r.state} />
                    {r.decided_by_display ? (
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        by {r.decided_by_display}
                      </p>
                    ) : null}
                    {r.decision_note ? (
                      <p
                        data-testid="decision-note"
                        className="mt-1 min-w-0 max-w-xs whitespace-pre-wrap break-words text-xs text-muted-foreground"
                      >
                        <span className="font-medium">Note:</span>{" "}
                        {r.decision_note}
                      </p>
                    ) : null}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {r.requested_by_display}
                  </td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {fmtTime(r.created_at)}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-1.5">
                      {r.state === "pending" && canApprove ? (
                        <>
                          <HeaderButton
                            variant="primary"
                            onClick={() =>
                              setDecision({ request: r, action: "approve" })
                            }
                          >
                            Approve
                          </HeaderButton>
                          <HeaderButton
                            variant="destructive"
                            onClick={() =>
                              setDecision({ request: r, action: "reject" })
                            }
                          >
                            Reject
                          </HeaderButton>
                        </>
                      ) : null}
                      {/* Withdraw is the REQUESTER's affordance. The server
                          allows only the requester (or a superadmin) to
                          cancel, so showing it to an approver on someone
                          else's row just hands them a 403. */}
                      {r.state === "pending" &&
                      (isSuperadmin || r.requested_by_user_id === myUserId) ? (
                        <HeaderButton
                          variant="secondary"
                          onClick={() =>
                            setDecision({ request: r, action: "cancel" })
                          }
                        >
                          Withdraw
                        </HeaderButton>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showNew ? (
        <NewRequestModal
          kinds={catalog.data ?? []}
          onClose={() => setShowNew(false)}
        />
      ) : null}
      {decision ? (
        <DecisionModal
          request={decision.request}
          action={decision.action}
          onClose={() => setDecision(null)}
        />
      ) : null}
    </div>
  );
}
