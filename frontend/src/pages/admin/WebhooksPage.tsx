/**
 * WebhooksPage — admin surface for typed-event subscriptions.
 *
 * Distinct from Settings → Audit Event Forwarding (which fires on
 * every audit row in the operator's chosen wire format). This page
 * subscribes to **typed events** (``subnet.created``,
 * ``ip.allocated``, ``zone.modified``, …) shaped for downstream
 * automation, with HMAC signing and an outbox-backed delivery queue
 * (exponential-backoff retry + dead-letter state).
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  ChevronRight,
  Copy,
  KeyRound,
  Pencil,
  Plus,
  RotateCw,
  Send,
  Trash2,
  Zap,
} from "lucide-react";
import {
  type WebhookDelivery,
  type WebhookSubscription,
  type WebhookSubscriptionWrite,
  type WebhookTestResult,
  webhooksApi,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { ListReadError } from "@/components/ui/list-read-error";
import { copyToClipboard } from "@/lib/clipboard";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground/80">{hint}</p>}
    </div>
  );
}

// ── Subscription editor ────────────────────────────────────────────────────

function SubscriptionEditor({
  existing,
  eventTypeVocab,
  onClose,
}: {
  existing: WebhookSubscription | null;
  eventTypeVocab: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [url, setUrl] = useState(existing?.url ?? "");
  const [secret, setSecret] = useState("");
  // Edit only: send `secret: ""`, which the API reads as "store no secret".
  // An empty field is `null` ("keep"), so without this the console could
  // not remove a webhook's secret at all (#1397).
  const [removeSecret, setRemoveSecret] = useState(false);
  const [eventTypes, setEventTypes] = useState<string[]>(
    existing?.event_types ?? [],
  );
  const [eventFilter, setEventFilter] = useState("");
  const [headers, setHeaders] = useState<string>(
    existing?.headers
      ? Object.entries(existing.headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n")
      : "",
  );
  const [timeoutSeconds, setTimeoutSeconds] = useState(
    existing?.timeout_seconds ?? 10,
  );
  const [maxAttempts, setMaxAttempts] = useState(existing?.max_attempts ?? 8);
  const [error, setError] = useState<string | null>(null);
  // The newly-issued secret comes back exactly once — surface it via
  // a "secret revealed" panel inside the modal so the operator can
  // copy it before the modal closes. The list query never sees it.
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  const parseHeaders = (): Record<string, string> | null => {
    const lines = headers
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (lines.length === 0) return null;
    const out: Record<string, string> = {};
    for (const line of lines) {
      const idx = line.indexOf(":");
      if (idx < 1) continue;
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + 1).trim();
      if (k) out[k] = v;
    }
    return Object.keys(out).length > 0 ? out : null;
  };

  const mut = useMutation({
    mutationFn: async () => {
      const body: WebhookSubscriptionWrite = {
        name: name.trim(),
        description: description.trim(),
        enabled,
        url: url.trim(),
        event_types: eventTypes.length > 0 ? eventTypes : null,
        headers: parseHeaders(),
        timeout_seconds: timeoutSeconds,
        max_attempts: maxAttempts,
        // ``null`` on edit when the operator didn't retype it = keep
        // existing; ``""`` = remove it. On create we let the server
        // auto-generate.
        secret: existing
          ? removeSecret
            ? ""
            : secret.length > 0
              ? secret
              : null
          : secret.length > 0
            ? secret
            : undefined,
      };
      if (existing) {
        return webhooksApi.update(existing.id, body);
      }
      return webhooksApi.create(body);
    },
    onSuccess: (sub) => {
      qc.invalidateQueries({ queryKey: ["webhooks"] });
      // Show the cleartext secret one final time before closing.
      if (sub.secret_plaintext) {
        setRevealedSecret(sub.secret_plaintext);
      } else {
        onClose();
      }
    },
    onError: (e: unknown) => {
      const err = e as { response?: { data?: { detail?: string } } };
      setError(err?.response?.data?.detail ?? "Save failed");
    },
  });

  const filteredVocab = useMemo(() => {
    if (!eventFilter.trim()) return eventTypeVocab;
    const f = eventFilter.toLowerCase();
    return eventTypeVocab.filter((t) => t.toLowerCase().includes(f));
  }, [eventFilter, eventTypeVocab]);

  if (revealedSecret) {
    return (
      <Modal
        onClose={onClose}
        title="Webhook secret — copy now, this is the only chance"
        wide
      >
        <div className="space-y-3">
          <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-200">
            <div className="mb-1 flex items-center gap-2 font-medium">
              <AlertTriangle className="h-4 w-4" />
              Stored encrypted at rest. The server will not display it again —
              copy it now into your receiver's HMAC verifier.
            </div>
            Use it as the HMAC-SHA256 key over{" "}
            <span className="font-mono">{`<X-SpatiumDDI-Timestamp>`}</span> +{" "}
            <span className="font-mono">"."</span> + the raw request body.
            Compare against the{" "}
            <span className="font-mono">{`X-SpatiumDDI-Signature`}</span> header
            (format <span className="font-mono">sha256=&lt;hex&gt;</span>).
          </div>
          <div className="rounded-md border bg-muted/30 p-3">
            <div className="mb-1 flex items-center justify-between">
              <span className="text-xs font-medium text-muted-foreground">
                Secret
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(revealedSecret)}
                className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs hover:bg-accent"
              >
                <Copy className="h-3 w-3" /> Copy
              </button>
            </div>
            <code className="block break-all font-mono text-sm">
              {revealedSecret}
            </code>
          </div>
          <div className="flex justify-end">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90"
            >
              Done — I've stored the secret
            </button>
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal
      onClose={onClose}
      title={
        existing ? "Edit webhook subscription" : "New webhook subscription"
      }
      wide
    >
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. ops-automation"
            />
          </Field>
          <Field label="Enabled">
            <select
              className={inputCls}
              value={enabled ? "1" : "0"}
              onChange={(e) => setEnabled(e.target.value === "1")}
            >
              <option value="1">Enabled</option>
              <option value="0">Disabled</option>
            </select>
          </Field>
        </div>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What this receiver does (free text)"
          />
        </Field>
        <Field
          label="URL"
          hint="HTTPS strongly preferred. Secret-based HMAC signing protects authenticity but TLS protects transport."
        >
          <input
            className={cn(inputCls, "font-mono")}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://automation.example.com/spddi"
          />
        </Field>
        <Field
          label={existing ? "Rotate secret (optional)" : "Secret (optional)"}
          hint={
            existing
              ? existing.secret_set
                ? "Leave blank to keep the stored secret, or type a new one to rotate it."
                : "No secret is stored, so deliveries go unsigned. Type one to sign them."
              : "Leave blank and the server will auto-generate a 32-byte secret. We surface it once after create — copy and store it on your receiver."
          }
        >
          <input
            type="password"
            autoComplete="new-password"
            className={cn(inputCls, "font-mono")}
            value={removeSecret ? "" : secret}
            disabled={removeSecret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder={
              existing && existing.secret_set && !removeSecret ? "(stored)" : ""
            }
          />
          {existing?.secret_set && (
            <label className="flex cursor-pointer items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={removeSecret}
                onChange={(e) => setRemoveSecret(e.target.checked)}
              />
              Remove the stored secret: deliveries then go unsigned, with no
              X-SpatiumDDI-Signature header.
            </label>
          )}
        </Field>

        <div className="rounded-md border p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">
              Event types ({eventTypes.length} of {eventTypeVocab.length}{" "}
              selected · empty = all)
            </span>
            <input
              className="rounded border bg-background px-2 py-0.5 text-xs"
              value={eventFilter}
              onChange={(e) => setEventFilter(e.target.value)}
              placeholder="Filter…"
            />
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 max-h-60 overflow-y-auto sm:grid-cols-3">
            {filteredVocab.map((t) => {
              const checked = eventTypes.includes(t);
              return (
                <label
                  key={t}
                  title={t}
                  className="flex min-w-0 items-center gap-2 text-xs font-mono cursor-pointer"
                >
                  <input
                    type="checkbox"
                    className="shrink-0"
                    checked={checked}
                    onChange={(e) => {
                      setEventTypes((prev) => {
                        if (e.target.checked) {
                          return prev.includes(t) ? prev : [...prev, t];
                        }
                        return prev.filter((x) => x !== t);
                      });
                    }}
                  />
                  <span className="truncate">{t}</span>
                </label>
              );
            })}
          </div>
        </div>

        <Field
          label="Custom headers (optional)"
          hint="One header per line, ``Key: value`` format. ``X-SpatiumDDI-*`` reserved for the platform."
        >
          <textarea
            className={cn(inputCls, "font-mono min-h-[60px]")}
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            placeholder={`Authorization: Bearer …\nX-Custom: value`}
          />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Timeout (seconds)"
            hint="Per-attempt HTTP timeout. Range 1–30."
          >
            <input
              type="number"
              min={1}
              max={30}
              className={inputCls}
              value={timeoutSeconds}
              onChange={(e) =>
                setTimeoutSeconds(
                  Math.max(1, Math.min(30, Number(e.target.value) || 10)),
                )
              }
            />
          </Field>
          <Field
            label="Max attempts"
            hint="After this many failed deliveries the row goes to the dead-letter state. 1–20."
          >
            <input
              type="number"
              min={1}
              max={20}
              className={inputCls}
              value={maxAttempts}
              onChange={(e) =>
                setMaxAttempts(
                  Math.max(1, Math.min(20, Number(e.target.value) || 8)),
                )
              }
            />
          </Field>
        </div>

        {error && <p className="text-xs text-red-600">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!name.trim() || !url.trim() || mut.isPending}
            onClick={() => mut.mutate()}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Deliveries panel ───────────────────────────────────────────────────────

function DeliveriesPanel({ subId }: { subId: string }) {
  const qc = useQueryClient();
  const { data: rows = [], isFetching } = useQuery({
    queryKey: ["webhook-deliveries", subId],
    queryFn: () => webhooksApi.listDeliveries(subId, 100),
    refetchInterval: 8_000,
  });
  const retry = useMutation({
    mutationFn: (id: string) => webhooksApi.retryDelivery(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["webhook-deliveries", subId] }),
  });

  return (
    <div className="rounded-md border bg-muted/10">
      <div className="flex items-center justify-between border-b px-3 py-2">
        <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Recent deliveries
        </span>
        <span className="text-[11px] text-muted-foreground">
          {isFetching ? "refreshing…" : `${rows.length} rows`}
        </span>
      </div>
      {rows.length === 0 ? (
        <p className="px-3 py-3 text-xs text-muted-foreground">
          No deliveries yet. Trigger an audit-emitting action (allocate an IP,
          create a zone, …) and watch the rows land within ~10 s.
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead className="bg-muted/40 text-[11px] uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="px-3 py-1.5 text-left">Event</th>
              <th className="px-3 py-1.5 text-left">State</th>
              <th className="px-3 py-1.5 text-left">Attempts</th>
              <th className="px-3 py-1.5 text-left">Last result</th>
              <th className="px-3 py-1.5 text-left">When</th>
              <th className="px-3 py-1.5"></th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {rows.map((r) => (
              <DeliveryRow
                key={r.id}
                row={r}
                onRetry={() => retry.mutate(r.id)}
                retrying={retry.isPending}
              />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function stateColour(state: WebhookDelivery["state"]) {
  switch (state) {
    case "delivered":
      return "text-emerald-600 dark:text-emerald-400";
    case "in_flight":
    case "pending":
      return "text-blue-600 dark:text-blue-400";
    case "failed":
      return "text-amber-600 dark:text-amber-400";
    case "dead":
      return "text-rose-600 dark:text-rose-400";
  }
}

function DeliveryRow({
  row,
  onRetry,
  retrying,
}: {
  row: WebhookDelivery;
  onRetry: () => void;
  retrying: boolean;
}) {
  const created = new Date(row.created_at);
  const lastResult =
    row.state === "delivered"
      ? `${row.last_status_code ?? ""}`
      : row.last_error
        ? `${row.last_status_code ?? "—"} ${row.last_error.slice(0, 60)}`
        : "—";
  return (
    <tr className="border-t">
      <td className="px-3 py-1.5 font-mono">{row.event_type}</td>
      <td
        className={cn(
          "px-3 py-1.5 text-[11px] font-semibold uppercase",
          stateColour(row.state),
        )}
      >
        {row.state}
      </td>
      <td className="px-3 py-1.5 tabular-nums">{row.attempts}</td>
      <td
        className="px-3 py-1.5 text-muted-foreground truncate max-w-[280px]"
        title={lastResult}
      >
        {lastResult}
      </td>
      <td className="px-3 py-1.5 text-muted-foreground" title={row.created_at}>
        {created.toLocaleString()}
      </td>
      <td className="px-3 py-1.5 text-right">
        {(row.state === "failed" || row.state === "dead") && (
          <button
            type="button"
            disabled={retrying}
            onClick={onRetry}
            className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs hover:bg-accent disabled:opacity-50"
            title="Reset to pending — next worker tick will re-deliver"
          >
            <RotateCw className="h-3 w-3" />
            Retry
          </button>
        )}
      </td>
    </tr>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

export function WebhooksPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<WebhookSubscription | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [testFlash, setTestFlash] = useState<
    Record<string, WebhookTestResult | undefined>
  >({});
  const [confirm, setConfirm] = useState<{
    name: string;
    onConfirm: () => void;
  } | null>(null);

  const {
    data: subs = [],
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["webhooks"],
    queryFn: webhooksApi.list,
  });
  const { data: vocab = [] } = useQuery({
    queryKey: ["webhook-event-types"],
    queryFn: webhooksApi.listEventTypes,
    staleTime: 5 * 60_000,
  });

  const del = useMutation({
    mutationFn: (id: string) => webhooksApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });

  const test = useMutation({
    mutationFn: (id: string) => webhooksApi.test(id),
    onSuccess: (result, id) => {
      setTestFlash((prev) => ({ ...prev, [id]: result }));
      window.setTimeout(() => {
        setTestFlash((prev) => {
          const { [id]: _drop, ...rest } = prev;
          return rest;
        });
      }, 6000);
    },
  });

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-6xl space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold">Webhooks</h1>
            <p className="max-w-2xl text-xs text-muted-foreground">
              Typed-event subscriptions for downstream automation. Every enabled
              subscription whose event-type filter matches receives one
              HMAC-signed POST per event with exponential-backoff retry and a
              dead-letter state. Distinct from the generic audit-forward webhook
              under Settings — that ships every audit row in your chosen wire
              format; this fires typed events shaped for code.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90"
          >
            <Plus className="h-4 w-4" />
            New subscription
          </button>
        </div>

        {isLoading ? (
          <p className="text-xs text-muted-foreground">Loading…</p>
        ) : subs.length === 0 && isError ? (
          // A refused or failed read is not an empty list (#1343).
          <div className="rounded-md border bg-muted/20 p-6 text-center text-sm">
            <ListReadError error={error} what="webhook subscriptions" />
          </div>
        ) : subs.length === 0 ? (
          <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
            No subscriptions yet. The platform is publishing typed events into
            the void.
          </div>
        ) : (
          <div className="space-y-3">
            {subs.map((s) => (
              <div key={s.id} className="rounded-md border bg-card">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b p-3">
                  <button
                    type="button"
                    onClick={() =>
                      setExpanded((prev) => ({ ...prev, [s.id]: !prev[s.id] }))
                    }
                    className="flex flex-1 items-center gap-2 text-left"
                  >
                    <ChevronRight
                      className={cn(
                        "h-4 w-4 transition-transform",
                        expanded[s.id] && "rotate-90",
                      )}
                    />
                    <span className="font-medium">{s.name}</span>
                    {s.enabled ? (
                      <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400">
                        <Check className="h-3 w-3" /> enabled
                      </span>
                    ) : (
                      <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
                        disabled
                      </span>
                    )}
                    {s.secret_set && (
                      <span
                        className="inline-flex items-center gap-1 text-[10px] text-muted-foreground"
                        title="HMAC-SHA256 signature on every delivery"
                      >
                        <KeyRound className="h-3 w-3" /> signed
                      </span>
                    )}
                    <span className="ml-2 truncate font-mono text-xs text-muted-foreground">
                      {s.url}
                    </span>
                  </button>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      disabled={test.isPending}
                      onClick={() => test.mutate(s.id)}
                      className="inline-flex items-center gap-1 rounded border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
                      title="Send a synthetic ``test.ping`` event through the same signing + transport path the worker uses"
                    >
                      <Send className="h-3 w-3" /> Test
                    </button>
                    <button
                      type="button"
                      onClick={() => setEditing(s)}
                      className="inline-flex items-center gap-1 rounded border px-2 py-1 text-xs hover:bg-accent"
                    >
                      <Pencil className="h-3 w-3" /> Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setConfirm({
                          name: s.name,
                          onConfirm: () => del.mutate(s.id),
                        });
                      }}
                      className="inline-flex items-center gap-1 rounded border border-rose-300 px-2 py-1 text-xs text-rose-600 hover:bg-rose-50 dark:border-rose-900 dark:hover:bg-rose-900/20"
                    >
                      <Trash2 className="h-3 w-3" /> Delete
                    </button>
                  </div>
                </div>

                {testFlash[s.id] && (
                  <div
                    className={cn(
                      "border-b px-3 py-2 text-xs",
                      testFlash[s.id]!.status === "ok"
                        ? "bg-emerald-50 text-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-300"
                        : "bg-rose-50 text-rose-800 dark:bg-rose-900/20 dark:text-rose-300",
                    )}
                  >
                    <Zap className="mr-1 inline h-3 w-3" />
                    {testFlash[s.id]!.status === "ok"
                      ? `Delivered (HTTP ${testFlash[s.id]!.status_code})`
                      : `Failed: ${testFlash[s.id]!.error ?? "unknown"}`}
                  </div>
                )}

                <div className="px-3 py-2 text-xs text-muted-foreground">
                  <span className="mr-3">
                    <strong>Events:</strong>{" "}
                    {s.event_types && s.event_types.length > 0
                      ? `${s.event_types.length} types`
                      : "all"}
                  </span>
                  <span className="mr-3">
                    <strong>Timeout:</strong> {s.timeout_seconds}s
                  </span>
                  <span>
                    <strong>Max attempts:</strong> {s.max_attempts}
                  </span>
                </div>

                {expanded[s.id] && (
                  <div className="border-t p-3">
                    {s.event_types && s.event_types.length > 0 && (
                      <div className="mb-2 text-[11px]">
                        <span className="font-medium text-muted-foreground">
                          Subscribed event types:
                        </span>{" "}
                        <span className="font-mono text-muted-foreground">
                          {s.event_types.join(", ")}
                        </span>
                      </div>
                    )}
                    <DeliveriesPanel subId={s.id} />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {showCreate && (
        <SubscriptionEditor
          existing={null}
          eventTypeVocab={vocab}
          onClose={() => setShowCreate(false)}
        />
      )}
      {editing && (
        <SubscriptionEditor
          existing={editing}
          eventTypeVocab={vocab}
          onClose={() => setEditing(null)}
        />
      )}
      <ConfirmModal
        open={confirm !== null}
        title="Delete subscription"
        message={`Delete subscription "${confirm?.name ?? ""}"? Pending and dead-letter deliveries are removed too.`}
        confirmLabel="Delete"
        tone="destructive"
        onConfirm={() => {
          confirm?.onConfirm();
          setConfirm(null);
        }}
        onClose={() => setConfirm(null)}
      />
    </div>
  );
}
