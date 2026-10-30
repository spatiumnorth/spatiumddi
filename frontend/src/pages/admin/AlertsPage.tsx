import { cloneElement, isValidElement, useId, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  Pencil,
  Play,
  Plus,
  Power,
  PowerOff,
  Trash2,
} from "lucide-react";
import {
  alertsApi,
  type AlertParamSpec,
  type AlertRule,
  type AlertRuleTypeSpec,
  type AlertRuleUpdate,
  type AlertSeverity,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { errMsg } from "@/pages/dhcp/_shared";
import { AskAIButton } from "@/components/copilot/AskAIButton";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// #1994 — the label names its control: the single child element gets an
// `id` and the label a matching `htmlFor`, so a screen reader (or a
// search by label) finds the control.
function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactElement<{ id?: string }>;
}) {
  const id = useId();
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {isValidElement(children) ? cloneElement(children, { id }) : children}
      {hint && <p className="text-[11px] text-muted-foreground/80">{hint}</p>}
    </div>
  );
}

// A numeric input's value: a stored null stays empty, never a default.
const numVal = (n: number | null): number | string => (n === null ? "" : n);
const parseNum = (v: string): number | null => (v === "" ? null : Number(v));

// A select's empty value ("") means NULL on the wire.
const norm = (v: unknown): unknown => (v === "" || v === undefined ? null : v);

// What the control shows for a stored value. A stored null stays empty for a
// number (#1986); a select has no empty option unless the catalogue lists
// one, so it shows the value the evaluator reads the null as (or, for a
// required parameter with no such value, the first option).
function shownFor(p: AlertParamSpec, stored: unknown): number | string | null {
  if (stored !== null && stored !== undefined) return stored as number | string;
  if (p.kind === "integer") return null;
  return p.default ?? p.initial ?? p.options[0]?.value ?? null;
}

// A new rule's starting value when the catalogue names no ``initial``: the
// evaluator's default, unless the API would refuse it (dns_query_rate_spike's
// 200% is above threshold_percent's 0..100) — then empty, which the evaluator
// reads as that same default.
function newRuleDefault(p: AlertParamSpec): number | string | null {
  if (p.kind === "select") return shownFor(p, null);
  const d = p.default;
  if (typeof d !== "number") return null;
  if ((p.min != null && d < p.min) || (p.max != null && d > p.max)) return null;
  return d;
}

// ── Rule editor ────────────────────────────────────────────────────────────

export function RuleEditorModal({
  existing,
  onClose,
}: {
  existing: AlertRule | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  // #1997 — the rule types and each one's editable parameters come from the
  // backend, so a type added there is editable here with no change.
  const catalogue = useQuery({
    queryKey: ["alert-rule-types"],
    queryFn: alertsApi.ruleTypes,
    staleTime: 5 * 60_000,
  });
  const types = catalogue.data;
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [pickedType, setPickedType] = useState<string | null>(null);
  const ruleType =
    existing?.rule_type ??
    pickedType ??
    types?.find((t) => t.rule_type === "subnet_utilization")?.rule_type ??
    types?.[0]?.rule_type ??
    null;
  const spec = types?.find((t) => t.rule_type === ruleType) ?? null;
  // Only what the operator has touched; everything else shows (and keeps)
  // the stored value, or the type's starting value on a new rule.
  const [touched, setTouched] = useState<Record<string, unknown>>({});
  const [severity, setSeverity] = useState<AlertSeverity>(
    existing?.severity ?? "warning",
  );
  const [notifySyslog, setNotifySyslog] = useState(
    existing?.notify_syslog ?? true,
  );
  const [notifyWebhook, setNotifyWebhook] = useState(
    existing?.notify_webhook ?? true,
  );
  const [notifySmtp, setNotifySmtp] = useState(existing?.notify_smtp ?? false);
  const [error, setError] = useState<string | null>(null);

  const stored = existing as unknown as Record<string, unknown> | null;
  const current = (p: AlertParamSpec): number | string | null => {
    if (p.name in touched) return touched[p.name] as number | string | null;
    if (stored) return shownFor(p, stored[p.name]);
    return p.initial ?? newRuleDefault(p);
  };
  const setParam = (n: string, v: number | string | null) =>
    setTouched((t) => ({ ...t, [n]: v }));

  const mut = useMutation({
    mutationFn: async () => {
      const base: AlertRuleUpdate = {
        name,
        description,
        enabled,
        severity,
        notify_syslog: notifySyslog,
        notify_webhook: notifyWebhook,
        notify_smtp: notifySmtp,
      };
      // Only the parameters this rule type has are ever sent.
      const params: Record<string, unknown> = {};
      for (const p of spec?.params ?? []) params[p.name] = norm(current(p));
      if (existing) {
        // #1986 — send only what the operator changed; an unchanged Save
        // sends nothing at all. A stored null a select can only show as a
        // value compares as the value the evaluator reads it as, so leaving
        // the control alone is not a change; a required parameter with no
        // such value (a compliance rule's classification) is compared to
        // null, so the shown choice is sent — the server refuses any edit
        // that keeps it null (#1580).
        const was = (k: string, p?: AlertParamSpec): unknown => {
          const v = (stored as Record<string, unknown>)[k];
          if (v !== null && v !== undefined) return v;
          return p?.kind === "select" ? norm(p.default) : null;
        };
        const changed: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(base)) {
          const w = k === "description" ? (was(k) ?? "") : was(k);
          if (w !== v) changed[k] = v;
        }
        for (const p of spec?.params ?? [])
          if (norm(was(p.name, p)) !== params[p.name])
            changed[p.name] = params[p.name];
        if (Object.keys(changed).length === 0) return existing;
        return alertsApi.updateRule(existing.id, changed as AlertRuleUpdate);
      }
      return alertsApi.createRule({
        ...base,
        ...params,
        name,
        rule_type: ruleType as string,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert-rules"] });
      onClose();
    },
    onError: (e: unknown) => {
      // #1993 — a 422's `detail` is a list; render it as text.
      setError(errMsg(e, "Save failed"));
    },
  });

  // The catalogue gates a NEW rule (no type to create without it); an edit
  // can still change its non-parameter fields if the catalogue is down.
  const catalogueBlocks = !existing && !spec;
  const groups: Record<string, AlertRuleTypeSpec[]> = {};
  for (const t of types ?? [])
    if (!t.system_driven) (groups[t.group] ??= []).push(t);

  return (
    <Modal
      onClose={onClose}
      title={existing ? "Edit alert rule" : "New alert rule"}
    >
      <div className="space-y-4">
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Subnet nearing capacity"
          />
        </Field>
        <Field label="Description">
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        {!existing && (
          <Field
            label="Rule type"
            hint="Cannot be changed after creation — delete + recreate to switch."
          >
            <select
              className={inputCls}
              value={ruleType ?? ""}
              disabled={!types}
              onChange={(e) => {
                setPickedType(e.target.value);
                setTouched({});
              }}
            >
              {Object.entries(groups).map(([g, ts]) => (
                <optgroup key={g} label={g}>
                  {ts.map((t) => (
                    <option key={t.rule_type} value={t.rule_type}>
                      {t.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </Field>
        )}
        {catalogue.isLoading && (
          <p className="text-xs text-muted-foreground">
            Loading rule parameters…
          </p>
        )}
        {catalogue.isError && (
          <p className="text-xs text-red-600">
            Could not load the rule types
            {existing ? "; its parameters cannot be edited here." : "."}
          </p>
        )}
        {existing && types && !spec && (
          // #2130 — the catalogue leaves out a type whose feature module is
          // off. The rule is kept as stored (no parameter is sent on Save)
          // and is not evaluated until the module is back on.
          <p className="text-xs text-muted-foreground">
            This rule&apos;s type belongs to a feature module that is turned
            off, so it is not evaluated. Its parameters are kept as stored and
            can be edited again once the module is on.
          </p>
        )}
        {spec?.params.map((p) => (
          <Field
            key={p.name}
            label={p.label}
            hint={
              p.hint
                ? p.default != null &&
                  p.kind === "integer" &&
                  p.hint.indexOf("Default") < 0
                  ? `${p.hint} Empty uses ${p.default}${p.unit === "%" ? "%" : p.unit === "days" ? " d" : ""}.`
                  : p.hint
                : undefined
            }
          >
            {p.kind === "select" ? (
              <select
                className={inputCls}
                value={String(current(p) ?? "")}
                onChange={(e) => setParam(p.name, e.target.value)}
              >
                {p.options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="number"
                min={p.min ?? undefined}
                max={p.max ?? undefined}
                className={inputCls}
                value={numVal(current(p) as number | null)}
                onChange={(e) => setParam(p.name, parseNum(e.target.value))}
              />
            )}
          </Field>
        ))}
        {spec && spec.params.length === 0 && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            No adjustable parameters.
          </p>
        )}
        {spec?.description && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            {spec.description}
          </p>
        )}
        {existing && !spec && types && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            This server does not describe rule type{" "}
            <code>{existing.rule_type}</code>; stored parameters are kept as
            they are.
          </p>
        )}
        <Field label="Severity">
          <select
            className={inputCls}
            value={severity}
            onChange={(e) => setSeverity(e.target.value as AlertSeverity)}
          >
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </Field>
        <div className="rounded-md border bg-muted/20 p-3 space-y-2">
          <p className="text-xs font-medium text-muted-foreground">
            Delivery channels
          </p>
          <p className="text-[11px] text-muted-foreground/80">
            Fans out to every enabled target of the matching kind in Settings →
            Audit Event Forwarding (webhook covers Slack / Teams / Discord chat
            flavors automatically).
          </p>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={notifySyslog}
              onChange={(e) => setNotifySyslog(e.target.checked)}
            />
            Syslog
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={notifyWebhook}
              onChange={(e) => setNotifyWebhook(e.target.checked)}
            />
            Webhook (incl. Slack / Teams / Discord)
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={notifySmtp}
              onChange={(e) => setNotifySmtp(e.target.checked)}
            />
            Email (SMTP)
          </label>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Rule enabled
        </label>
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
            disabled={
              !name.trim() ||
              mut.isPending ||
              catalogueBlocks ||
              (!!existing && catalogue.isLoading)
            }
            onClick={() => mut.mutate()}
            className={cn(
              "rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground",
              "hover:bg-primary/90 disabled:opacity-50",
            )}
          >
            {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// The Parameters cell: each parameter the type has, a stored null shown as
// the value the evaluator reads it as (#1997).
function paramSummary(r: AlertRule, spec?: AlertRuleTypeSpec): string {
  if (!spec || spec.params.length === 0) return "—";
  const row = r as unknown as Record<string, unknown>;
  return (
    spec.params
      .map((p) => {
        const v = row[p.name] ?? p.default;
        if (v === null || v === undefined || v === "") return null;
        if (p.kind === "select")
          return `${p.label}: ${p.options.find((o) => o.value === v)?.label ?? v}`;
        const unit = p.unit === "%" ? "%" : p.unit === "days" ? " d" : "";
        return `${p.label}: ${v}${unit}`;
      })
      .filter(Boolean)
      .join(" · ") || "—"
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

export function AlertsPage() {
  // #1341 — every write on this page takes a superadmin (its handlers
  // take SuperAdmin), so a read-only user is offered none of them.
  const superadminGate = permissionGate(
    usePermissions().isSuperadmin,
    NEEDS_SUPERADMIN,
  );
  const qc = useQueryClient();
  const [editing, setEditing] = useState<AlertRule | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [openOnly, setOpenOnly] = useState(true);

  const { data: rules = [], isLoading: rulesLoading } = useQuery({
    queryKey: ["alert-rules"],
    queryFn: alertsApi.listRules,
  });

  const { data: ruleTypes } = useQuery({
    queryKey: ["alert-rule-types"],
    queryFn: alertsApi.ruleTypes,
    staleTime: 5 * 60_000,
  });
  const specByType = new Map((ruleTypes ?? []).map((t) => [t.rule_type, t]));

  const { data: events = [] } = useQuery({
    queryKey: ["alert-events", { openOnly }],
    queryFn: () => alertsApi.listEvents({ open_only: openOnly, limit: 100 }),
    refetchInterval: 15_000,
  });

  const toggle = useMutation({
    mutationFn: (r: AlertRule) =>
      alertsApi.updateRule(r.id, { enabled: !r.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alert-rules"] }),
  });

  const del = useMutation({
    mutationFn: (id: string) => alertsApi.deleteRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alert-rules"] }),
  });

  const evaluate = useMutation({
    mutationFn: () => alertsApi.evaluateNow(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert-events"] });
    },
  });

  const resolve = useMutation({
    mutationFn: (id: string) => alertsApi.resolveEvent(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alert-events"] }),
  });

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-[1200px] space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Rule-based notifications on subnet utilization + server health.
              Each rule notifies by syslog, webhook or email (SMTP), as set on
              the rule.
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => evaluate.mutate()}
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
              disabled={evaluate.isPending}
              {...superadminGate}
            >
              <Play className="h-3.5 w-3.5" />
              {evaluate.isPending ? "Evaluating…" : "Evaluate now"}
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground",
                "hover:bg-primary/90",
              )}
              {...superadminGate}
            >
              <Plus className="h-3.5 w-3.5" />
              New rule
            </button>
          </div>
        </div>

        {/* ── Events (first, deliberately) ──────────────────────────
              Events are what an operator acts on; rules are the
              configuration that produces them. With a populated rule
              table this section used to sit well below the fold, so
              arriving here from the dashboard's "N alerts open" pill
              landed on a screen of rules with the alerts themselves
              off-screen — the pill's whole job is to show them (#942).
              ``openOnly`` already defaults on, so this opens on
              exactly what the pill counted. ─────────────────────── */}
        <div className="rounded-lg border bg-card">
          <div className="flex items-center justify-between border-b px-4 py-2.5">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <h2 className="text-sm font-semibold">Events</h2>
              <span className="text-xs text-muted-foreground">
                {events.length} shown
              </span>
            </div>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={openOnly}
                onChange={(e) => setOpenOnly(e.target.checked)}
              />
              Open only
            </label>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted-foreground">
                <tr className="border-b">
                  <th className="px-4 py-2 text-left">Fired</th>
                  <th className="px-4 py-2 text-left">Severity</th>
                  <th className="px-4 py-2 text-left">Subject</th>
                  <th className="px-4 py-2 text-left">Message</th>
                  <th className="px-4 py-2 text-left">State</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {events.length === 0 && (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-4 py-8 text-center text-xs text-muted-foreground"
                    >
                      {openOnly
                        ? "No open events — all clear."
                        : "No events yet."}
                    </td>
                  </tr>
                )}
                {events.map((ev) => (
                  <tr key={ev.id} className="border-b">
                    <td className="px-4 py-2 text-xs text-muted-foreground tabular-nums whitespace-nowrap">
                      {new Date(ev.fired_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2">
                      <SeverityBadge severity={ev.severity} />
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <span className="text-muted-foreground">
                        {ev.subject_type}:
                      </span>{" "}
                      <span className="font-medium">{ev.subject_display}</span>
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {ev.message}
                    </td>
                    <td className="px-4 py-2">
                      {ev.resolved_at ? (
                        <span className="text-xs text-emerald-600 dark:text-emerald-400">
                          resolved {new Date(ev.resolved_at).toLocaleString()}
                        </span>
                      ) : (
                        <span className="text-xs text-amber-600 dark:text-amber-400">
                          open
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex items-center justify-end gap-1">
                        <AskAIButton
                          context={[
                            `Alert event on ${ev.subject_type} ${ev.subject_display}`,
                            `severity: ${ev.severity}`,
                            `message: ${ev.message}`,
                            `fired_at: ${ev.fired_at}`,
                            ev.resolved_at
                              ? `resolved_at: ${ev.resolved_at}`
                              : "state: open",
                            `event_id: ${ev.id}`,
                          ].join(", ")}
                          tooltip="Ask AI about this alert"
                          prompt="Explain this alert — what tripped it, what it means, and the most likely remediation."
                          iconOnly
                          className="px-1.5 py-1"
                        />
                        {!ev.resolved_at && (
                          <button
                            onClick={() => resolve.mutate(ev.id)}
                            className="rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                            {...superadminGate}
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Rules ───────────────────────────────────────────────────── */}
        <div className="rounded-lg border bg-card">
          <div className="flex items-center justify-between border-b px-4 py-2.5">
            <h2 className="text-sm font-semibold">Rules</h2>
            <span className="text-xs text-muted-foreground">
              {rules.length} total
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase tracking-wider text-muted-foreground">
                <tr className="border-b">
                  <th className="px-4 py-2 text-left">Name</th>
                  <th className="px-4 py-2 text-left">Type</th>
                  <th className="px-4 py-2 text-left">Parameters</th>
                  <th className="px-4 py-2 text-left">Severity</th>
                  <th className="px-4 py-2 text-left">Channels</th>
                  <th className="px-4 py-2 text-left">Status</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {rulesLoading && (
                  <tr>
                    <td
                      colSpan={7}
                      className="px-4 py-8 text-center text-xs text-muted-foreground"
                    >
                      Loading…
                    </td>
                  </tr>
                )}
                {!rulesLoading && rules.length === 0 && (
                  <tr>
                    <td
                      colSpan={7}
                      className="px-4 py-8 text-center text-xs text-muted-foreground"
                    >
                      No rules yet — click “New rule” to create one.
                    </td>
                  </tr>
                )}
                {rules.map((r) => (
                  <tr key={r.id} className="border-b">
                    <td className="px-4 py-2 font-medium">{r.name}</td>
                    <td className="px-4 py-2 text-muted-foreground">
                      {r.rule_type}
                    </td>
                    <td className="px-4 py-2 text-muted-foreground tabular-nums">
                      {paramSummary(r, specByType.get(r.rule_type))}
                    </td>
                    <td className="px-4 py-2">
                      <SeverityBadge severity={r.severity} />
                    </td>
                    <td className="px-4 py-2 text-[11px] text-muted-foreground">
                      {[
                        r.notify_syslog && "syslog",
                        r.notify_webhook && "webhook",
                        r.notify_smtp && "smtp",
                      ]
                        .filter(Boolean)
                        .join(" · ") || "(none)"}
                    </td>
                    <td className="px-4 py-2">
                      {r.enabled ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                          <Check className="h-3.5 w-3.5" /> enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                          <PowerOff className="h-3.5 w-3.5" /> disabled
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex justify-end gap-1">
                        <AskAIButton
                          context={[
                            `Alert rule ${r.name}`,
                            `type: ${r.rule_type}`,
                            `severity: ${r.severity}`,
                            r.threshold_percent != null
                              ? `threshold: ${r.threshold_percent}%`
                              : null,
                            r.threshold_days != null
                              ? `threshold: ${r.threshold_days} days`
                              : null,
                            r.server_type
                              ? `server type: ${r.server_type}`
                              : null,
                            r.enabled ? "enabled" : "disabled",
                            `rule_id: ${r.id}`,
                          ]
                            .filter(Boolean)
                            .join(", ")}
                          tooltip="Ask AI about this rule"
                          prompt="Explain what this alert rule does, when it would fire, and recommend tuning if relevant."
                          iconOnly
                          className="px-1.5 py-1"
                        />
                        <button
                          onClick={() => toggle.mutate(r)}
                          title={r.enabled ? "Disable" : "Enable"}
                          className="rounded p-1.5 hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                          {...superadminGate}
                        >
                          <Power className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setEditing(r)}
                          title="Edit"
                          className="rounded p-1.5 hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                          {...superadminGate}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm(`Delete rule "${r.name}"?`)) {
                              del.mutate(r.id);
                            }
                          }}
                          title="Delete"
                          className="rounded p-1.5 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30 disabled:cursor-not-allowed disabled:opacity-50"
                          {...superadminGate}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {showCreate && (
          <RuleEditorModal
            existing={null}
            onClose={() => setShowCreate(false)}
          />
        )}
        {editing && (
          <RuleEditorModal
            existing={editing}
            onClose={() => setEditing(null)}
          />
        )}
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  const cls =
    severity === "critical"
      ? "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400"
      : severity === "warning"
        ? "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400"
        : "bg-blue-100 text-blue-700 dark:bg-blue-950/30 dark:text-blue-400";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        cls,
      )}
    >
      {severity}
    </span>
  );
}
