import { useState } from "react";
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
  type AlertChangeScope,
  type AlertClassification,
  type AlertRule,
  type AlertRuleType,
  type AlertServerType,
  type AlertSeverity,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { AskAIButton } from "@/components/copilot/AskAIButton";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// Per-rule-type sensible starting values, seeded when the operator picks a
// type in the New-rule modal. Without this, switching to e.g. stale_ip_count
// would inherit subnet_utilization's 90 / 30 and create a 90-count / 30-day
// rule that contradicts the documented 10 / 90 semantics.
const RULE_TYPE_PARAM_DEFAULTS: Partial<
  Record<AlertRuleType, { threshold?: number; thresholdDays?: number }>
> = {
  subnet_utilization: { threshold: 90 },
  voice_lease_count_below: { threshold: 10 },
  stale_ip_count: { threshold: 10, thresholdDays: 90 },
  dhcp_pool_exhaustion: { threshold: 90 },
  domain_expiring: { thresholdDays: 30 },
  circuit_term_expiring: { thresholdDays: 30 },
  service_term_expiring: { thresholdDays: 30 },
  secret_expiring: { thresholdDays: 30 },
  decom_expiring: { thresholdDays: 30 },
  // #983 Phase 2 — PSI stall %. Conservative on purpose: nobody has watched
  // PSI on a loaded appliance yet, so it starts where the reading is
  // unambiguous rather than where it is sensitive. Tune DOWN with field
  // numbers; starting low pages on day one and teaches people to ignore it.
  node_pressure: { threshold: 50 },
};

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

// ── Rule editor ────────────────────────────────────────────────────────────

function RuleEditorModal({
  existing,
  onClose,
}: {
  existing: AlertRule | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [ruleType, setRuleType] = useState<AlertRuleType>(
    existing?.rule_type ?? "subnet_utilization",
  );
  const [threshold, setThreshold] = useState<number>(
    existing?.threshold_percent ?? 90,
  );
  const [thresholdDays, setThresholdDays] = useState<number>(
    existing?.threshold_days ?? 30,
  );
  // dhcp_pool_exhaustion: 0 means "no free-address floor" (occupancy % only).
  const [minFree, setMinFree] = useState<number>(
    existing?.min_free_addresses ?? 0,
  );
  const [serverType, setServerType] = useState<AlertServerType>(
    (existing?.server_type as AlertServerType | null) ?? "any",
  );
  const [classification, setClassification] = useState<AlertClassification>(
    (existing?.classification as AlertClassification | null) ?? "pci_scope",
  );
  const [changeScope, setChangeScope] = useState<AlertChangeScope>(
    (existing?.change_scope as AlertChangeScope | null) ?? "any_change",
  );
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

  const mut = useMutation({
    mutationFn: async () => {
      const body = {
        name,
        description,
        enabled,
        severity,
        notify_syslog: notifySyslog,
        notify_webhook: notifyWebhook,
        notify_smtp: notifySmtp,
        threshold_percent:
          ruleType === "subnet_utilization" ||
          ruleType === "voice_lease_count_below" ||
          ruleType === "stale_ip_count" ||
          ruleType === "dhcp_pool_exhaustion" ||
          ruleType === "node_pressure" ||
          ruleType === "backup_stale"
            ? threshold
            : null,
        min_free_addresses:
          ruleType === "dhcp_pool_exhaustion" && minFree > 0 ? minFree : null,
        threshold_days:
          ruleType === "domain_expiring" ||
          ruleType === "circuit_term_expiring" ||
          ruleType === "service_term_expiring" ||
          ruleType === "secret_expiring" ||
          ruleType === "decom_expiring" ||
          ruleType === "stale_ip_count"
            ? thresholdDays
            : null,
        server_type: ruleType === "server_unreachable" ? serverType : null,
        classification:
          ruleType === "compliance_change" ? classification : null,
        change_scope: ruleType === "compliance_change" ? changeScope : null,
      };
      if (existing) {
        return alertsApi.updateRule(existing.id, body);
      }
      return alertsApi.createRule({ ...body, rule_type: ruleType });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alert-rules"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as { response?: { data?: { detail?: string } } };
      setError(err?.response?.data?.detail ?? "Save failed");
    },
  });

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
              value={ruleType}
              onChange={(e) => {
                const next = e.target.value as AlertRuleType;
                setRuleType(next);
                const d = RULE_TYPE_PARAM_DEFAULTS[next];
                if (d?.threshold !== undefined) setThreshold(d.threshold);
                if (d?.thresholdDays !== undefined)
                  setThresholdDays(d.thresholdDays);
              }}
            >
              <optgroup label="Infrastructure">
                <option value="subnet_utilization">Subnet utilization</option>
                <option value="dhcp_pool_exhaustion">
                  DHCP pool exhaustion (dynamic pool pressure)
                </option>
                <option value="server_unreachable">Server unreachable</option>
                <option value="stale_ip_count">
                  Stale IP count (address-space hygiene)
                </option>
                <option value="node_pressure">
                  Node resource pressure (PSI stalling)
                </option>
              </optgroup>
              <optgroup label="Subnet / IPAM">
                <option value="decom_expiring">
                  Subnet decommission approaching
                </option>
              </optgroup>
              <optgroup label="Network (ASN / RPKI)">
                <option value="asn_holder_drift">ASN holder drift</option>
                <option value="asn_whois_unreachable">
                  ASN WHOIS unreachable
                </option>
                <option value="rpki_roa_expiring">RPKI ROA expiring</option>
                <option value="rpki_roa_expired">RPKI ROA expired</option>
              </optgroup>
              <optgroup label="Domains (registry)">
                <option value="domain_expiring">Domain expiring</option>
                <option value="domain_nameserver_drift">
                  Domain nameserver drift
                </option>
                <option value="domain_registrar_changed">
                  Domain registrar changed (transfer)
                </option>
                <option value="domain_dnssec_status_changed">
                  Domain DNSSEC status changed
                </option>
              </optgroup>
              <optgroup label="Circuits (WAN transport)">
                <option value="circuit_term_expiring">
                  Circuit term expiring
                </option>
                <option value="circuit_status_changed">
                  Circuit status changed (suspended / decom)
                </option>
              </optgroup>
              <optgroup label="Service catalog">
                <option value="service_term_expiring">
                  Service term expiring
                </option>
                <option value="service_resource_orphaned">
                  Service resource orphaned (target deleted)
                </option>
              </optgroup>
              <optgroup label="Compliance">
                <option value="compliance_change">
                  Compliance change (PCI / HIPAA / internet-facing)
                </option>
              </optgroup>
              <optgroup label="VoIP">
                <option value="voice_lease_count_below">
                  Voice VLAN lease count below threshold
                </option>
              </optgroup>
              <optgroup label="Security">
                <option value="secret_expiring">
                  Secret / certificate expiring
                </option>
              </optgroup>
            </select>
          </Field>
        )}
        {ruleType === "voice_lease_count_below" && (
          <Field
            label="Minimum active leases"
            hint="Fires when any subnet tagged subnet_role='voice' has fewer active DHCP leases than this. Set to roughly 50% of the expected phone fleet so brief reboots don't trigger but a real mass-disconnect does."
          >
            <input
              type="number"
              min={0}
              className={inputCls}
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
          </Field>
        )}
        {ruleType === "subnet_utilization" && (
          <Field
            label="Threshold (%)"
            hint="Fires when subnet utilization ≥ this. PTP / loopback subnets (prefix > utilization_max_prefix_*) are excluded."
          >
            <input
              type="number"
              min={0}
              max={100}
              className={inputCls}
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
          </Field>
        )}
        {ruleType === "node_pressure" && (
          <Field
            label="Stall threshold (%)"
            hint={
              "Warns when CPU or memory 'some' stalling holds at or above this " +
              "across a 5-minute window — the share of wall time at least one " +
              "task was blocked waiting for the resource. Separate from the " +
              "fixed 1% memory 'full' floor, which is always critical: 'some' " +
              "at 20% is a busy node, 'full' at 20% is a node doing no work. " +
              "Silent on nodes whose kubelet does not report PSI (below " +
              "Kubernetes 1.36)."
            }
          >
            <input
              type="number"
              min={0}
              max={100}
              className={inputCls}
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
          </Field>
        )}
        {ruleType === "backup_stale" && (
          <Field
            label="Missed runs"
            hint="Fires when a scheduled backup target has had no successful run for this many scheduled runs, plus one hour. Default 2."
          >
            <input
              type="number"
              min={1}
              max={100}
              className={inputCls}
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
          </Field>
        )}
        {ruleType === "dhcp_pool_exhaustion" && (
          <>
            <Field
              label="Occupancy threshold (%)"
              hint="Fires when a dynamic DHCP pool's live occupancy (active leases ÷ pool size) reaches this. Orthogonal to subnet utilization, which counts allocated IPAM rows — a pool can be exhausted while the subnet looks empty."
            >
              <input
                type="number"
                min={0}
                max={100}
                className={inputCls}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
              />
            </Field>
            <Field
              label="Minimum free addresses (optional)"
              hint="Also fire when fewer than this many addresses are free in the pool, regardless of percent. Set 0 to use the percent threshold only."
            >
              <input
                type="number"
                min={0}
                className={inputCls}
                value={minFree}
                onChange={(e) => setMinFree(Number(e.target.value))}
              />
            </Field>
          </>
        )}
        {ruleType === "stale_ip_count" && (
          <>
            <Field
              label="Stale IP count threshold"
              hint="Fires when a subnet holds at least this many allocated IPs that haven't been seen on the wire in the window below. Reads the discovery last-seen signal; never-seen rows are excluded (chase those from the Stale-IP report)."
            >
              <input
                type="number"
                min={1}
                className={inputCls}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
              />
            </Field>
            <Field
              label="Stale window (days)"
              hint="An allocated IP counts as stale once its last-seen timestamp is older than this. Default 90."
            >
              <input
                type="number"
                min={1}
                max={3650}
                className={inputCls}
                value={thresholdDays}
                onChange={(e) => setThresholdDays(Number(e.target.value))}
              />
            </Field>
          </>
        )}
        {ruleType === "server_unreachable" && (
          <Field label="Server type">
            <select
              className={inputCls}
              value={serverType}
              onChange={(e) => setServerType(e.target.value as AlertServerType)}
            >
              <option value="any">DNS + DHCP</option>
              <option value="dns">DNS only</option>
              <option value="dhcp">DHCP only</option>
            </select>
          </Field>
        )}
        {(ruleType === "domain_expiring" ||
          ruleType === "circuit_term_expiring" ||
          ruleType === "service_term_expiring" ||
          ruleType === "secret_expiring" ||
          ruleType === "decom_expiring") && (
          <Field
            label="Threshold (days)"
            hint="Soft fire at threshold; severity escalates to warning at threshold/4 and critical at threshold/12 (e.g. 30 → 7.5 → 2.5 d)."
          >
            <input
              type="number"
              min={1}
              max={3650}
              className={inputCls}
              value={thresholdDays}
              onChange={(e) => setThresholdDays(Number(e.target.value))}
            />
          </Field>
        )}
        {ruleType === "domain_nameserver_drift" && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            Fires for any domain whose operator-pinned{" "}
            <code>expected_nameservers</code> list differs from the
            registrar-reported <code>actual_nameservers</code>. Resolves when
            drift clears.
          </p>
        )}
        {ruleType === "domain_registrar_changed" && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            Fires once per registrar transition (e.g. a transfer). Auto-resolves
            after 7 days; can be marked resolved manually before then. The first
            observation per domain is recorded as a baseline without paging.
          </p>
        )}
        {ruleType === "domain_dnssec_status_changed" && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            Fires once when a domain's <code>dnssec_signed</code> flag flips at
            the parent zone (DS records appearing or disappearing).
            Auto-resolves after 7 days; can be marked resolved manually.
          </p>
        )}
        {ruleType === "circuit_status_changed" && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            Fires once when a circuit transitions into <code>suspended</code> or{" "}
            <code>decom</code>. Routine <code>active</code> ↔{" "}
            <code>pending</code> flips during commissioning are excluded.
            Auto-resolves after 7 days; can be marked resolved manually.
          </p>
        )}
        {ruleType === "service_resource_orphaned" && (
          <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
            Fires when a service has a resource link (VRF / subnet / circuit /
            etc.) whose target row was deleted out from under it. Resolves
            automatically when the operator detaches the orphan link or
            re-creates the target.
          </p>
        )}
        {ruleType === "compliance_change" && (
          <>
            <Field
              label="Classification"
              hint="Subnet flag this rule watches. Mutations against subnets / IPs / DHCP scopes whose subnet has the flag fire one event per audit row."
            >
              <select
                className={inputCls}
                value={classification}
                onChange={(e) =>
                  setClassification(e.target.value as AlertClassification)
                }
              >
                <option value="pci_scope">PCI scope</option>
                <option value="hipaa_scope">HIPAA scope</option>
                <option value="internet_facing">Internet-facing</option>
              </select>
            </Field>
            <Field
              label="Change scope"
              hint="Which audit-log actions count. Update + create + delete cover the common cases; pick a narrower scope to reduce noise."
            >
              <select
                className={inputCls}
                value={changeScope}
                onChange={(e) =>
                  setChangeScope(e.target.value as AlertChangeScope)
                }
              >
                <option value="any_change">
                  Any change (create + update + delete)
                </option>
                <option value="create">Create only</option>
                <option value="delete">Delete only</option>
              </select>
            </Field>
            <p className="rounded-md border bg-muted/20 p-3 text-[11px] text-muted-foreground">
              On first enable, the rule baselines its watermark to "now" — it
              won't retro-fire on existing audit history. Each matching audit
              row opens one event that auto-resolves after 24 h. Inheritance
              from IP block / space is not supported today (classification flags
              only exist on subnet rows).
            </p>
          </>
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
            disabled={!name.trim() || mut.isPending}
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

// ── Page ───────────────────────────────────────────────────────────────────

export function AlertsPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<AlertRule | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [openOnly, setOpenOnly] = useState(true);

  const { data: rules = [], isLoading: rulesLoading } = useQuery({
    queryKey: ["alert-rules"],
    queryFn: alertsApi.listRules,
  });

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
              Fires via syslog + webhook to the audit-forward targets.
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => evaluate.mutate()}
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
              disabled={evaluate.isPending}
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
                            className="rounded border px-2 py-0.5 text-[11px] hover:bg-accent"
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
                      {r.rule_type === "subnet_utilization"
                        ? `≥ ${r.threshold_percent}%`
                        : r.rule_type === "voice_lease_count_below"
                          ? `< ${r.threshold_percent ?? 1} leases`
                          : r.rule_type === "stale_ip_count"
                            ? `≥ ${r.threshold_percent ?? 10} stale · ${r.threshold_days ?? 90}d`
                            : r.rule_type === "node_pressure"
                              ? `≥ ${r.threshold_percent ?? 50}% stalled · full ≥ 1%`
                              : r.rule_type === "server_unreachable"
                                ? `type=${r.server_type ?? "any"}`
                                : r.rule_type === "domain_expiring" ||
                                    r.rule_type === "circuit_term_expiring" ||
                                    r.rule_type === "service_term_expiring" ||
                                    r.rule_type === "secret_expiring" ||
                                    r.rule_type === "decom_expiring"
                                  ? `≤ ${r.threshold_days ?? 30} d`
                                  : r.rule_type === "compliance_change"
                                    ? `${r.classification ?? "?"} · ${r.change_scope ?? "any_change"}`
                                    : r.rule_type === "backup_stale"
                                      ? `${r.threshold_percent ?? 2} missed runs`
                                      : "—"}
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
                          className="rounded p-1.5 hover:bg-accent"
                        >
                          <Power className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setEditing(r)}
                          title="Edit"
                          className="rounded p-1.5 hover:bg-accent"
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
                          className="rounded p-1.5 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30"
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
