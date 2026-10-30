import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  AlertTriangle,
  Check,
  Download,
  FileDown,
  Loader2,
  Pencil,
  Play,
  Plus,
  PowerOff,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import {
  conformityApi,
  type ConformityCheckCatalogEntry,
  type ConformityPolicy,
  type ConformityPolicyCreate,
  type ConformityPolicyUpdate,
  type ConformityResult,
  type ConformitySeverity,
  type ConformityStatus,
  type ConformityTargetKind,
  formatApiError,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

/**
 * Conformity admin page (issue #106).
 *
 * Three sections:
 *
 *   - Per-framework summary card row (totals + pass / warn / fail).
 *   - Policies table with inline toggle / re-evaluate / edit / delete.
 *   - Latest results panel filterable by policy / status — clicking a
 *     row reveals the diagnostic JSON.
 *
 * Built-in policies (``is_builtin=true``) cannot be deleted and only
 * accept a narrow set of edits — the form auto-locks the identity
 * fields when editing one of those rows.
 */
export function ConformityPage() {
  // #1341 — a read-only user is offered no write it would be refused:
  // the router asks admin on 'conformity'.
  const perms = usePermissions();
  const adminGate = permissionGate(
    perms.can("admin", "conformity"),
    "Requires admin permission on conformity policies",
  );
  const qc = useQueryClient();
  const [editing, setEditing] = useState<ConformityPolicy | null>(null);
  const [creating, setCreating] = useState(false);
  const [statusFilter, setStatusFilter] = useState<ConformityStatus | "">(
    "fail",
  );
  const [policyFilter, setPolicyFilter] = useState<string>("");

  const policiesQ = useQuery({
    queryKey: ["conformity-policies"],
    queryFn: () => conformityApi.listPolicies(),
  });
  const summaryQ = useQuery({
    queryKey: ["conformity-summary"],
    queryFn: () => conformityApi.summary(),
  });
  const checksQ = useQuery({
    queryKey: ["conformity-checks"],
    queryFn: () => conformityApi.listCheckKinds(),
  });
  const resultsQ = useQuery({
    queryKey: ["conformity-results", statusFilter, policyFilter],
    queryFn: () =>
      conformityApi.listResults({
        status: statusFilter || undefined,
        policy_id: policyFilter || undefined,
        limit: 500,
      }),
  });

  const togglePolicyMut = useMutation({
    mutationFn: (p: ConformityPolicy) =>
      conformityApi.updatePolicy(p.id, { enabled: !p.enabled }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["conformity-policies"] });
      qc.invalidateQueries({ queryKey: ["conformity-summary"] });
    },
  });

  const evaluateMut = useMutation({
    mutationFn: (id: string) => conformityApi.evaluatePolicyNow(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["conformity-policies"] });
      qc.invalidateQueries({ queryKey: ["conformity-summary"] });
      qc.invalidateQueries({ queryKey: ["conformity-results"] });
    },
  });

  const deletePolicyMut = useMutation({
    mutationFn: (id: string) => conformityApi.deletePolicy(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["conformity-policies"] });
      qc.invalidateQueries({ queryKey: ["conformity-summary"] });
      qc.invalidateQueries({ queryKey: ["conformity-results"] });
    },
  });

  const exportPdfMut = useMutation({
    mutationFn: (framework: string | undefined) =>
      conformityApi.exportPdf(framework),
    onError: (e: unknown) => {
      alert(`PDF export failed: ${formatApiError(e, "unknown error")}`);
    },
  });

  const policies = policiesQ.data ?? [];
  const summary = summaryQ.data;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Conformity</h1>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              Periodic policy checks against PCI / HIPAA / internet-facing
              classifications. Built-in policies are seeded disabled — toggle
              them on to start collecting evidence. Companion to the reactive
              compliance-change alerts in #105.
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-1.5">
            <HeaderButton
              variant="secondary"
              onClick={() => exportPdfMut.mutate(undefined)}
              disabled={exportPdfMut.isPending}
            >
              <FileDown className="h-4 w-4" />
              {exportPdfMut.isPending ? "Exporting…" : "Export PDF"}
            </HeaderButton>
            <HeaderButton
              variant="primary"
              onClick={() => setCreating(true)}
              {...adminGate}
            >
              <Plus className="h-4 w-4" />
              New policy
            </HeaderButton>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6 space-y-6">
        {/* Summary cards */}
        <SummaryRibbon
          summary={summary}
          loading={summaryQ.isLoading}
          onExport={(fw) => exportPdfMut.mutate(fw)}
        />

        {/* Policies */}
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">Policies</h2>
          <div className="overflow-hidden rounded-lg border bg-card">
            <table className="w-full text-sm">
              <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Name</th>
                  <th className="px-3 py-2 text-left font-medium">Framework</th>
                  <th className="px-3 py-2 text-left font-medium">Target</th>
                  <th className="px-3 py-2 text-left font-medium">Check</th>
                  <th className="px-3 py-2 text-left font-medium">Severity</th>
                  <th className="px-3 py-2 text-left font-medium">Last run</th>
                  <th className="px-3 py-2 text-left font-medium">State</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {policiesQ.isLoading && (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-3 py-8 text-center text-xs text-muted-foreground"
                    >
                      Loading…
                    </td>
                  </tr>
                )}
                {!policiesQ.isLoading && policies.length === 0 && (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-3 py-8 text-center text-xs text-muted-foreground"
                    >
                      <ListEmpty
                        error={policiesQ.error}
                        what="conformity policies"
                      >
                        No policies yet — click “New policy” to add one.
                      </ListEmpty>
                    </td>
                  </tr>
                )}
                {policies.map((p) => (
                  <tr key={p.id} className="border-b last:border-0">
                    <td className="px-3 py-2 font-medium">
                      {p.name}
                      {p.is_builtin && (
                        <span className="ml-1.5 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                          built-in
                        </span>
                      )}
                      {p.reference && (
                        <div className="text-[11px] text-muted-foreground">
                          {p.reference}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {p.framework}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {p.target_kind}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground font-mono text-[11px]">
                      {p.check_kind}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={p.severity} />
                    </td>
                    <td className="px-3 py-2 text-[11px] text-muted-foreground tabular-nums">
                      {p.last_evaluated_at
                        ? new Date(p.last_evaluated_at).toLocaleString()
                        : "never"}
                    </td>
                    <td className="px-3 py-2">
                      {p.enabled ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                          <Check className="h-3.5 w-3.5" /> enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                          <PowerOff className="h-3.5 w-3.5" /> disabled
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex justify-end gap-1">
                        <button
                          type="button"
                          title={p.enabled ? "Disable" : "Enable"}
                          onClick={() => togglePolicyMut.mutate(p)}
                          className="rounded p-1 hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                          {...adminGate}
                        >
                          {p.enabled ? (
                            <PowerOff className="h-4 w-4" />
                          ) : (
                            <Check className="h-4 w-4" />
                          )}
                        </button>
                        <button
                          type="button"
                          title="Re-evaluate now"
                          onClick={() => evaluateMut.mutate(p.id)}
                          className="rounded p-1 hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                          disabled={evaluateMut.isPending}
                          {...adminGate}
                        >
                          <Play className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          title="Edit"
                          onClick={() => setEditing(p)}
                          className="rounded p-1 hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                          {...adminGate}
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                        {!p.is_builtin && (
                          <button
                            type="button"
                            title="Delete"
                            onClick={() => {
                              if (
                                confirm(
                                  `Delete policy "${p.name}"? This removes the policy and every evaluation result it produced.`,
                                )
                              ) {
                                deletePolicyMut.mutate(p.id);
                              }
                            }}
                            className="rounded p-1 hover:bg-accent text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                            {...adminGate}
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Results */}
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Latest results</h2>
            <div className="flex items-center gap-2 text-xs">
              <select
                value={policyFilter}
                onChange={(e) => setPolicyFilter(e.target.value)}
                className="rounded-md border bg-background px-2 py-1 text-xs"
              >
                <option value="">All policies</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.framework} · {p.name}
                  </option>
                ))}
              </select>
              <select
                value={statusFilter}
                onChange={(e) =>
                  setStatusFilter(e.target.value as ConformityStatus | "")
                }
                className="rounded-md border bg-background px-2 py-1 text-xs"
              >
                <option value="">Any status</option>
                <option value="fail">Fail</option>
                <option value="warn">Warn</option>
                <option value="pass">Pass</option>
                <option value="not_applicable">Not applicable</option>
              </select>
            </div>
          </div>
          <ResultsList
            results={resultsQ.data ?? []}
            loading={resultsQ.isLoading}
            policies={policies}
          />
        </section>
      </div>

      {creating && (
        <PolicyEditorModal
          existing={null}
          checks={checksQ.data ?? []}
          onClose={() => setCreating(false)}
        />
      )}
      {editing && (
        <PolicyEditorModal
          existing={editing}
          checks={checksQ.data ?? []}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

// ── Sub-components ──────────────────────────────────────────────────

function SummaryRibbon({
  summary,
  loading,
  onExport,
}: {
  summary: import("@/lib/api").ConformitySummary | undefined;
  loading: boolean;
  onExport: (framework: string) => void;
}) {
  if (loading || !summary) {
    return (
      <div className="rounded-lg border bg-card p-6 text-center">
        <Loader2 className="mx-auto h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    );
  }
  const totalEvaluated =
    summary.overall_pass +
    summary.overall_warn +
    summary.overall_fail +
    summary.overall_not_applicable;
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label="Pass"
        value={summary.overall_pass}
        total={totalEvaluated}
        tone="emerald"
      />
      <KpiCard
        label="Fail"
        value={summary.overall_fail}
        total={totalEvaluated}
        tone="red"
      />
      <KpiCard
        label="Warn"
        value={summary.overall_warn}
        total={totalEvaluated}
        tone="amber"
      />
      <KpiCard
        label="N/A"
        value={summary.overall_not_applicable}
        total={totalEvaluated}
        tone="zinc"
      />
      {summary.frameworks.map((fw) => (
        <FrameworkCard
          key={fw.framework}
          framework={fw}
          onExport={() => onExport(fw.framework)}
        />
      ))}
    </div>
  );
}

function KpiCard({
  label,
  value,
  total,
  tone,
}: {
  label: string;
  value: number;
  total: number;
  tone: "emerald" | "red" | "amber" | "zinc";
}) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  const color =
    tone === "emerald"
      ? "text-emerald-600 dark:text-emerald-400"
      : tone === "red"
        ? "text-red-600 dark:text-red-400"
        : tone === "amber"
          ? "text-amber-600 dark:text-amber-400"
          : "text-muted-foreground";
  return (
    <div className="rounded-lg border bg-card p-3">
      <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
      <p className={cn("mt-1 text-2xl font-bold tabular-nums", color)}>
        {value}
      </p>
      <p className="text-[11px] text-muted-foreground">
        {pct}% of {total}
      </p>
    </div>
  );
}

function FrameworkCard({
  framework,
  onExport,
}: {
  framework: import("@/lib/api").ConformityFrameworkRollup;
  onExport: () => void;
}) {
  const totalResults =
    framework.pass_count +
    framework.warn_count +
    framework.fail_count +
    framework.not_applicable_count;
  const passPct =
    totalResults > 0
      ? Math.round((framework.pass_count / totalResults) * 100)
      : 0;
  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-semibold">{framework.framework}</p>
          <p className="text-[11px] text-muted-foreground">
            {framework.policies_enabled}/{framework.policies_total} policies
            enabled
          </p>
        </div>
        <button
          type="button"
          title={`Download ${framework.framework} PDF`}
          className="text-xs text-primary hover:underline"
          onClick={onExport}
        >
          <Download className="inline h-3.5 w-3.5" />
        </button>
      </div>
      <div className="mt-2 flex items-end gap-3">
        <p className="text-xl font-bold tabular-nums">{passPct}%</p>
        <div className="flex flex-1 gap-2 text-[11px] text-muted-foreground">
          <span className="text-emerald-600 dark:text-emerald-400">
            {framework.pass_count}p
          </span>
          <span className="text-amber-600 dark:text-amber-400">
            {framework.warn_count}w
          </span>
          <span className="text-red-600 dark:text-red-400">
            {framework.fail_count}f
          </span>
          <span>{framework.not_applicable_count}n/a</span>
        </div>
      </div>
    </div>
  );
}

function ResultsList({
  results,
  loading,
  policies,
}: {
  results: ConformityResult[];
  loading: boolean;
  policies: ConformityPolicy[];
}) {
  const policyById = useMemo(
    () => new Map(policies.map((p) => [p.id, p])),
    [policies],
  );
  const [expanded, setExpanded] = useState<string | null>(null);

  if (loading) {
    return (
      <div className="rounded-lg border bg-card p-6 text-center">
        <Loader2 className="mx-auto h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (results.length === 0) {
    return (
      <div className="rounded-lg border bg-card p-6 text-center text-xs text-muted-foreground">
        No results match the current filter. Re-evaluate a policy or relax the
        filter.
      </div>
    );
  }
  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <table className="w-full text-sm">
        <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-3 py-2 text-left font-medium">Status</th>
            <th className="px-3 py-2 text-left font-medium">Policy</th>
            <th className="px-3 py-2 text-left font-medium">Resource</th>
            <th className="px-3 py-2 text-left font-medium">Detail</th>
            <th className="px-3 py-2 text-left font-medium">Evaluated</th>
          </tr>
        </thead>
        <tbody className={zebraBodyCls}>
          {results.map((r) => {
            const isExpanded = expanded === r.id;
            const policy = policyById.get(r.policy_id);
            return (
              <>
                <tr
                  key={r.id}
                  className="cursor-pointer border-b last:border-0 hover:bg-muted/20"
                  onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                >
                  <td className="px-3 py-2">
                    <StatusBadge status={r.status} />
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {policy ? (
                      <span>
                        <span className="text-muted-foreground">
                          {policy.framework} ·{" "}
                        </span>
                        {policy.name}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">
                        (deleted policy)
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <span className="text-muted-foreground">
                      {r.resource_kind}{" "}
                    </span>
                    {r.resource_display}
                  </td>
                  <td className="px-3 py-2 text-xs">{r.detail || "—"}</td>
                  <td className="px-3 py-2 text-[11px] text-muted-foreground tabular-nums">
                    {new Date(r.evaluated_at).toLocaleString()}
                  </td>
                </tr>
                {isExpanded && r.diagnostic && (
                  <tr key={`${r.id}-diag`}>
                    <td colSpan={5} className="bg-muted/10 px-3 py-2">
                      <pre className="overflow-auto rounded bg-card p-2 text-[11px] font-mono">
                        {JSON.stringify(r.diagnostic, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function StatusBadge({ status }: { status: ConformityStatus }) {
  const cls =
    status === "pass"
      ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300"
      : status === "fail"
        ? "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
        : status === "warn"
          ? "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
          : "bg-muted text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] uppercase tracking-wider",
        cls,
      )}
    >
      {status === "fail" && <AlertTriangle className="h-3 w-3" />}
      {status}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: ConformitySeverity }) {
  const cls =
    severity === "critical"
      ? "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
      : severity === "warning"
        ? "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
        : "bg-muted text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 text-[11px] uppercase tracking-wider",
        cls,
      )}
    >
      {severity}
    </span>
  );
}

// ── Editor modal ────────────────────────────────────────────────────

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// Target kinds whose backend resolver actually honours
// `target_filter.classification`. `platform` has no rows to filter, and
// the multicast resolver (`_resolve_multicast_groups`) deliberately
// ignores target_filter entirely — offering the control for those would
// render a picker whose value is silently discarded. Rendering and the
// request payload share this list so the two can't drift apart.
const CLASSIFIABLE_TARGET_KINDS = [
  "subnet",
  "ip_address",
  "dns_zone",
  "dhcp_scope",
];

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

function PolicyEditorModal({
  existing,
  checks,
  onClose,
}: {
  existing: ConformityPolicy | null;
  checks: ConformityCheckCatalogEntry[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const isBuiltin = existing?.is_builtin ?? false;
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [framework, setFramework] = useState(existing?.framework ?? "custom");
  const [reference, setReference] = useState(existing?.reference ?? "");
  const [severity, setSeverity] = useState<ConformitySeverity>(
    existing?.severity ?? "warning",
  );
  const [targetKind, setTargetKind] = useState<ConformityTargetKind>(
    existing?.target_kind ?? "subnet",
  );
  const [classification, setClassification] = useState<string>(
    String(existing?.target_filter?.classification ?? "pci_scope"),
  );
  const [checkKind, setCheckKind] = useState<string>(
    existing?.check_kind ?? "has_field",
  );
  const [checkArgsRaw, setCheckArgsRaw] = useState<string>(
    JSON.stringify(existing?.check_args ?? {}, null, 2),
  );
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [intervalHours, setIntervalHours] = useState<number>(
    existing?.eval_interval_hours ?? 24,
  );
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: async () => {
      let parsedArgs: Record<string, unknown> = {};
      try {
        parsedArgs = checkArgsRaw.trim()
          ? (JSON.parse(checkArgsRaw) as Record<string, unknown>)
          : {};
      } catch {
        throw new Error("check_args must be valid JSON");
      }
      const targetFilter: Record<string, unknown> = {};
      if (CLASSIFIABLE_TARGET_KINDS.includes(targetKind)) {
        if (classification) {
          targetFilter.classification = classification;
        }
      }
      if (existing) {
        const update: ConformityPolicyUpdate = {};
        if (!isBuiltin) {
          update.name = name;
          update.framework = framework;
          update.reference = reference || null;
          update.target_kind = targetKind;
          update.target_filter = targetFilter;
          update.check_kind = checkKind;
          update.check_args = parsedArgs;
        }
        update.description = description;
        update.severity = severity;
        update.enabled = enabled;
        update.eval_interval_hours = intervalHours;
        return conformityApi.updatePolicy(existing.id, update);
      }
      const body: ConformityPolicyCreate = {
        name,
        description,
        framework,
        reference: reference || null,
        severity,
        target_kind: targetKind,
        target_filter: targetFilter,
        check_kind: checkKind,
        check_args: parsedArgs,
        enabled,
        eval_interval_hours: intervalHours,
      };
      return conformityApi.createPolicy(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["conformity-policies"] });
      qc.invalidateQueries({ queryKey: ["conformity-summary"] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  const checkInfo = checks.find((c) => c.name === checkKind);

  return (
    <Modal
      onClose={onClose}
      title={existing ? "Edit conformity policy" : "New conformity policy"}
    >
      <div className="space-y-4">
        {isBuiltin && (
          <div className="rounded-md border border-amber-300/50 bg-amber-50 p-3 text-[11px] dark:bg-amber-900/20">
            Built-in policy. Identity (name / framework / target / check) is
            locked — clone first to author a variant.
          </div>
        )}
        <Field label="Name">
          <input
            className={cn(inputCls, isBuiltin && "opacity-60")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={isBuiltin}
          />
        </Field>
        <Field label="Description">
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Framework">
            <input
              className={cn(inputCls, isBuiltin && "opacity-60")}
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
              disabled={isBuiltin}
              placeholder="PCI-DSS 4.0 / HIPAA / SOC2 / custom"
            />
          </Field>
          <Field label="Reference">
            <input
              className={cn(inputCls, isBuiltin && "opacity-60")}
              value={reference ?? ""}
              onChange={(e) => setReference(e.target.value)}
              disabled={isBuiltin}
              placeholder="e.g. 1.2.1"
            />
          </Field>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Severity">
            <select
              className={inputCls}
              value={severity}
              onChange={(e) =>
                setSeverity(e.target.value as ConformitySeverity)
              }
            >
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>
          </Field>
          <Field label="Eval interval (hours)" hint="0 = on-demand only">
            <input
              type="number"
              min={0}
              max={8760}
              className={inputCls}
              value={intervalHours}
              onChange={(e) => setIntervalHours(Number(e.target.value))}
            />
          </Field>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Target kind">
            <select
              className={cn(inputCls, isBuiltin && "opacity-60")}
              value={targetKind}
              onChange={(e) =>
                setTargetKind(e.target.value as ConformityTargetKind)
              }
              disabled={isBuiltin}
            >
              <option value="platform">Platform (single check)</option>
              <option value="subnet">Subnet</option>
              <option value="ip_address">IP address</option>
              <option value="dns_zone">DNS zone</option>
              <option value="dhcp_scope">DHCP scope</option>
              <option value="multicast_group">Multicast group</option>
            </select>
          </Field>
          {CLASSIFIABLE_TARGET_KINDS.includes(targetKind) && (
            <Field label="Classification filter">
              <select
                className={cn(inputCls, isBuiltin && "opacity-60")}
                value={classification}
                onChange={(e) => setClassification(e.target.value)}
                disabled={isBuiltin}
              >
                <option value="">Any (no filter)</option>
                <option value="pci_scope">PCI scope</option>
                <option value="hipaa_scope">HIPAA scope</option>
                <option value="internet_facing">Internet-facing</option>
              </select>
            </Field>
          )}
        </div>
        <Field label="Check kind">
          <select
            className={cn(inputCls, isBuiltin && "opacity-60")}
            value={checkKind}
            onChange={(e) => setCheckKind(e.target.value)}
            disabled={isBuiltin}
          >
            {checks.map((c) => (
              <option key={c.name} value={c.name}>
                {c.label} — {c.name}
              </option>
            ))}
          </select>
          {checkInfo && (
            <p className="text-[11px] text-muted-foreground/80">
              Supports: {checkInfo.supports.join(", ")}
              {checkInfo.args.length > 0 &&
                ` · args: ${checkInfo.args.map((a) => a.name + (a.required ? "*" : "")).join(", ")}`}
            </p>
          )}
        </Field>
        <Field
          label="check_args (JSON)"
          hint="Per-check args — see catalog above for required keys."
        >
          <textarea
            className={cn(
              inputCls,
              "min-h-[80px] font-mono text-[12px]",
              isBuiltin && "opacity-60",
            )}
            value={checkArgsRaw}
            onChange={(e) => setCheckArgsRaw(e.target.value)}
            disabled={isBuiltin}
          />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Policy enabled
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
