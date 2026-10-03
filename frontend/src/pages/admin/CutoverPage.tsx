import { Fragment, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRightLeft,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  Copy,
  FileText,
  History,
  Loader2,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  Timer,
  Trash2,
} from "lucide-react";

import {
  cutoverApi,
  dhcpApi,
  dnsApi,
  formatApiError,
  type CutoverBlocker,
  type CutoverCandidate,
  type CutoverChecklistItem,
  type CutoverItem,
  type CutoverItemIn,
  type CutoverLeaseHandoverPlan,
  type CutoverParityReport,
  type CutoverPlan,
  type CutoverPlanDetail,
  type CutoverPlanParityResult,
  type CutoverShadowReport,
  type CutoverSwitchResult,
  type CutoverTTLPreflightPlan,
  type DHCPServer,
  type DNSServer,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { useSessionState } from "@/lib/useSessionState";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";

/**
 * Configuration → Import → Windows cutover (issue #756).
 *
 * The guided migration off Windows DNS / DHCP. A plan holds one item per
 * Windows zone or scope, and the four tabs are the four phases the backend
 * models: parity (Items), the parallel run (shadow queries), the switch (TTL
 * pre-flight / lease handover / cut over / roll back), and the decommission
 * checklist.
 *
 * Two things drive most of the layout decisions here:
 *
 * * **Blockers are the point.** Every ``Blocker.message`` the API returns is
 *   written to state the fix, so they are rendered verbatim — in the item
 *   table, in the cutover confirmation, and in the 409 body when the switch is
 *   refused. The Cut over button is disabled outright while any blocker has
 *   ``severity: "block"``; that refusal (notably the AD "Secure only" one) is
 *   not something a UI affordance may talk its way past.
 * * **Everything expensive is on demand.** Parity, the shadow run and discover
 *   all make live WinRM / DNS calls against the operator's estate, so nothing
 *   here polls: results are read back from the persisted ``last_parity`` /
 *   ``last_shadow`` columns and only re-run when the operator asks.
 *
 * Wire shapes come from ``cutoverApi`` in lib/api.ts.
 */

const MODULE_ID = "migration.cutover";

const PLAN_STATUSES = [
  "draft",
  "verifying",
  "parallel",
  "cutting_over",
  "completed",
  "rolled_back",
  "abandoned",
] as const;

type DetailTab = "items" | "parallel" | "cutover" | "decommission";

const DETAIL_TABS: { key: DetailTab; label: string; hint: string }[] = [
  { key: "items", label: "Items", hint: "Phase 1 — parity" },
  { key: "parallel", label: "Parallel run", hint: "Phase 2 — shadow queries" },
  { key: "cutover", label: "Cutover", hint: "Phase 3 — pre-flight + switch" },
  {
    key: "decommission",
    label: "Decommission",
    hint: "Phase 4 — retire Windows",
  },
];

type Tone = "success" | "amber" | "destructive" | "muted" | "info" | "violet";

const TONE_CLS: Record<Tone, string> = {
  success: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  amber: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  destructive: "bg-destructive/15 text-destructive",
  muted: "bg-zinc-500/15 text-zinc-700 dark:text-zinc-400",
  info: "bg-sky-500/15 text-sky-700 dark:text-sky-400",
  violet: "bg-violet-500/15 text-violet-700 dark:text-violet-400",
};

const STAGE_TONES: Record<string, Tone> = {
  pending: "muted",
  parity_checked: "info",
  preflight_done: "violet",
  cut_over: "success",
  rolled_back: "amber",
};

const DIFF_TONES: Record<string, Tone> = {
  in_sync: "success",
  value_mismatch: "amber",
  drifted_since_import: "amber",
  never_imported: "info",
  intentionally_diverged: "violet",
};

const PARITY_STATUS_TONES: Record<string, Tone> = {
  ok: "success",
  unmatched: "amber",
  unverified: "amber",
  error: "destructive",
};

const AUTO_STATE_TONES: Record<string, Tone> = {
  ok: "success",
  attention: "amber",
  not_applicable: "muted",
  manual: "muted",
};

const CATEGORY_LABELS: Record<string, string> = {
  ad: "Active Directory",
  dns: "DNS",
  dhcp: "DHCP",
  general: "General decommission",
};

// ── error helpers ─────────────────────────────────────────────────────

type ErrorDetail = { detail?: unknown };

function errorDetail(err: unknown): unknown {
  return (err as { response?: { data?: ErrorDetail } })?.response?.data?.detail;
}

/** The 409 from POST …/cutover is ``CutoverBlocked.as_dict()``: an ``error``
 *  string plus the blockers. Everything else falls through to the shared
 *  formatter. */
function extractError(err: unknown): string {
  const detail = errorDetail(err);
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const msg = (detail as { error?: unknown }).error;
    if (typeof msg === "string" && msg.trim()) return msg;
  }
  return formatApiError(err);
}

function extractBlockers(err: unknown): CutoverBlocker[] {
  const detail = errorDetail(err);
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const raw = (detail as { blockers?: unknown }).blockers;
    if (Array.isArray(raw)) return raw as CutoverBlocker[];
  }
  return [];
}

function hasBlocking(blockers: CutoverBlocker[] | null | undefined): boolean {
  return (blockers ?? []).some((b) => b.severity === "block");
}

function warnOnly(blockers: CutoverBlocker[] | null | undefined) {
  return (blockers ?? []).filter((b) => b.severity === "warn");
}

function shortDate(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

// ── presentational primitives ─────────────────────────────────────────

function Chip({
  tone,
  children,
  title,
}: {
  tone: Tone;
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium",
        TONE_CLS[tone],
      )}
    >
      {children}
    </span>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs text-destructive">
      <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
      <div className="min-w-0 break-all">{message}</div>
    </div>
  );
}

function WarningList({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="space-y-1 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
      <div className="font-medium text-amber-700 dark:text-amber-400">
        Warnings
      </div>
      {warnings.map((w, i) => (
        <div
          key={i}
          className="break-all text-amber-700/90 dark:text-amber-300/90"
        >
          {w}
        </div>
      ))}
    </div>
  );
}

/** Full blocker rendering — code, severity and the message verbatim. */
function BlockerList({ blockers }: { blockers: CutoverBlocker[] }) {
  if (blockers.length === 0) return null;
  return (
    <ul className="space-y-1.5">
      {blockers.map((b, i) => (
        <li
          key={`${b.code}:${i}`}
          className={cn(
            "flex items-start gap-2 rounded-md border p-2 text-xs",
            b.severity === "block"
              ? "border-destructive/40 bg-destructive/5"
              : "border-amber-500/40 bg-amber-500/5",
          )}
        >
          {b.severity === "block" ? (
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-destructive" />
          ) : (
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-amber-600 dark:text-amber-400" />
          )}
          <div className="min-w-0">
            <span className="break-all font-mono text-[10px] text-muted-foreground">
              {b.code}
            </span>
            <p className="break-words text-foreground">{b.message}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

/** Compact form for a table cell. */
function BlockerChips({ blockers }: { blockers: CutoverBlocker[] }) {
  if (blockers.length === 0)
    return <span className="text-xs text-muted-foreground">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {blockers.map((b, i) => (
        <Chip
          key={`${b.code}:${i}`}
          tone={b.severity === "block" ? "destructive" : "amber"}
          title={b.message}
        >
          {b.code}
        </Chip>
      ))}
    </span>
  );
}

function StageChip({ stage }: { stage: string }) {
  return <Chip tone={STAGE_TONES[stage] ?? "muted"}>{stage}</Chip>;
}

function ParityCell({ item }: { item: CutoverItem }) {
  const report = item.last_parity;
  if (!report)
    return <span className="text-xs text-muted-foreground">not checked</span>;
  return (
    <span className="flex flex-wrap items-center gap-1">
      <Chip tone={PARITY_STATUS_TONES[report.status] ?? "muted"}>
        {report.status}
      </Chip>
      {report.is_parity ? (
        <Chip tone="success">in parity</Chip>
      ) : (
        <Chip tone="amber">{report.difference_count} diff</Chip>
      )}
      <span className="text-[11px] text-muted-foreground">
        {report.in_sync} in sync · {shortDate(item.last_parity_at)}
      </span>
    </span>
  );
}

/** Read-only markdown / PowerShell block with a copy button.
 *
 * Deliberately a ``<pre>`` and not a rendered document: the runbook and the
 * Windows-side instructions exist to be pasted into a change ticket or a
 * PowerShell prompt, and rendering them would lose the exact text. */
function CopyBlock({
  text,
  label,
  className,
}: {
  text: string;
  label: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const t = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(t);
  }, [copied]);

  return (
    <div className={cn("rounded-md border bg-muted/30", className)}>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-3 py-1.5">
        <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        <HeaderButton
          icon={copied ? CheckCircle2 : Copy}
          className="px-2 py-1 text-xs"
          onClick={() => {
            navigator.clipboard
              ?.writeText(text)
              .then(() => setCopied(true))
              // Clipboard access can be denied (insecure origin, permission
              // policy); the text stays selectable, so there is nothing to fix.
              .catch(() => setCopied(false));
          }}
        >
          {copied ? "Copied" : "Copy"}
        </HeaderButton>
      </div>
      <pre className="max-h-[28rem] overflow-auto p-3 text-xs leading-relaxed">
        {text}
      </pre>
    </div>
  );
}

// ── root ──────────────────────────────────────────────────────────────

export function CutoverPage() {
  const { ready, enabled } = useFeatureModules();
  // ``enabled`` is optimistic while the module set loads, so a hard page load
  // would otherwise fire a gated query that 404s before the real state lands.
  const canQuery = ready && enabled(MODULE_ID);
  const [planId, setPlanId] = useSessionState<string | null>(
    "admin.cutover.plan",
    null,
  );

  if (ready && !enabled(MODULE_ID)) {
    return (
      <div className="p-6">
        <div className="rounded-md border bg-muted/20 p-4 text-sm text-muted-foreground">
          The <strong>Windows cutover</strong> module is turned off. Enable{" "}
          <code>{MODULE_ID}</code> under Settings → Features to use it.
        </div>
      </div>
    );
  }

  return planId ? (
    <PlanDetailView
      planId={planId}
      canQuery={canQuery}
      onBack={() => setPlanId(null)}
    />
  ) : (
    <PlanListView canQuery={canQuery} onOpen={(id) => setPlanId(id)} />
  );
}

// ── master list ───────────────────────────────────────────────────────

function PlanListView({
  canQuery,
  onOpen,
}: {
  canQuery: boolean;
  onOpen: (id: string) => void;
}) {
  const qc = useQueryClient();
  const [newOpen, setNewOpen] = useState(false);
  const [deleting, setDeleting] = useState<CutoverPlan | null>(null);
  const [error, setError] = useState<string | null>(null);

  const plansQ = useQuery({
    queryKey: ["cutover", "plans"],
    queryFn: cutoverApi.listPlans,
    enabled: canQuery,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => cutoverApi.deletePlan(id),
    onSuccess: () => {
      setDeleting(null);
      setError(null);
      qc.invalidateQueries({ queryKey: ["cutover", "plans"] });
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const plans = plansQ.data ?? [];
  // A list that was never read is not an empty one to invite a first plan
  // into; the error banner says why (#1343).
  const unread = plansQ.isError && plans.length === 0;

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <ArrowRightLeft className="h-5 w-5 flex-shrink-0 text-primary" />
          <div className="min-w-0">
            <h1 className="text-lg font-semibold">Windows cutover</h1>
            <p className="text-xs text-muted-foreground">
              Guided migration off Windows DNS / DHCP — verify parity, run both
              sides in parallel, cut over one item at a time with a rollback,
              then work the decommission checklist.
            </p>
          </div>
        </div>
        <div className="flex flex-shrink-0 flex-wrap items-center gap-2">
          <HeaderButton
            icon={plansQ.isFetching ? Loader2 : RefreshCw}
            iconClassName={plansQ.isFetching ? "animate-spin" : undefined}
            onClick={() => plansQ.refetch()}
            disabled={!canQuery}
          >
            Refresh
          </HeaderButton>
          <HeaderButton
            variant="primary"
            icon={Plus}
            onClick={() => setNewOpen(true)}
            disabled={!canQuery}
          >
            New plan
          </HeaderButton>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        <div className="space-y-4">
          {error && <ErrorBanner message={error} />}
          {plansQ.isError && (
            <ErrorBanner message={formatApiError(plansQ.error)} />
          )}

          {plansQ.isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading plans…
            </div>
          ) : unread ? null : plans.length === 0 ? (
            <div className="rounded-md border bg-muted/20 p-4 text-sm text-muted-foreground">
              No cutover plans yet. Create one, point it at the Windows DNS /
              DHCP servers you are migrating away from and the SpatiumDDI groups
              taking over, then run <strong>Discover</strong> to pull the zones
              and scopes off the live source.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-md border bg-background">
              <table className="w-full min-w-[52rem] text-sm">
                <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 text-left">Plan</th>
                    <th className="px-3 py-2 text-left">Status</th>
                    <th className="px-3 py-2 text-left">Items</th>
                    <th className="px-3 py-2 text-left">Stages</th>
                    <th className="px-3 py-2 text-left">Blocked</th>
                    <th className="px-3 py-2 text-left">Created</th>
                    <th className="px-3 py-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {plans.map((p) => (
                    <tr key={p.id} className="border-t hover:bg-muted/20">
                      <td className="px-3 py-2 align-top">
                        <button
                          type="button"
                          onClick={() => onOpen(p.id)}
                          className="break-all text-left font-medium text-primary hover:underline"
                        >
                          {p.name}
                        </button>
                        {p.description && (
                          <p className="break-words text-[11px] text-muted-foreground">
                            {p.description}
                          </p>
                        )}
                      </td>
                      <td className="px-3 py-2 align-top">
                        <Chip
                          tone={
                            p.status === "completed"
                              ? "success"
                              : p.status === "rolled_back" ||
                                  p.status === "abandoned"
                                ? "amber"
                                : "info"
                          }
                        >
                          {p.status}
                        </Chip>
                      </td>
                      <td className="px-3 py-2 align-top tabular-nums">
                        {p.item_count}
                      </td>
                      <td className="px-3 py-2 align-top">
                        <span className="flex flex-wrap gap-1">
                          {Object.entries(p.stage_counts).map(([s, n]) => (
                            <Chip key={s} tone={STAGE_TONES[s] ?? "muted"}>
                              {s} {n}
                            </Chip>
                          ))}
                        </span>
                      </td>
                      <td className="px-3 py-2 align-top">
                        {p.blocked_count > 0 ? (
                          <Chip tone="destructive">{p.blocked_count}</Chip>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            0
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 align-top text-xs text-muted-foreground">
                        {shortDate(p.created_at)}
                      </td>
                      <td className="px-3 py-2 align-top text-right">
                        <div className="flex flex-wrap justify-end gap-2">
                          <HeaderButton
                            className="px-2 py-1 text-xs"
                            onClick={() => onOpen(p.id)}
                          >
                            Open
                          </HeaderButton>
                          <HeaderButton
                            variant="destructive"
                            icon={Trash2}
                            className="px-2 py-1 text-xs"
                            onClick={() => setDeleting(p)}
                          >
                            Delete
                          </HeaderButton>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {newOpen && (
        <NewPlanModal
          canQuery={canQuery}
          onClose={() => setNewOpen(false)}
          onCreated={(plan) => {
            setNewOpen(false);
            qc.invalidateQueries({ queryKey: ["cutover", "plans"] });
            onOpen(plan.id);
          }}
        />
      )}

      <ConfirmModal
        open={deleting !== null}
        tone="destructive"
        title="Delete cutover plan?"
        message={
          <span>
            Deletes <strong className="break-all">{deleting?.name}</strong> with
            its items, checklist and timeline. Nothing the plan points at is
            touched — zones, scopes and reservations are owned by their own
            tables. It does throw away any pre-flight TTL snapshot, which is the
            only record of the pre-migration TTLs.
          </span>
        }
        confirmLabel="Delete plan"
        loading={deleteMut.isPending}
        onConfirm={() => deleting && deleteMut.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      />
    </div>
  );
}

// ── new plan ──────────────────────────────────────────────────────────

function NewPlanModal({
  canQuery,
  onClose,
  onCreated,
}: {
  canQuery: boolean;
  onClose: () => void;
  onCreated: (plan: CutoverPlanDetail) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [dnsSource, setDnsSource] = useState("");
  const [dhcpSource, setDhcpSource] = useState("");
  const [dnsTarget, setDnsTarget] = useState("");
  const [dhcpTarget, setDhcpTarget] = useState("");
  const [error, setError] = useState<string | null>(null);

  const dnsGroupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: dnsApi.listGroups,
    enabled: canQuery,
  });
  const dhcpGroupsQ = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
    enabled: canQuery,
  });
  // DNS servers are only listable per group, so the picker fans out over the
  // groups it just loaded.
  const dnsGroupIds = (dnsGroupsQ.data ?? []).map((g) => g.id);
  const dnsServersQ = useQuery({
    queryKey: ["cutover", "dns-servers", dnsGroupIds.join(",")],
    queryFn: async () => {
      const perGroup = await Promise.all(
        dnsGroupIds.map((id) => dnsApi.listServers(id)),
      );
      return perGroup.flat();
    },
    enabled: canQuery && dnsGroupIds.length > 0,
  });
  const dhcpServersQ = useQuery({
    queryKey: ["cutover", "dhcp-servers"],
    queryFn: () => dhcpApi.listServers(),
    enabled: canQuery,
  });

  const windowsDns = (dnsServersQ.data ?? []).filter(
    (s: DNSServer) => s.driver === "windows_dns",
  );
  const windowsDhcp = (dhcpServersQ.data ?? []).filter(
    (s: DHCPServer) => s.driver === "windows_dhcp",
  );

  const createMut = useMutation({
    mutationFn: () =>
      cutoverApi.createPlan({
        name: name.trim(),
        description,
        source_dns_server_id: dnsSource || null,
        source_dhcp_server_id: dhcpSource || null,
        target_dns_group_id: dnsTarget || null,
        target_dhcp_group_id: dhcpTarget || null,
      }),
    onSuccess: onCreated,
    onError: (err: unknown) => setError(extractError(err)),
  });

  return (
    <Modal title="New cutover plan" onClose={onClose} wide>
      <div className="space-y-4">
        {error && <ErrorBanner message={error} />}

        <div>
          <label className="block text-sm font-medium">Name</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Retire DC01 — corp.example + 10.0.20.0/24"
            className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>

        <div>
          <label className="block text-sm font-medium">Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label className="block text-sm font-medium">
              Source Windows DNS server
            </label>
            <p className="mb-1 text-[11px] text-muted-foreground">
              What zones are pulled from. Needs the <code>windows_dns</code>{" "}
              driver.
            </p>
            <select
              value={dnsSource}
              onChange={(e) => setDnsSource(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="">— none —</option>
              {windowsDns.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.host})
                </option>
              ))}
            </select>
            {!dnsServersQ.isLoading && windowsDns.length === 0 && (
              <p className="mt-1 text-[11px] text-muted-foreground">
                No Windows DNS servers are configured.
              </p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium">
              Target DNS server group
            </label>
            <p className="mb-1 text-[11px] text-muted-foreground">
              The SpatiumDDI group taking the zones over.
            </p>
            <select
              value={dnsTarget}
              onChange={(e) => setDnsTarget(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="">— none —</option>
              {(dnsGroupsQ.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium">
              Source Windows DHCP server
            </label>
            <p className="mb-1 text-[11px] text-muted-foreground">
              What scopes and leases are pulled from. Needs the{" "}
              <code>windows_dhcp</code> driver.
            </p>
            <select
              value={dhcpSource}
              onChange={(e) => setDhcpSource(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="">— none —</option>
              {windowsDhcp.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({s.host})
                </option>
              ))}
            </select>
            {!dhcpServersQ.isLoading && windowsDhcp.length === 0 && (
              <p className="mt-1 text-[11px] text-muted-foreground">
                No Windows DHCP servers are configured.
              </p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium">
              Target DHCP server group
            </label>
            <p className="mb-1 text-[11px] text-muted-foreground">
              The SpatiumDDI group taking the scopes over.
            </p>
            <select
              value={dhcpTarget}
              onChange={(e) => setDhcpTarget(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="">— none —</option>
              {(dhcpGroupsQ.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex flex-wrap justify-end gap-2">
          <HeaderButton onClick={onClose}>Cancel</HeaderButton>
          <HeaderButton
            variant="primary"
            icon={createMut.isPending ? Loader2 : Plus}
            iconClassName={createMut.isPending ? "animate-spin" : undefined}
            onClick={() => {
              setError(null);
              createMut.mutate();
            }}
            disabled={!name.trim() || createMut.isPending}
          >
            Create plan
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

// ── plan detail ───────────────────────────────────────────────────────

function PlanDetailView({
  planId,
  canQuery,
  onBack,
}: {
  planId: string;
  canQuery: boolean;
  onBack: () => void;
}) {
  const qc = useQueryClient();
  const [tab, setTab] = useSessionState<DetailTab>(
    "admin.cutover.detailTab",
    "items",
  );
  const [discoverOpen, setDiscoverOpen] = useState(false);
  const [runbookOpen, setRunbookOpen] = useState(false);
  const [timelineOpen, setTimelineOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const planQ = useQuery({
    queryKey: ["cutover", "plan", planId],
    queryFn: () => cutoverApi.getPlan(planId),
    enabled: canQuery,
  });

  const statusMut = useMutation({
    mutationFn: (status: string) => cutoverApi.updatePlan(planId, { status }),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });
      qc.invalidateQueries({ queryKey: ["cutover", "plans"] });
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const plan = planQ.data;
  const items = useMemo(() => plan?.items ?? [], [plan]);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });
    qc.invalidateQueries({ queryKey: ["cutover", "checklist", planId] });
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b p-4">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <HeaderButton icon={ArrowLeft} onClick={onBack} className="px-2">
            Plans
          </HeaderButton>
          <div className="min-w-0">
            <h1 className="break-all text-lg font-semibold">
              {plan?.name ?? "Cutover plan"}
            </h1>
            <p className="text-xs text-muted-foreground">
              {plan
                ? `${plan.item_count} item(s) · ${plan.blocked_count} blocked`
                : "Loading…"}
            </p>
          </div>
        </div>
        <div className="flex flex-shrink-0 flex-wrap items-center gap-2">
          {plan && (
            <select
              value={plan.status}
              onChange={(e) => statusMut.mutate(e.target.value)}
              disabled={statusMut.isPending}
              className="rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              aria-label="Plan status"
            >
              {PLAN_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          )}
          <HeaderButton
            icon={planQ.isFetching ? Loader2 : RefreshCw}
            iconClassName={planQ.isFetching ? "animate-spin" : undefined}
            onClick={refresh}
            disabled={!canQuery}
          >
            Refresh
          </HeaderButton>
          <HeaderButton icon={History} onClick={() => setTimelineOpen(true)}>
            Timeline
          </HeaderButton>
          <HeaderButton icon={FileText} onClick={() => setRunbookOpen(true)}>
            Runbook
          </HeaderButton>
        </div>
      </div>

      {/* Phase tabs. */}
      <div className="flex flex-wrap gap-1 border-b px-4">
        {DETAIL_TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            title={t.hint}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm transition-colors",
              tab === t.key
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-4">
        <div className="space-y-4">
          {error && <ErrorBanner message={error} />}
          {planQ.isError && (
            <ErrorBanner message={formatApiError(planQ.error)} />
          )}

          {planQ.isLoading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading plan…
            </div>
          )}

          {plan && tab === "items" && (
            <ItemsTab
              planId={planId}
              items={items}
              onDiscover={() => setDiscoverOpen(true)}
            />
          )}
          {plan && tab === "parallel" && (
            <ParallelTab planId={planId} items={items} />
          )}
          {plan && tab === "cutover" && (
            <CutoverTab planId={planId} items={items} />
          )}
          {plan && tab === "decommission" && (
            <DecommissionTab planId={planId} canQuery={canQuery} />
          )}
        </div>
      </div>

      {discoverOpen && (
        <DiscoverModal
          planId={planId}
          onClose={() => setDiscoverOpen(false)}
          onAdded={() => {
            setDiscoverOpen(false);
            qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });
            qc.invalidateQueries({ queryKey: ["cutover", "plans"] });
          }}
        />
      )}
      {runbookOpen && (
        <RunbookModal
          planId={planId}
          canQuery={canQuery}
          onClose={() => setRunbookOpen(false)}
        />
      )}
      {timelineOpen && (
        <TimelineModal
          planId={planId}
          canQuery={canQuery}
          onClose={() => setTimelineOpen(false)}
        />
      )}
    </div>
  );
}

// ── Phase 1 — Items ───────────────────────────────────────────────────

function ItemsTab({
  planId,
  items,
  onDiscover,
}: {
  planId: string;
  items: CutoverItem[];
  onDiscover: () => void;
}) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [removing, setRemoving] = useState<CutoverItem | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [planParity, setPlanParity] = useState<CutoverPlanParityResult | null>(
    null,
  );
  const [runningItem, setRunningItem] = useState<string | null>(null);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });
    qc.invalidateQueries({ queryKey: ["cutover", "plans"] });
  };

  const itemParityMut = useMutation({
    mutationFn: (itemId: string) => cutoverApi.runItemParity(planId, itemId),
    onSuccess: () => {
      setError(null);
      setRunningItem(null);
      invalidate();
    },
    onError: (err: unknown) => {
      setRunningItem(null);
      setError(extractError(err));
    },
  });

  const planParityMut = useMutation({
    mutationFn: () => cutoverApi.runPlanParity(planId),
    onSuccess: (result) => {
      setError(null);
      setPlanParity(result);
      invalidate();
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const removeMut = useMutation({
    mutationFn: (itemId: string) => cutoverApi.deleteItem(planId, itemId),
    onSuccess: () => {
      setRemoving(null);
      setError(null);
      invalidate();
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1 text-xs text-muted-foreground">
          Parity answers one question per item: does SpatiumDDI hold what
          Windows is actually serving? A failed or unmatched pull is never
          treated as parity.
        </div>
        <div className="flex flex-shrink-0 flex-wrap items-center gap-2">
          <HeaderButton
            icon={planParityMut.isPending ? Loader2 : CheckCircle2}
            iconClassName={planParityMut.isPending ? "animate-spin" : undefined}
            onClick={() => planParityMut.mutate()}
            disabled={planParityMut.isPending || items.length === 0}
          >
            {planParityMut.isPending ? "Running parity…" : "Run parity on all"}
          </HeaderButton>
          <HeaderButton variant="primary" icon={Search} onClick={onDiscover}>
            Discover
          </HeaderButton>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {planParity && (
        <div className="rounded-md border bg-muted/20 p-3 text-xs">
          <span className="font-medium">
            {planParity.in_parity} of {planParity.total} item(s) in parity.
          </span>{" "}
          {planParity.items
            .filter((r) => r.status !== "ok")
            .map((r) => (
              <span key={r.item_id} className="mr-2 break-all">
                <Chip tone={PARITY_STATUS_TONES[r.status] ?? "muted"}>
                  {r.source_ref}: {r.status}
                </Chip>
              </span>
            ))}
        </div>
      )}

      {items.length === 0 ? (
        <div className="rounded-md border bg-muted/20 p-4 text-sm text-muted-foreground">
          This plan has no items. Run <strong>Discover</strong> to pull the
          zones and scopes off the live Windows source — each candidate comes
          back already matched against the target group, with its blockers
          computed.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border bg-background">
          <table className="w-full min-w-[64rem] text-sm">
            <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-8 px-2 py-2" />
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-left">Source ref</th>
                <th className="px-3 py-2 text-left">Matched target</th>
                <th className="px-3 py-2 text-left">Stage</th>
                <th className="px-3 py-2 text-left">Blockers</th>
                <th className="px-3 py-2 text-left">Last parity</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const target = item.zone_id ?? item.scope_id;
                const open = expanded === item.id;
                const busy = itemParityMut.isPending && runningItem === item.id;
                return (
                  <Fragment key={item.id}>
                    <tr className="border-t hover:bg-muted/20">
                      <td className="px-2 py-2 align-top">
                        <button
                          type="button"
                          aria-label={open ? "Collapse" : "Expand"}
                          onClick={() => setExpanded(open ? null : item.id)}
                          className="rounded p-1 text-muted-foreground hover:text-foreground"
                        >
                          {open ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </button>
                      </td>
                      <td className="px-3 py-2 align-top">
                        <Chip
                          tone={item.kind === "dns_zone" ? "info" : "violet"}
                        >
                          {item.kind}
                        </Chip>
                      </td>
                      <td className="break-all px-3 py-2 align-top font-mono text-xs">
                        {item.source_ref}
                      </td>
                      <td className="px-3 py-2 align-top">
                        {target ? (
                          <span className="break-all font-mono text-[10px] text-muted-foreground">
                            {target}
                          </span>
                        ) : (
                          <Chip tone="destructive">not linked</Chip>
                        )}
                      </td>
                      <td className="px-3 py-2 align-top">
                        <StageChip stage={item.stage} />
                      </td>
                      <td className="px-3 py-2 align-top">
                        <BlockerChips blockers={item.blockers} />
                      </td>
                      <td className="px-3 py-2 align-top">
                        <ParityCell item={item} />
                      </td>
                      <td className="px-3 py-2 align-top text-right">
                        <div className="flex flex-wrap justify-end gap-2">
                          <HeaderButton
                            className="px-2 py-1 text-xs"
                            icon={busy ? Loader2 : CheckCircle2}
                            iconClassName={busy ? "animate-spin" : undefined}
                            onClick={() => {
                              setRunningItem(item.id);
                              itemParityMut.mutate(item.id);
                            }}
                            disabled={itemParityMut.isPending}
                          >
                            Run parity
                          </HeaderButton>
                          <HeaderButton
                            variant="destructive"
                            className="px-2 py-1 text-xs"
                            icon={Trash2}
                            onClick={() => setRemoving(item)}
                          >
                            Remove
                          </HeaderButton>
                        </div>
                      </td>
                    </tr>
                    {open && (
                      <tr className="border-t bg-muted/10">
                        <td colSpan={8} className="px-3 py-3">
                          <ItemParityDetail item={item} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmModal
        open={removing !== null}
        tone="destructive"
        title="Remove item from plan?"
        message={
          <span>
            Removes{" "}
            <strong className="break-all">{removing?.source_ref}</strong> and
            its parity / shadow history from this plan. An item that has already
            been cut over cannot be removed — roll it back first.
          </span>
        }
        confirmLabel="Remove item"
        loading={removeMut.isPending}
        onConfirm={() => removing && removeMut.mutate(removing.id)}
        onClose={() => setRemoving(null)}
      />
    </div>
  );
}

function ItemParityDetail({ item }: { item: CutoverItem }) {
  const report: CutoverParityReport | null = item.last_parity;
  return (
    <div className="space-y-3">
      {item.blockers.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            Readiness
          </div>
          <BlockerList blockers={item.blockers} />
        </div>
      )}

      {!report ? (
        <p className="text-xs text-muted-foreground">
          No parity report yet — run one to compare this item against the live
          Windows object.
        </p>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <Chip tone={PARITY_STATUS_TONES[report.status] ?? "muted"}>
              {report.status}
            </Chip>
            <span>
              <strong className="text-foreground">{report.in_sync}</strong> in
              sync
            </span>
            <span>
              <strong className="text-foreground">
                {report.difference_count}
              </strong>{" "}
              difference(s)
            </span>
            {report.not_compared > 0 && (
              <span title="Records the source's read path cannot report — excluded from both counts.">
                <strong className="text-foreground">
                  {report.not_compared}
                </strong>{" "}
                not compared
              </span>
            )}
            {Object.entries(report.counts_by_class)
              .filter(([, n]) => n > 0)
              .map(([cls, n]) => (
                <Chip key={cls} tone={DIFF_TONES[cls] ?? "muted"}>
                  {cls} {n}
                </Chip>
              ))}
          </div>

          {report.error && <ErrorBanner message={report.error} />}
          <WarningList warnings={report.warnings} />

          {report.differences.length > 0 && (
            <div className="overflow-x-auto rounded-md border bg-background">
              <table className="w-full min-w-[48rem] text-sm">
                <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 text-left">Classification</th>
                    <th className="px-3 py-2 text-left">Name</th>
                    <th className="px-3 py-2 text-left">Type</th>
                    <th className="px-3 py-2 text-left">Detail</th>
                    <th className="px-3 py-2 text-left">Windows</th>
                    <th className="px-3 py-2 text-left">SpatiumDDI</th>
                  </tr>
                </thead>
                <tbody>
                  {report.differences.map((d, i) => (
                    <tr key={`${d.name}:${i}`} className="border-t">
                      <td className="px-3 py-2 align-top">
                        <Chip tone={DIFF_TONES[d.classification] ?? "muted"}>
                          {d.classification}
                        </Chip>
                      </td>
                      <td className="break-all px-3 py-2 align-top font-mono text-xs">
                        {d.name || "—"}
                      </td>
                      <td className="px-3 py-2 align-top text-xs">
                        {d.record_type ?? "—"}
                      </td>
                      <td className="break-words px-3 py-2 align-top text-xs text-muted-foreground">
                        {d.detail}
                      </td>
                      <td className="break-all px-3 py-2 align-top font-mono text-[11px]">
                        {d.source_value ?? "—"}
                      </td>
                      <td className="break-all px-3 py-2 align-top font-mono text-[11px]">
                        {d.target_value ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Phase 2 — parallel run ────────────────────────────────────────────

function ParallelTab({
  planId,
  items,
}: {
  planId: string;
  items: CutoverItem[];
}) {
  const dnsItems = items.filter((i) => i.kind === "dns_zone");
  if (dnsItems.length === 0) {
    return (
      <div className="rounded-md border bg-muted/20 p-4 text-sm text-muted-foreground">
        The shadow comparison is DNS-only — this plan has no{" "}
        <code>dns_zone</code> items. DHCP is verified by parity and by the lease
        handover on the Cutover tab.
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">
        Each run replays a sample of names at the Windows source and at every
        enabled server in the target group, then compares the answers. Names
        come from the recorded query log when there is one — that is what makes
        it a shadow of production traffic rather than a second config diff.
      </p>
      {dnsItems.map((item) => (
        <ShadowCard key={item.id} planId={planId} item={item} />
      ))}
    </div>
  );
}

function ShadowCard({ planId, item }: { planId: string; item: CutoverItem }) {
  const qc = useQueryClient();
  const [sampleSize, setSampleSize] = useState(25);
  const [error, setError] = useState<string | null>(null);
  const [fresh, setFresh] = useState<CutoverShadowReport | null>(null);

  const shadowMut = useMutation({
    mutationFn: () => cutoverApi.runShadow(planId, item.id, sampleSize),
    onSuccess: (report) => {
      setError(null);
      setFresh(report);
      qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const report = fresh ?? item.last_shadow;

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          <div className="break-all font-mono text-sm font-medium">
            {item.source_ref}
          </div>
          <div className="text-[11px] text-muted-foreground">
            Last run {shortDate(item.last_shadow_at)}
          </div>
        </div>
        <div className="flex flex-shrink-0 flex-wrap items-center gap-2">
          <label className="flex items-center gap-1 text-xs text-muted-foreground">
            Samples
            <input
              type="number"
              min={1}
              max={200}
              value={sampleSize}
              onChange={(e) =>
                setSampleSize(
                  Math.max(1, Math.min(200, Number(e.target.value) || 1)),
                )
              }
              className="w-20 rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <HeaderButton
            icon={shadowMut.isPending ? Loader2 : ArrowRightLeft}
            iconClassName={shadowMut.isPending ? "animate-spin" : undefined}
            onClick={() => shadowMut.mutate()}
            disabled={shadowMut.isPending}
          >
            {shadowMut.isPending ? "Querying…" : "Run shadow comparison"}
          </HeaderButton>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}

      {!report ? (
        <p className="text-xs text-muted-foreground">
          No shadow comparison recorded for this zone yet.
        </p>
      ) : (
        <div className="space-y-3">
          <SampleSourceBanner source={report.sample_source} />

          <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
            <span>
              <strong className="text-foreground">{report.sampled}</strong>{" "}
              sampled
            </span>
            <Chip tone="success">{report.matched} matched</Chip>
            {report.mismatched > 0 && (
              <Chip tone="destructive">{report.mismatched} mismatched</Chip>
            )}
            {report.errors > 0 && (
              <Chip tone="amber">{report.errors} error</Chip>
            )}
            <span className="break-all">
              source{" "}
              <strong className="text-foreground">{report.source}</strong>
              {report.targets.length > 0 && (
                <> · targets {report.targets.join(", ")}</>
              )}
            </span>
          </div>

          <WarningList warnings={report.warnings} />

          {report.samples.length > 0 && (
            <div className="overflow-x-auto rounded-md border bg-background">
              <table className="w-full min-w-[52rem] text-sm">
                <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 text-left">Name</th>
                    <th className="px-3 py-2 text-left">Type</th>
                    <th className="px-3 py-2 text-left">Verdict</th>
                    <th className="px-3 py-2 text-left">Windows answer</th>
                    <th className="px-3 py-2 text-left">SpatiumDDI answer</th>
                  </tr>
                </thead>
                <tbody>
                  {report.samples.map((s, i) => (
                    <tr key={`${s.name}:${s.qtype}:${i}`} className="border-t">
                      <td className="break-all px-3 py-2 align-top font-mono text-xs">
                        {s.name}
                      </td>
                      <td className="px-3 py-2 align-top text-xs">{s.qtype}</td>
                      <td className="px-3 py-2 align-top">
                        <Chip
                          tone={
                            s.verdict === "match"
                              ? "success"
                              : s.verdict === "mismatch"
                                ? "destructive"
                                : "amber"
                          }
                          title={s.error ?? undefined}
                        >
                          {s.verdict}
                        </Chip>
                      </td>
                      <td className="break-all px-3 py-2 align-top font-mono text-[11px]">
                        {s.source_answers.length
                          ? s.source_answers.join(", ")
                          : "—"}
                      </td>
                      <td className="px-3 py-2 align-top font-mono text-[11px]">
                        {Object.keys(s.target_answers).length === 0 ? (
                          "—"
                        ) : (
                          <ul className="space-y-0.5">
                            {Object.entries(s.target_answers).map(
                              ([target, answers]) => (
                                <li key={target} className="break-all">
                                  <span className="text-muted-foreground">
                                    {target}:
                                  </span>{" "}
                                  {answers.length ? answers.join(", ") : "—"}
                                </li>
                              ),
                            )}
                          </ul>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Where the sampled names came from decides how much the run proves. */
function SampleSourceBanner({ source }: { source: string }) {
  const isTraffic = source === "query_log";
  return (
    <div
      className={cn(
        "flex items-start gap-2 rounded-md border p-3 text-xs",
        isTraffic
          ? "border-emerald-500/40 bg-emerald-500/5"
          : "border-amber-500/40 bg-amber-500/5",
      )}
    >
      {isTraffic ? (
        <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-600 dark:text-emerald-400" />
      ) : (
        <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-600 dark:text-amber-400" />
      )}
      <div className="min-w-0">
        <div className="font-medium text-foreground">
          Sample source: <code>{source}</code>
        </div>
        {isTraffic ? (
          <p className="text-muted-foreground">
            Names were replayed from names clients actually asked for, so a
            clean run is evidence about production traffic.
          </p>
        ) : (
          <p className="text-muted-foreground">
            Names came from SpatiumDDI&apos;s own zone records, not from
            observed traffic — this proves the two servers agree about what we
            hold, not that they agree about what clients ask for. Turn the query
            log on for the source zone to get a real shadow run.
          </p>
        )}
      </div>
    </div>
  );
}

// ── Phase 3 — the switch ──────────────────────────────────────────────

function CutoverTab({
  planId,
  items,
}: {
  planId: string;
  items: CutoverItem[];
}) {
  if (items.length === 0) {
    return (
      <div className="rounded-md border bg-muted/20 p-4 text-sm text-muted-foreground">
        This plan has no items to cut over yet.
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">
        Pre-flight first, switch second. For DNS the pre-flight is the TTL drop
        and the switch is a delegation change SpatiumDDI does not own — it
        records the transition and hands back the steps. For DHCP the handover
        mints reservations from the live Windows leases, and the switch is real:
        the Windows scope is deactivated before the managed scope is activated.
      </p>
      {items.map((item) =>
        item.kind === "dns_zone" ? (
          <DnsCutoverCard key={item.id} planId={planId} item={item} />
        ) : (
          <DhcpCutoverCard key={item.id} planId={planId} item={item} />
        ),
      )}
    </div>
  );
}

/** Header + switch controls shared by the DNS and DHCP cards. */
function SwitchControls({
  planId,
  item,
}: {
  planId: string;
  item: CutoverItem;
}) {
  const qc = useQueryClient();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refused, setRefused] = useState<CutoverBlocker[]>([]);
  const [result, setResult] = useState<CutoverSwitchResult | null>(null);

  const blocked = hasBlocking(item.blockers);
  const warnings = warnOnly(item.blockers);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });
    qc.invalidateQueries({ queryKey: ["cutover", "plans"] });
  };

  const cutMut = useMutation({
    mutationFn: (force: boolean) => cutoverApi.cutOver(planId, item.id, force),
    onSuccess: (res) => {
      setConfirmOpen(false);
      setError(null);
      setRefused([]);
      setResult(res);
      invalidate();
    },
    onError: (err: unknown) => {
      setConfirmOpen(false);
      setError(extractError(err));
      setRefused(extractBlockers(err));
    },
  });

  const rollbackMut = useMutation({
    mutationFn: () => cutoverApi.rollback(planId, item.id),
    onSuccess: (res) => {
      setRollbackOpen(false);
      setError(null);
      setRefused([]);
      setResult(res);
      invalidate();
    },
    onError: (err: unknown) => {
      setRollbackOpen(false);
      setError(extractError(err));
      setRefused(extractBlockers(err));
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1 text-xs text-muted-foreground">
          {blocked
            ? "Cutting over is refused while a blocking readiness check fails. Fix the blocker below — there is no override."
            : warnings.length > 0
              ? "Warnings must be acknowledged before the switch."
              : "No blockers outstanding."}
        </div>
        <div className="flex flex-shrink-0 flex-wrap gap-2">
          <HeaderButton
            variant="primary"
            icon={cutMut.isPending ? Loader2 : ArrowRightLeft}
            iconClassName={cutMut.isPending ? "animate-spin" : undefined}
            onClick={() => setConfirmOpen(true)}
            disabled={blocked || cutMut.isPending || item.stage === "cut_over"}
            title={
              blocked
                ? "A blocking readiness check refuses this cutover."
                : undefined
            }
          >
            Cut over
          </HeaderButton>
          <HeaderButton
            icon={rollbackMut.isPending ? Loader2 : RotateCcw}
            iconClassName={rollbackMut.isPending ? "animate-spin" : undefined}
            onClick={() => setRollbackOpen(true)}
            disabled={rollbackMut.isPending || item.stage !== "cut_over"}
          >
            Roll back
          </HeaderButton>
        </div>
      </div>

      {error && <ErrorBanner message={error} />}
      {/* A refusal rolls its transaction back, so the freshly-evaluated
          blockers in the 409 body are the only copy of them — prefer those
          over the ones persisted on the item. */}
      <BlockerList blockers={refused.length > 0 ? refused : item.blockers} />
      {result && <SwitchResultPanel result={result} />}

      <ConfirmModal
        open={confirmOpen}
        tone="destructive"
        title={`Cut over ${item.source_ref}?`}
        message={
          <div className="space-y-3">
            <p>
              {item.kind === "dhcp_scope"
                ? "Deactivates the Windows scope, then activates the managed scope. Between the two the subnet has no DHCP server for one WinRM round-trip — that gap is deliberate, because two servers answering at once hand out conflicting addresses."
                : "Records the transition and returns the delegation steps. The Windows zone is left untouched and keeps serving as the fallback until you move the delegation."}
            </p>
            {item.blockers.length > 0 && (
              <div>
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider">
                  Outstanding readiness checks
                </div>
                <BlockerList blockers={item.blockers} />
              </div>
            )}
          </div>
        }
        confirmLabel="Cut over"
        requireCheckboxLabel={
          warnings.length > 0
            ? `I acknowledge the ${warnings.length} warning(s) above and want to proceed.`
            : undefined
        }
        loading={cutMut.isPending}
        onConfirm={() => cutMut.mutate(warnings.length > 0)}
        onClose={() => setConfirmOpen(false)}
      />

      <ConfirmModal
        open={rollbackOpen}
        title={`Roll ${item.source_ref} back?`}
        message={
          item.kind === "dhcp_scope"
            ? "Deactivates the managed scope, then re-activates the Windows scope. Reservations minted by the lease handover stay in place — they are harmless while the scope is inactive."
            : "Restores the pre-flight TTL snapshot and returns the steps for reverting the delegation."
        }
        confirmLabel="Roll back"
        loading={rollbackMut.isPending}
        onConfirm={() => rollbackMut.mutate()}
        onClose={() => setRollbackOpen(false)}
      />
    </div>
  );
}

function SwitchResultPanel({ result }: { result: CutoverSwitchResult }) {
  return (
    <div className="space-y-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 p-3 text-xs">
      <div className="font-medium text-emerald-700 dark:text-emerald-400">
        {result.stage === "rolled_back" ? "Rolled back" : "Cut over"} —{" "}
        <span className="break-all">{result.source_ref}</span>
      </div>
      {result.actions.length > 0 && (
        <ul className="list-inside list-disc space-y-0.5">
          {result.actions.map((a, i) => (
            <li key={i} className="break-words">
              {a}
            </li>
          ))}
        </ul>
      )}
      {result.instructions.length > 0 && (
        <div>
          <div className="mt-1 font-medium text-foreground">
            Operator-side steps
          </div>
          <ol className="list-inside list-decimal space-y-0.5">
            {result.instructions.map((s, i) => (
              <li key={i} className="break-words">
                {s}
              </li>
            ))}
          </ol>
        </div>
      )}
      {result.recovery_estimate_seconds != null && (
        <div className="text-muted-foreground">
          Expected recovery once reversed: ~{result.recovery_estimate_seconds}s.
        </div>
      )}
      <WarningList warnings={result.warnings ?? []} />
    </div>
  );
}

function DnsCutoverCard({
  planId,
  item,
}: {
  planId: string;
  item: CutoverItem;
}) {
  const qc = useQueryClient();
  const [targetTtl, setTargetTtl] = useState(300);
  const [preview, setPreview] = useState<CutoverTTLPreflightPlan | null>(null);
  const [committed, setCommitted] = useState<CutoverTTLPreflightPlan | null>(
    null,
  );
  const [restored, setRestored] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });

  const previewMut = useMutation({
    mutationFn: () => cutoverApi.previewTtl(planId, item.id, targetTtl),
    onSuccess: (plan) => {
      setError(null);
      setCommitted(null);
      setRestored(null);
      setPreview(plan);
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const commitMut = useMutation({
    mutationFn: () => cutoverApi.commitTtl(planId, item.id, targetTtl),
    onSuccess: (plan) => {
      setError(null);
      setRestored(null);
      setCommitted(plan);
      invalidate();
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const restoreMut = useMutation({
    mutationFn: () => cutoverApi.restoreTtl(planId, item.id),
    onSuccess: (res) => {
      setError(null);
      setPreview(null);
      setCommitted(null);
      setRestored(res.records_restored);
      invalidate();
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const shown = committed ?? preview;

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Chip tone="info">dns_zone</Chip>
        <span className="min-w-0 flex-1 break-all font-mono text-sm font-medium">
          {item.source_ref}
        </span>
        <StageChip stage={item.stage} />
      </div>

      <div className="space-y-3">
        <div className="rounded-md border bg-background p-3">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Timer className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
            <span className="min-w-0 flex-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              TTL pre-flight
            </span>
            <label className="flex items-center gap-1 text-xs text-muted-foreground">
              Target TTL (s)
              <input
                type="number"
                min={30}
                max={86400}
                value={targetTtl}
                onChange={(e) => setTargetTtl(Number(e.target.value) || 0)}
                className="w-24 rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <HeaderButton
                className="px-2 py-1 text-xs"
                icon={previewMut.isPending ? Loader2 : Search}
                iconClassName={
                  previewMut.isPending ? "animate-spin" : undefined
                }
                onClick={() => previewMut.mutate()}
                disabled={previewMut.isPending}
              >
                Preview
              </HeaderButton>
              <HeaderButton
                variant="primary"
                className="px-2 py-1 text-xs"
                icon={commitMut.isPending ? Loader2 : Timer}
                iconClassName={commitMut.isPending ? "animate-spin" : undefined}
                onClick={() => commitMut.mutate()}
                disabled={commitMut.isPending}
              >
                Commit
              </HeaderButton>
              <HeaderButton
                className="px-2 py-1 text-xs"
                icon={restoreMut.isPending ? Loader2 : RotateCcw}
                iconClassName={
                  restoreMut.isPending ? "animate-spin" : undefined
                }
                onClick={() => restoreMut.mutate()}
                disabled={restoreMut.isPending || !item.ttl_snapshot}
              >
                Restore
              </HeaderButton>
            </div>
          </div>

          <div className="mb-2 text-[11px] text-muted-foreground">
            {item.ttl_lowered_at
              ? `TTLs lowered ${shortDate(item.ttl_lowered_at)} — the snapshot taken before the first commit is what Restore replays.`
              : "TTLs have not been lowered for this zone. A rollback then propagates at the zone's full TTL."}
          </div>

          {error && <ErrorBanner message={error} />}
          {restored !== null && (
            <div className="rounded-md border border-emerald-500/40 bg-emerald-500/5 p-2 text-xs text-emerald-700 dark:text-emerald-400">
              Restored {restored} record TTL(s) from the pre-flight snapshot.
            </div>
          )}

          {shown && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                <Chip tone={committed ? "success" : "info"}>
                  {committed ? "committed" : "preview"}
                </Chip>
                <span>
                  target{" "}
                  <strong className="text-foreground">
                    {shown.target_ttl}s
                  </strong>
                </span>
                <span>
                  <strong className="text-foreground">{shown.changed}</strong>{" "}
                  changed
                </span>
                <span>
                  <strong className="text-foreground">{shown.unchanged}</strong>{" "}
                  already at or below
                </span>
                <span className="break-all">
                  SOA{" "}
                  {Object.entries(shown.zone_current)
                    .map(([k, v]) => `${k} ${v}`)
                    .join(" · ")}{" "}
                  →{" "}
                  {Object.entries(shown.zone_after)
                    .map(([k, v]) => `${k} ${v}`)
                    .join(" · ")}
                </span>
              </div>

              <WarningList warnings={shown.warnings} />

              {shown.source_side_instructions && (
                <CopyBlock
                  label="Run this on the Windows source — SpatiumDDI does not write its TTLs"
                  text={shown.source_side_instructions}
                />
              )}

              {shown.records.length > 0 && (
                <div className="overflow-x-auto rounded-md border bg-background">
                  <table className="w-full min-w-[36rem] text-sm">
                    <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                      <tr>
                        <th className="px-3 py-2 text-left">Record</th>
                        <th className="px-3 py-2 text-left">Type</th>
                        <th className="px-3 py-2 text-left">Current TTL</th>
                        <th className="px-3 py-2 text-left">New TTL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {shown.records.map((r) => (
                        <tr key={r.record_id} className="border-t">
                          <td className="break-all px-3 py-2 align-top font-mono text-xs">
                            {r.name || "@"}
                          </td>
                          <td className="px-3 py-2 align-top text-xs">
                            {r.record_type}
                          </td>
                          <td className="px-3 py-2 align-top text-xs tabular-nums">
                            {r.current_ttl ?? "inherit"}
                          </td>
                          <td className="px-3 py-2 align-top text-xs tabular-nums">
                            {r.new_ttl}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>

        <SwitchControls planId={planId} item={item} />
      </div>
    </div>
  );
}

function DhcpCutoverCard({
  planId,
  item,
}: {
  planId: string;
  item: CutoverItem;
}) {
  const qc = useQueryClient();
  const [preview, setPreview] = useState<CutoverLeaseHandoverPlan | null>(null);
  const [committed, setCommitted] = useState<CutoverLeaseHandoverPlan | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);

  const previewMut = useMutation({
    mutationFn: () => cutoverApi.previewLeases(planId, item.id),
    onSuccess: (plan) => {
      setError(null);
      setCommitted(null);
      setPreview(plan);
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const commitMut = useMutation({
    mutationFn: () => {
      if (!preview) throw new Error("Preview the lease handover first");
      return cutoverApi.commitLeases(planId, item.id, preview.entries);
    },
    onSuccess: (plan) => {
      setError(null);
      setCommitted(plan);
      qc.invalidateQueries({ queryKey: ["cutover", "plan", planId] });
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  // Only a real plan (from this session's preview or commit) has entries and
  // warnings to render. ``item.lease_handover`` is the persisted summary —
  // four counters and a timestamp — so it gets its own compact line below
  // rather than being fed to the table renderer.
  const shown = committed ?? preview;
  const lastRun = item.lease_handover;

  return (
    <div className="rounded-md border bg-muted/20 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Chip tone="violet">dhcp_scope</Chip>
        <span className="min-w-0 flex-1 break-all font-mono text-sm font-medium">
          {item.source_ref}
        </span>
        <StageChip stage={item.stage} />
      </div>

      <div className="space-y-3">
        <div className="rounded-md border bg-background p-3">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <ClipboardList className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
            <span className="min-w-0 flex-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Lease handover
            </span>
            <div className="flex flex-wrap gap-2">
              <HeaderButton
                className="px-2 py-1 text-xs"
                icon={previewMut.isPending ? Loader2 : Search}
                iconClassName={
                  previewMut.isPending ? "animate-spin" : undefined
                }
                onClick={() => previewMut.mutate()}
                disabled={previewMut.isPending}
              >
                Preview
              </HeaderButton>
              <HeaderButton
                variant="primary"
                className="px-2 py-1 text-xs"
                icon={commitMut.isPending ? Loader2 : ClipboardList}
                iconClassName={commitMut.isPending ? "animate-spin" : undefined}
                onClick={() => commitMut.mutate()}
                disabled={commitMut.isPending || !preview}
              >
                Commit
              </HeaderButton>
            </div>
          </div>

          <p className="mb-2 text-[11px] text-muted-foreground">
            Turns each live Windows lease into a reservation on the managed
            scope, so a client renewing against Kea keeps the address it already
            holds instead of drawing a fresh one from an empty pool. Rows are
            re-classified against live data at commit, so a reservation added
            between the two calls is skipped rather than failing the batch.
          </p>

          {error && <ErrorBanner message={error} />}

          {lastRun && (
            <p className="mb-2 text-xs text-muted-foreground">
              Last handover{" "}
              <span className="text-foreground">
                {new Date(lastRun.at).toLocaleString()}
              </span>
              : <strong className="text-foreground">{lastRun.created}</strong>{" "}
              created ·{" "}
              <strong className="text-foreground">{lastRun.skipped}</strong>{" "}
              skipped ·{" "}
              <strong className="text-foreground">{lastRun.failed}</strong>{" "}
              failed. Preview again to see the current lease table.
            </p>
          )}

          {!shown ? (
            <p className="text-xs text-muted-foreground">
              No handover previewed yet.
            </p>
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                {shown.scope_cidr && (
                  <span className="break-all font-mono">
                    {shown.scope_cidr}
                  </span>
                )}
                <Chip tone="success">{shown.create_count} create</Chip>
                <Chip tone="muted">{shown.skip_count} skip</Chip>
                {shown.conflict_count > 0 && (
                  <Chip tone="destructive">
                    {shown.conflict_count} conflict
                  </Chip>
                )}
                {shown.created + shown.skipped + shown.failed > 0 && (
                  <span>
                    committed:{" "}
                    <strong className="text-foreground">{shown.created}</strong>{" "}
                    created ·{" "}
                    <strong className="text-foreground">{shown.skipped}</strong>{" "}
                    skipped ·{" "}
                    <strong className="text-foreground">{shown.failed}</strong>{" "}
                    failed
                  </span>
                )}
              </div>

              <WarningList warnings={shown.warnings} />

              {shown.entries.length > 0 && (
                <div className="overflow-x-auto rounded-md border bg-background">
                  <table className="w-full min-w-[52rem] text-sm">
                    <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                      <tr>
                        <th className="px-3 py-2 text-left">IP</th>
                        <th className="px-3 py-2 text-left">MAC</th>
                        <th className="px-3 py-2 text-left">Hostname</th>
                        <th className="px-3 py-2 text-left">Action</th>
                        <th className="px-3 py-2 text-left">Reason</th>
                        <th className="px-3 py-2 text-left">Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {shown.entries.map((e, i) => (
                        <tr
                          key={`${e.mac_address}:${e.ip_address}:${i}`}
                          className="border-t"
                        >
                          <td className="break-all px-3 py-2 align-top font-mono text-xs">
                            {e.ip_address}
                          </td>
                          <td className="break-all px-3 py-2 align-top font-mono text-xs">
                            {e.mac_address}
                          </td>
                          <td className="break-all px-3 py-2 align-top text-xs">
                            {e.hostname || "—"}
                          </td>
                          <td className="px-3 py-2 align-top">
                            <Chip
                              tone={
                                e.action === "create"
                                  ? "success"
                                  : e.action === "conflict"
                                    ? "destructive"
                                    : "muted"
                              }
                            >
                              {e.action}
                            </Chip>
                          </td>
                          <td className="break-words px-3 py-2 align-top text-xs text-muted-foreground">
                            {e.reason || "—"}
                          </td>
                          <td className="break-words px-3 py-2 align-top text-xs">
                            {e.result ? (
                              <Chip
                                tone={
                                  e.result === "created"
                                    ? "success"
                                    : e.result === "failed"
                                      ? "destructive"
                                      : "muted"
                                }
                                title={e.error ?? undefined}
                              >
                                {e.result}
                              </Chip>
                            ) : (
                              "—"
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>

        <SwitchControls planId={planId} item={item} />
      </div>
    </div>
  );
}

// ── Phase 4 — decommission checklist ──────────────────────────────────

function DecommissionTab({
  planId,
  canQuery,
}: {
  planId: string;
  canQuery: boolean;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const checklistQ = useQuery({
    queryKey: ["cutover", "checklist", planId],
    queryFn: () => cutoverApi.getChecklist(planId),
    enabled: canQuery,
  });

  const patchMut = useMutation({
    mutationFn: (args: {
      key: string;
      body: { is_done?: boolean; notes?: string };
    }) => cutoverApi.patchChecklistItem(planId, args.key, args.body),
    onSuccess: () => {
      setError(null);
      qc.invalidateQueries({ queryKey: ["cutover", "checklist", planId] });
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const rows = checklistQ.data ?? [];
  const grouped = useMemo(() => {
    const m = new Map<string, CutoverChecklistItem[]>();
    for (const r of rows) {
      const arr = m.get(r.category) ?? [];
      arr.push(r);
      m.set(r.category, arr);
    }
    return Array.from(m.entries());
  }, [rows]);

  const done = rows.filter((r) => r.is_done).length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="min-w-0 flex-1 text-xs text-muted-foreground">
          The switch is the visible part; the decommission is the part that
          bites weeks later. Auto-checks are advisory — they never tick a box.
        </p>
        <Chip
          tone={done === rows.length && rows.length > 0 ? "success" : "muted"}
        >
          {done} / {rows.length} done
        </Chip>
      </div>

      {error && <ErrorBanner message={error} />}
      {checklistQ.isError && (
        <ErrorBanner message={formatApiError(checklistQ.error)} />
      )}

      {checklistQ.isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading checklist…
        </div>
      ) : (
        grouped.map(([category, entries]) => (
          <div key={category} className="space-y-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {CATEGORY_LABELS[category] ?? category}
            </h2>
            {entries.map((entry) => (
              <ChecklistRow
                key={entry.key}
                entry={entry}
                saving={patchMut.isPending}
                onToggle={(isDone) =>
                  patchMut.mutate({ key: entry.key, body: { is_done: isDone } })
                }
                onNotes={(notes) =>
                  patchMut.mutate({ key: entry.key, body: { notes } })
                }
              />
            ))}
          </div>
        ))
      )}
    </div>
  );
}

function ChecklistRow({
  entry,
  saving,
  onToggle,
  onNotes,
}: {
  entry: CutoverChecklistItem;
  saving: boolean;
  onToggle: (isDone: boolean) => void;
  onNotes: (notes: string) => void;
}) {
  const [notes, setNotes] = useState(entry.notes);

  // The server row is the source of truth: re-sync the draft whenever a PATCH
  // (or a refetch) brings back different text, so an edit elsewhere isn't
  // silently overwritten by a stale local draft.
  useEffect(() => {
    setNotes(entry.notes);
  }, [entry.notes]);

  return (
    <div
      className={cn(
        "rounded-md border p-3",
        entry.is_done
          ? "border-emerald-500/40 bg-emerald-500/5"
          : "bg-muted/20",
      )}
    >
      <div className="flex items-start gap-3">
        <input
          type="checkbox"
          checked={entry.is_done}
          disabled={saving}
          onChange={(e) => onToggle(e.target.checked)}
          className="mt-1 h-4 w-4 flex-shrink-0 cursor-pointer rounded border focus:ring-2 focus:ring-ring"
          aria-label={entry.label}
        />
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="min-w-0 flex-1 break-words text-sm font-medium">
              {entry.label}
            </span>
            <Chip tone="muted" title={`Applies to ${entry.applies_to}`}>
              {entry.applies_to}
            </Chip>
            <Chip
              tone={AUTO_STATE_TONES[entry.auto_state] ?? "muted"}
              title={entry.auto_detail || undefined}
            >
              auto: {entry.auto_state}
            </Chip>
          </div>
          <p className="break-words text-xs text-muted-foreground">
            {entry.description}
          </p>
          {entry.auto_detail && (
            <p
              className={cn(
                "break-words rounded-md border p-2 text-[11px]",
                entry.auto_state === "attention"
                  ? "border-amber-500/40 bg-amber-500/5 text-amber-700 dark:text-amber-300"
                  : "bg-background text-muted-foreground",
              )}
            >
              {entry.auto_detail}
            </p>
          )}
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            onBlur={() => {
              if (notes !== entry.notes) onNotes(notes);
            }}
            rows={2}
            placeholder="Notes — who checked this, when, ticket reference…"
            className="w-full rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
          />
          {entry.done_at && (
            <p className="text-[11px] text-muted-foreground">
              Marked done {shortDate(entry.done_at)}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Discover ──────────────────────────────────────────────────────────

function DiscoverModal({
  planId,
  onClose,
  onAdded,
}: {
  planId: string;
  onClose: () => void;
  onAdded: () => void;
}) {
  const [result, setResult] = useState<{
    dns: CutoverCandidate[];
    dhcp: CutoverCandidate[];
    dnsError: string | null;
    dhcpError: string | null;
  } | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const discoverMut = useMutation({
    mutationFn: () => cutoverApi.discover(planId),
    onSuccess: (res) => {
      setError(null);
      setSelected(new Set());
      // Each side is independent: a WinRM failure on one reports its own
      // ``error`` string while the other still returns candidates.
      setResult({
        dns: res.dns.candidates,
        dhcp: res.dhcp.candidates,
        dnsError: res.dns.error,
        dhcpError: res.dhcp.error,
      });
    },
    onError: (err: unknown) => setError(extractError(err)),
  });

  const addMut = useMutation({
    mutationFn: (items: CutoverItemIn[]) => cutoverApi.addItems(planId, items),
    onSuccess: onAdded,
    onError: (err: unknown) => setError(extractError(err)),
  });

  const candidates = useMemo(
    () => [...(result?.dns ?? []), ...(result?.dhcp ?? [])],
    [result],
  );

  const toggle = (ref: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(ref)) next.delete(ref);
      else next.add(ref);
      return next;
    });

  const add = () => {
    const chosen = candidates.filter(
      (c) => selected.has(`${c.kind}:${c.source_ref}`) && !c.already_in_plan,
    );
    if (chosen.length === 0) return;
    addMut.mutate(
      chosen.map((c) => ({
        kind: c.kind,
        source_ref: c.source_ref,
        zone_id: c.kind === "dns_zone" ? c.matched_id : null,
        scope_id: c.kind === "dhcp_scope" ? c.matched_id : null,
      })),
    );
  };

  return (
    <Modal
      title="Discover candidates from the Windows source"
      onClose={onClose}
      wide
    >
      <div className="space-y-4">
        <p className="text-xs text-muted-foreground">
          Live-pulls the zones and scopes off the plan&apos;s source servers,
          matches each against the target group (zones by name, scopes by subnet
          CIDR) and pre-computes its blockers. Read-only — nothing is written
          until you add the selected rows.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <HeaderButton
            icon={discoverMut.isPending ? Loader2 : Search}
            iconClassName={discoverMut.isPending ? "animate-spin" : undefined}
            onClick={() => discoverMut.mutate()}
            disabled={discoverMut.isPending}
          >
            {discoverMut.isPending ? "Pulling…" : "Run discovery"}
          </HeaderButton>
          <div className="min-w-0 flex-1" />
          <HeaderButton
            variant="primary"
            icon={addMut.isPending ? Loader2 : Plus}
            iconClassName={addMut.isPending ? "animate-spin" : undefined}
            onClick={add}
            disabled={addMut.isPending || selected.size === 0}
          >
            Add {selected.size} item(s)
          </HeaderButton>
        </div>

        {error && <ErrorBanner message={error} />}
        {result?.dnsError && <ErrorBanner message={result.dnsError} />}
        {result?.dhcpError && <ErrorBanner message={result.dhcpError} />}

        {result && candidates.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No candidates came back from either source.
          </p>
        )}

        {candidates.length > 0 && (
          <div className="overflow-x-auto rounded-md border bg-background">
            <table className="w-full min-w-[44rem] text-sm">
              <thead className="bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="w-8 px-2 py-2" />
                  <th className="px-3 py-2 text-left">Candidate</th>
                  <th className="px-3 py-2 text-left">Kind</th>
                  <th className="px-3 py-2 text-left">Matched</th>
                  <th className="px-3 py-2 text-left">Blockers</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((c) => {
                  const key = `${c.kind}:${c.source_ref}`;
                  return (
                    <tr key={key} className="border-t">
                      <td className="px-2 py-2 align-top">
                        <input
                          type="checkbox"
                          checked={selected.has(key)}
                          disabled={c.already_in_plan}
                          onChange={() => toggle(key)}
                          className="h-4 w-4 cursor-pointer rounded border focus:ring-2 focus:ring-ring"
                          aria-label={`Select ${c.source_ref}`}
                        />
                      </td>
                      <td className="break-all px-3 py-2 align-top">
                        <span className="font-mono text-xs">
                          {c.display_name}
                        </span>
                        {c.already_in_plan && (
                          <span className="ml-2">
                            <Chip tone="muted">already in plan</Chip>
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 align-top">
                        <Chip tone={c.kind === "dns_zone" ? "info" : "violet"}>
                          {c.kind}
                        </Chip>
                      </td>
                      <td className="break-all px-3 py-2 align-top text-xs">
                        {c.matched_display ?? (
                          <Chip tone="destructive">no target</Chip>
                        )}
                      </td>
                      <td className="px-3 py-2 align-top">
                        <BlockerChips blockers={c.blockers} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Modal>
  );
}

// ── Runbook + timeline ────────────────────────────────────────────────

function RunbookModal({
  planId,
  canQuery,
  onClose,
}: {
  planId: string;
  canQuery: boolean;
  onClose: () => void;
}) {
  const runbookQ = useQuery({
    queryKey: ["cutover", "runbook", planId],
    queryFn: () => cutoverApi.runbook(planId),
    enabled: canQuery,
  });

  return (
    <Modal title="Cutover runbook" onClose={onClose} wide>
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Generated from the plan&apos;s persisted state — it does not re-pull
          the Windows source, so it is safe to produce for a change ticket.
          Markdown, verbatim.
        </p>
        {runbookQ.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Rendering…
          </div>
        ) : runbookQ.isError ? (
          <ErrorBanner message={formatApiError(runbookQ.error)} />
        ) : (
          <CopyBlock label="runbook.md" text={runbookQ.data?.markdown ?? ""} />
        )}
      </div>
    </Modal>
  );
}

function TimelineModal({
  planId,
  canQuery,
  onClose,
}: {
  planId: string;
  canQuery: boolean;
  onClose: () => void;
}) {
  const eventsQ = useQuery({
    queryKey: ["cutover", "events", planId],
    queryFn: () => cutoverApi.listEvents(planId, { limit: 200 }),
    enabled: canQuery,
  });

  const events = eventsQ.data ?? [];

  return (
    <Modal title="Plan timeline" onClose={onClose} wide>
      <div className="space-y-3">
        {eventsQ.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading timeline…
          </div>
        ) : eventsQ.isError ? (
          <ErrorBanner message={formatApiError(eventsQ.error)} />
        ) : events.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            Nothing has happened on this plan yet.
          </p>
        ) : (
          <ul className="space-y-2">
            {events.map((e) => (
              <li key={e.id} className="rounded-md border bg-muted/20 p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone="muted">{e.kind}</Chip>
                  <span className="text-[11px] text-muted-foreground">
                    {shortDate(e.at)}
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {e.user_display_name}
                  </span>
                </div>
                <p className="mt-1 break-words text-xs">{e.summary}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Modal>
  );
}
