import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  circuitsApi,
  customersApi,
  providersApi,
  sitesApi,
  type CircuitCreate,
  type CircuitRead,
  type CircuitStatus,
  type CircuitUpdate,
  type TransportClass,
  formatApiError,
} from "@/lib/api";
import { formatDateOnly, termDaysLeft } from "@/lib/localTime";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal, ModalTabs } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { ServicesUsingButton } from "@/components/ServicesUsingButton";
import { SavedViewsMenu } from "@/components/SavedViewsMenu";
import { TagFilterChips } from "@/components/TagFilterChips";
import {
  CustomerChip,
  ProviderChip,
  SiteChip,
} from "@/components/ownership/pickers";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const TRANSPORT_CLASSES: TransportClass[] = [
  "mpls",
  "internet_broadband",
  "fiber_direct",
  "wavelength",
  "lte",
  "satellite",
  "direct_connect_aws",
  "express_route_azure",
  "interconnect_gcp",
];

// Operator-facing labels — verbose-form for the picker, short-form
// for table cells (per the admin-page memory: kind chips with verbose
// picker labels need a separate short label for list views).
const TRANSPORT_LABELS: Record<TransportClass, string> = {
  mpls: "MPLS L3VPN",
  internet_broadband: "Internet broadband",
  fiber_direct: "Direct fiber (dark)",
  wavelength: "Wavelength (DWDM)",
  lte: "LTE / 5G cellular",
  satellite: "Satellite",
  direct_connect_aws: "AWS Direct Connect",
  express_route_azure: "Azure ExpressRoute",
  interconnect_gcp: "GCP Cloud Interconnect",
};

const TRANSPORT_LABELS_SHORT: Record<TransportClass, string> = {
  mpls: "MPLS",
  internet_broadband: "Broadband",
  fiber_direct: "Fiber",
  wavelength: "λ",
  lte: "LTE",
  satellite: "SAT",
  direct_connect_aws: "AWS DX",
  express_route_azure: "Azure ER",
  interconnect_gcp: "GCP IC",
};

const STATUSES: CircuitStatus[] = ["active", "pending", "suspended", "decom"];

function StatusBadge({ status }: { status: CircuitStatus }) {
  const styles: Record<CircuitStatus, string> = {
    active:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    pending:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
    suspended:
      "bg-rose-100 text-rose-700 dark:bg-rose-950/30 dark:text-rose-400",
    decom: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        styles[status],
      )}
    >
      {status}
    </span>
  );
}

function TermBadge({ termEnd }: { termEnd: string | null }) {
  if (!termEnd) return <span className="text-muted-foreground/50">—</span>;
  const days = termDaysLeft(termEnd);
  let cls =
    "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400";
  let label = `${days}d`;
  if (days < 0) {
    cls = "bg-red-200 text-red-900 dark:bg-red-950/50 dark:text-red-300";
    label = `expired ${Math.abs(days)}d ago`;
  } else if (days < 30) {
    cls = "bg-red-100 text-red-700 dark:bg-red-950/30 dark:text-red-400";
  } else if (days <= 90) {
    cls =
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400";
  }
  return (
    <span className="inline-flex items-center gap-2">
      <span className="text-[11px] tabular-nums text-muted-foreground">
        {formatDateOnly(termEnd)}
      </span>
      <span
        className={cn(
          "rounded px-2 py-0.5 text-[10px] font-medium tabular-nums",
          cls,
        )}
      >
        {label}
      </span>
    </span>
  );
}

function fmtBandwidth(mbps: number): string {
  if (mbps >= 1000 && mbps % 1000 === 0) return `${mbps / 1000} Gbps`;
  if (mbps >= 1000) return `${(mbps / 1000).toFixed(1)} Gbps`;
  return `${mbps} Mbps`;
}

function formatCost(cost: string | null, currency: string): string {
  if (!cost) return "—";
  const n = Number(cost);
  if (Number.isNaN(n)) return cost;
  return `${n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency}`;
}

// ── Editor modal ────────────────────────────────────────────────────

type EditorTab = "general" | "endpoints" | "term" | "notes";

export function CircuitEditorModal({
  existing,
  onClose,
}: {
  existing: CircuitRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [tab, setTab] = useState<EditorTab>("general");

  // ── identity ──
  const [name, setName] = useState(existing?.name ?? "");
  const [cktId, setCktId] = useState(existing?.ckt_id ?? "");
  const [providerId, setProviderId] = useState(existing?.provider_id ?? "");
  const [customerId, setCustomerId] = useState<string | null>(
    existing?.customer_id ?? null,
  );
  const [transportClass, setTransportClass] = useState<TransportClass>(
    existing?.transport_class ?? "internet_broadband",
  );
  const [bwDown, setBwDown] = useState(
    String(existing?.bandwidth_mbps_down ?? 0),
  );
  const [bwUp, setBwUp] = useState(String(existing?.bandwidth_mbps_up ?? 0));
  const [status, setStatus] = useState<CircuitStatus>(
    existing?.status ?? "active",
  );

  // ── endpoints ──
  const [aSiteId, setASiteId] = useState<string | null>(
    existing?.a_end_site_id ?? null,
  );
  const [aSubnetId, setASubnetId] = useState<string | null>(
    existing?.a_end_subnet_id ?? null,
  );
  const [zSiteId, setZSiteId] = useState<string | null>(
    existing?.z_end_site_id ?? null,
  );
  const [zSubnetId, setZSubnetId] = useState<string | null>(
    existing?.z_end_subnet_id ?? null,
  );

  // ── term + cost ──
  const [termStart, setTermStart] = useState(existing?.term_start_date ?? "");
  const [termEnd, setTermEnd] = useState(existing?.term_end_date ?? "");
  const [monthlyCost, setMonthlyCost] = useState(existing?.monthly_cost ?? "");
  const [currency, setCurrency] = useState(existing?.currency ?? "USD");

  // ── notes ──
  const [notes, setNotes] = useState(existing?.notes ?? "");

  const [error, setError] = useState<string | null>(null);

  // Picker data — only fetched once, shared across the four pickers.
  const providersQ = useQuery({
    queryKey: ["providers", "all"],
    queryFn: () => providersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const sitesQ = useQuery({
    queryKey: ["sites", "all"],
    queryFn: () => sitesApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const providers = providersQ.data?.items ?? [];
  const customers = customersQ.data?.items ?? [];
  const sites = sitesQ.data?.items ?? [];

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      if (!providerId) throw new Error("Provider is required");
      const body: CircuitCreate | CircuitUpdate = {
        name,
        ckt_id: cktId || null,
        provider_id: providerId,
        customer_id: customerId,
        transport_class: transportClass,
        bandwidth_mbps_down: Number(bwDown) || 0,
        bandwidth_mbps_up: Number(bwUp) || 0,
        a_end_site_id: aSiteId,
        a_end_subnet_id: aSubnetId,
        z_end_site_id: zSiteId,
        z_end_subnet_id: zSubnetId,
        term_start_date: termStart || null,
        term_end_date: termEnd || null,
        monthly_cost: monthlyCost || null,
        currency: currency || "USD",
        status,
        notes,
      };
      if (existing) return circuitsApi.update(existing.id, body);
      return circuitsApi.create(body as CircuitCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["circuits"] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  return (
    <Modal
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New circuit"}
      wide
    >
      <div className="space-y-3 pb-4">
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. NYC-LON primary"
            autoFocus={!existing}
          />
        </div>
      </div>

      <ModalTabs<EditorTab>
        tabs={[
          { key: "general", label: "General" },
          { key: "endpoints", label: "Endpoints" },
          { key: "term", label: "Term + cost" },
          { key: "notes", label: "Notes" },
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === "general" && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Carrier circuit ID
            </label>
            <input
              className={inputCls}
              value={cktId}
              onChange={(e) => setCktId(e.target.value)}
              placeholder="Carrier-supplied identifier (e.g. COG-9001)"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Provider
            </label>
            <select
              className={inputCls}
              value={providerId}
              onChange={(e) => setProviderId(e.target.value)}
            >
              <option value="">— select —</option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} · {p.kind}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Customer (optional)
            </label>
            <select
              className={inputCls}
              value={customerId ?? ""}
              onChange={(e) => setCustomerId(e.target.value || null)}
            >
              <option value="">— None —</option>
              {customers.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Transport class
            </label>
            <select
              className={inputCls}
              value={transportClass}
              onChange={(e) =>
                setTransportClass(e.target.value as TransportClass)
              }
            >
              {TRANSPORT_CLASSES.map((t) => (
                <option key={t} value={t}>
                  {TRANSPORT_LABELS[t]}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Status
            </label>
            <select
              className={inputCls}
              value={status}
              onChange={(e) => setStatus(e.target.value as CircuitStatus)}
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Bandwidth down (Mbps)
            </label>
            <input
              type="number"
              min={0}
              className={inputCls}
              value={bwDown}
              onChange={(e) => setBwDown(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Bandwidth up (Mbps)
            </label>
            <input
              type="number"
              min={0}
              className={inputCls}
              value={bwUp}
              onChange={(e) => setBwUp(e.target.value)}
            />
          </div>
        </div>
      )}

      {tab === "endpoints" && (
        <div className="space-y-4">
          <p className="text-xs text-muted-foreground">
            A-end / Z-end are arbitrary directional labels. Pick the site
            terminating each end and (optionally) the /30 or /31 subnet used at
            that termination.
          </p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-3 rounded border bg-muted/20 p-3">
              <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                A-end
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">
                  Site
                </label>
                <select
                  className={inputCls}
                  value={aSiteId ?? ""}
                  onChange={(e) => setASiteId(e.target.value || null)}
                >
                  <option value="">— None —</option>
                  {sites.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                      {s.code ? ` (${s.code})` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">
                  Subnet UUID (optional)
                </label>
                <input
                  className={inputCls}
                  value={aSubnetId ?? ""}
                  onChange={(e) => setASubnetId(e.target.value || null)}
                  placeholder="UUID of the /30 used at this end"
                />
                <p className="mt-0.5 text-[11px] text-muted-foreground/80">
                  Pasted from the IPAM subnet detail page (subnet picker UI is a
                  follow-up).
                </p>
              </div>
            </div>
            <div className="space-y-3 rounded border bg-muted/20 p-3">
              <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Z-end
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">
                  Site
                </label>
                <select
                  className={inputCls}
                  value={zSiteId ?? ""}
                  onChange={(e) => setZSiteId(e.target.value || null)}
                >
                  <option value="">— None —</option>
                  {sites.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                      {s.code ? ` (${s.code})` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs font-medium text-muted-foreground">
                  Subnet UUID (optional)
                </label>
                <input
                  className={inputCls}
                  value={zSubnetId ?? ""}
                  onChange={(e) => setZSubnetId(e.target.value || null)}
                  placeholder="UUID of the /30 used at this end"
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === "term" && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Term start
            </label>
            <input
              type="date"
              className={inputCls}
              value={termStart}
              onChange={(e) => setTermStart(e.target.value)}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Term end
            </label>
            <input
              type="date"
              className={inputCls}
              value={termEnd}
              onChange={(e) => setTermEnd(e.target.value)}
            />
            <p className="mt-0.5 text-[11px] text-muted-foreground/80">
              Drives the future expiring-soon alert rule.
            </p>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Monthly cost
            </label>
            <input
              type="text"
              inputMode="decimal"
              className={inputCls}
              value={monthlyCost}
              onChange={(e) => setMonthlyCost(e.target.value)}
              placeholder="e.g. 1500.00"
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Currency
            </label>
            <input
              className={cn(inputCls, "uppercase")}
              maxLength={3}
              value={currency}
              onChange={(e) => setCurrency(e.target.value.toUpperCase())}
              placeholder="USD"
            />
            <p className="mt-0.5 text-[11px] text-muted-foreground/80">
              ISO 4217 3-letter code. Reports group by currency rather than
              converting.
            </p>
          </div>
        </div>
      )}

      {tab === "notes" && (
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Notes
          </label>
          <textarea
            className={cn(inputCls, "min-h-[160px]")}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="LOA reference numbers, escalation contacts, anything else worth knowing about this circuit."
          />
        </div>
      )}

      {error && <p className="mt-3 text-sm text-destructive">{error}</p>}

      <div className="mt-6 flex justify-end gap-2 border-t pt-3">
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={mut.isPending}
          onClick={() => mut.mutate()}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
        </button>
      </div>
    </Modal>
  );
}

// ── Page ────────────────────────────────────────────────────────────

export function CircuitsPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the circuit router asks write (delete) on 'circuit'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "circuit"),
    "Requires write permission on circuits",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "circuit"),
    "Requires delete permission on circuits",
  );
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<CircuitStatus | "">("");
  const [transportFilter, setTransportFilter] = useState<TransportClass | "">(
    "",
  );
  const [providerFilter, setProviderFilter] = useState("");
  const [editing, setEditing] = useState<CircuitRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [tagFilters, setTagFilters] = useState<string[]>([]);

  const providersQ = useQuery({
    queryKey: ["providers", "all"],
    queryFn: () => providersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  // Saved-views payload (#77) — the page's filter state, stored verbatim.
  type CircuitsViewPayload = {
    search: string;
    status: CircuitStatus | "";
    transport: TransportClass | "";
    provider_id: string;
    tags: string[];
  };
  const viewPayload: CircuitsViewPayload = {
    search,
    status: statusFilter,
    transport: transportFilter,
    provider_id: providerFilter,
    tags: tagFilters,
  };
  function applyView(p: CircuitsViewPayload) {
    setSearch(typeof p.search === "string" ? p.search : "");
    setStatusFilter((p.status ?? "") as CircuitStatus | "");
    setTransportFilter((p.transport ?? "") as TransportClass | "");
    setProviderFilter(typeof p.provider_id === "string" ? p.provider_id : "");
    setTagFilters(Array.isArray(p.tags) ? p.tags : []);
  }

  const query = useQuery({
    queryKey: [
      "circuits",
      search,
      statusFilter,
      transportFilter,
      providerFilter,
      tagFilters,
    ],
    queryFn: () =>
      circuitsApi.list({
        limit: 500,
        search: search || undefined,
        status: (statusFilter || undefined) as CircuitStatus | undefined,
        transport_class: (transportFilter || undefined) as
          | TransportClass
          | undefined,
        provider_id: providerFilter || undefined,
        tag: tagFilters.length > 0 ? tagFilters : undefined,
      }),
  });

  const items = query.data?.items ?? [];

  const allChecked = useMemo(
    () => items.length > 0 && items.every((c) => selectedIds.has(c.id)),
    [items, selectedIds],
  );

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => circuitsApi.bulkDelete(ids),
    onSuccess: () => {
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["circuits"] });
    },
  });

  const removeOne = useMutation({
    mutationFn: (id: string) => circuitsApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["circuits"] }),
  });

  function toggle(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (allChecked) setSelectedIds(new Set());
    else setSelectedIds(new Set(items.map((c) => c.id)));
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold">WAN circuits</h1>
            <p className="text-sm text-muted-foreground">
              Carrier-supplied transport pipes — provider, class, bandwidth,
              endpoints, contract term + cost. Foundation for the future MPLS
              service catalog and SD-WAN overlay routing roadmap items.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <SavedViewsMenu
              page="network.circuits"
              currentPayload={viewPayload}
              onApply={applyView}
            />
            <HeaderButton
              icon={RefreshCw}
              onClick={() => query.refetch()}
              iconClassName={query.isFetching ? "animate-spin" : undefined}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowNew(true)}
              {...writeGate}
            >
              New circuit
            </HeaderButton>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            className={cn(inputCls, "max-w-xs")}
            placeholder="Search name / circuit ID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className={cn(inputCls, "max-w-[180px]")}
            value={statusFilter}
            onChange={(e) =>
              setStatusFilter(e.target.value as CircuitStatus | "")
            }
          >
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            className={cn(inputCls, "max-w-[200px]")}
            value={transportFilter}
            onChange={(e) =>
              setTransportFilter(e.target.value as TransportClass | "")
            }
          >
            <option value="">All transport</option>
            {TRANSPORT_CLASSES.map((t) => (
              <option key={t} value={t}>
                {TRANSPORT_LABELS[t]}
              </option>
            ))}
          </select>
          <select
            className={cn(inputCls, "max-w-[200px]")}
            value={providerFilter}
            onChange={(e) => setProviderFilter(e.target.value)}
          >
            <option value="">All providers</option>
            {(providersQ.data?.items ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>

        <TagFilterChips
          value={tagFilters}
          onChange={setTagFilters}
          placeholder="Filter by tag — try env or env:prod…"
        />

        {selectedIds.size > 0 && (
          <div className="flex items-center justify-between rounded-md border bg-muted/50 px-3 py-2 text-sm">
            <span>{selectedIds.size} selected</span>
            <HeaderButton
              variant="destructive"
              icon={Trash2}
              disabled={bulkDelete.isPending}
              onClick={() => {
                const ids = Array.from(selectedIds);
                setConfirm({
                  title: "Delete circuits",
                  message: `Delete ${ids.length} circuit${ids.length === 1 ? "" : "s"}?`,
                  confirmLabel: "Delete",
                  onConfirm: () => bulkDelete.mutate(ids),
                });
              }}
              {...deleteGate}
            >
              Delete selected
            </HeaderButton>
          </div>
        )}

        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-8 px-3 py-2">
                  <input
                    type="checkbox"
                    checked={allChecked}
                    onChange={toggleAll}
                    aria-label="Select all"
                  />
                </th>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">Carrier ID</th>
                <th className="px-3 py-2 text-left">Provider</th>
                <th className="px-3 py-2 text-left">Customer</th>
                <th className="px-3 py-2 text-left">Transport</th>
                <th className="px-3 py-2 text-left">Bandwidth</th>
                <th className="px-3 py-2 text-left">A-end</th>
                <th className="px-3 py-2 text-left">Z-end</th>
                <th className="px-3 py-2 text-left">Term ends</th>
                <th className="px-3 py-2 text-left">Monthly</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="w-24 px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {query.isLoading && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={13}
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!query.isLoading && items.length === 0 && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={13}
                  >
                    <ListEmpty
                      error={query.error}
                      what="circuits"
                      filtered={
                        search !== "" ||
                        statusFilter !== "" ||
                        transportFilter !== "" ||
                        providerFilter !== "" ||
                        tagFilters.length > 0
                      }
                      onClearFilters={() => {
                        setSearch("");
                        setStatusFilter("");
                        setTransportFilter("");
                        setProviderFilter("");
                        setTagFilters([]);
                      }}
                    >
                      No circuits yet — click "New circuit" to add one.
                    </ListEmpty>
                  </td>
                </tr>
              )}
              {items.map((c) => (
                <tr key={c.id} className="border-t">
                  <td className="px-3 py-2 align-top">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(c.id)}
                      onChange={() => toggle(c.id)}
                    />
                  </td>
                  <td className="px-3 py-2 align-top break-words font-medium">
                    {c.name}
                  </td>
                  <td className="px-3 py-2 align-top break-all text-muted-foreground tabular-nums">
                    {c.ckt_id ?? "—"}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <ProviderChip providerId={c.provider_id} />
                  </td>
                  <td className="px-3 py-2 align-top">
                    {c.customer_id ? (
                      <CustomerChip customerId={c.customer_id} />
                    ) : (
                      <span className="text-muted-foreground/50">—</span>
                    )}
                  </td>
                  <td
                    className="px-3 py-2 align-top text-muted-foreground"
                    title={TRANSPORT_LABELS[c.transport_class]}
                  >
                    {TRANSPORT_LABELS_SHORT[c.transport_class]}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                    {c.bandwidth_mbps_down === c.bandwidth_mbps_up
                      ? fmtBandwidth(c.bandwidth_mbps_down)
                      : `${fmtBandwidth(c.bandwidth_mbps_down)} ↓ / ${fmtBandwidth(c.bandwidth_mbps_up)} ↑`}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <SiteChip siteId={c.a_end_site_id} />
                  </td>
                  <td className="px-3 py-2 align-top">
                    <SiteChip siteId={c.z_end_site_id} />
                  </td>
                  <td className="px-3 py-2 align-top">
                    <TermBadge termEnd={c.term_end_date} />
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                    {formatCost(c.monthly_cost, c.currency)}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <StatusBadge status={c.status} />
                  </td>
                  <td className="px-3 py-2 align-top text-right">
                    <ServicesUsingButton
                      kind="circuit"
                      resourceId={c.id}
                      label={c.name}
                      compact
                    />
                    <button
                      type="button"
                      title="Edit"
                      onClick={() => setEditing(c)}
                      className="ml-1 rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                      {...writeGate}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      title="Delete"
                      onClick={() => {
                        setConfirm({
                          title: "Delete circuit",
                          message: `Delete circuit "${c.name}"?`,
                          confirmLabel: "Delete",
                          onConfirm: () => removeOne.mutate(c.id),
                        });
                      }}
                      className="ml-1 rounded p-1 text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"
                      {...deleteGate}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {showNew && (
          <CircuitEditorModal
            existing={null}
            onClose={() => setShowNew(false)}
          />
        )}
        {editing && (
          <CircuitEditorModal
            existing={editing}
            onClose={() => setEditing(null)}
          />
        )}
        <ConfirmModal
          open={confirm !== null}
          title={confirm?.title ?? ""}
          message={confirm?.message ?? ""}
          confirmLabel={confirm?.confirmLabel}
          tone="destructive"
          onConfirm={() => {
            confirm?.onConfirm();
            setConfirm(null);
          }}
          onClose={() => setConfirm(null)}
        />
      </div>
    </div>
  );
}
