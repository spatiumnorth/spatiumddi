import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  customersApi,
  overlaysApi,
  type OverlayCreate,
  type OverlayKind,
  type OverlayPathStrategy,
  type OverlayRead,
  type OverlayStatus,
  type OverlayUpdate,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { TagFilterChips } from "@/components/TagFilterChips";
import { CustomerChip } from "@/components/ownership/pickers";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const KINDS: OverlayKind[] = [
  "sdwan",
  "ipsec_mesh",
  "wireguard_mesh",
  "dmvpn",
  "vxlan_evpn",
  "gre_mesh",
];
const KIND_LABELS: Record<OverlayKind, string> = {
  sdwan: "SD-WAN (vendor)",
  ipsec_mesh: "IPsec mesh",
  wireguard_mesh: "WireGuard mesh",
  dmvpn: "DMVPN",
  vxlan_evpn: "VXLAN-EVPN",
  gre_mesh: "GRE mesh",
};

const STATUSES: OverlayStatus[] = ["active", "building", "suspended", "decom"];

const STRATEGIES: OverlayPathStrategy[] = [
  "active_active",
  "active_backup",
  "load_balance",
  "app_aware",
];
const STRATEGY_LABELS: Record<OverlayPathStrategy, string> = {
  active_active: "Active / Active",
  active_backup: "Active / Backup",
  load_balance: "Load balance",
  app_aware: "App-aware",
};

// Curated vendor list — operators can type a free-form value too. The
// dropdown's first entry is the empty-string sentinel so "no vendor"
// is a valid choice.
const CURATED_VENDORS = [
  "cisco_viptela",
  "cisco_meraki",
  "fortinet",
  "velocloud",
  "versa",
  "cato",
  "aryaka",
  "silver_peak",
  "open_source",
];

function StatusBadge({ status }: { status: OverlayStatus }) {
  const styles: Record<OverlayStatus, string> = {
    active:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    building: "bg-sky-100 text-sky-700 dark:bg-sky-950/30 dark:text-sky-400",
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

function KindBadge({ kind }: { kind: OverlayKind }) {
  const styles: Record<OverlayKind, string> = {
    sdwan:
      "bg-violet-100 text-violet-700 dark:bg-violet-950/30 dark:text-violet-300",
    ipsec_mesh:
      "bg-indigo-100 text-indigo-700 dark:bg-indigo-950/30 dark:text-indigo-300",
    wireguard_mesh:
      "bg-cyan-100 text-cyan-700 dark:bg-cyan-950/30 dark:text-cyan-300",
    dmvpn: "bg-blue-100 text-blue-700 dark:bg-blue-950/30 dark:text-blue-300",
    vxlan_evpn:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-300",
    gre_mesh: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium",
        styles[kind],
      )}
    >
      {KIND_LABELS[kind]}
    </span>
  );
}

// ── Editor modal ───────────────────────────────────────────────────

function OverlayEditorModal({
  existing,
  onClose,
}: {
  existing: OverlayRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState<OverlayKind>(existing?.kind ?? "sdwan");
  const [customerId, setCustomerId] = useState<string | null>(
    existing?.customer_id ?? null,
  );
  const [vendor, setVendor] = useState(existing?.vendor ?? "");
  const [encryptionProfile, setEncryptionProfile] = useState(
    existing?.encryption_profile ?? "",
  );
  const [strategy, setStrategy] = useState<OverlayPathStrategy>(
    existing?.default_path_strategy ?? "active_backup",
  );
  const [status, setStatus] = useState<OverlayStatus>(
    existing?.status ?? "building",
  );
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const customers = customersQ.data?.items ?? [];

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      const body: OverlayCreate | OverlayUpdate = {
        name,
        kind,
        customer_id: customerId,
        vendor: vendor || null,
        encryption_profile: encryptionProfile || null,
        default_path_strategy: strategy,
        status,
        notes,
      };
      if (existing) return overlaysApi.update(existing.id, body);
      return overlaysApi.create(body as OverlayCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["overlays"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string } };
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Save failed");
    },
  });

  return (
    <Modal
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New overlay"}
      wide
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Acme Corp Global Overlay"
            autoFocus={!existing}
          />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Kind
          </label>
          <select
            className={inputCls}
            value={kind}
            onChange={(e) => setKind(e.target.value as OverlayKind)}
          >
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_LABELS[k]}
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
            Vendor
          </label>
          <input
            className={inputCls}
            value={vendor}
            onChange={(e) => setVendor(e.target.value)}
            list="overlay-vendor-list"
            placeholder="cisco_meraki, fortinet, …"
          />
          <datalist id="overlay-vendor-list">
            {CURATED_VENDORS.map((v) => (
              <option key={v} value={v} />
            ))}
          </datalist>
          <p className="mt-0.5 text-[11px] text-muted-foreground/80">
            Free-form. Curated suggestions in the dropdown; type a custom vendor
            name if yours isn't listed.
          </p>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Default path strategy
          </label>
          <select
            className={inputCls}
            value={strategy}
            onChange={(e) => setStrategy(e.target.value as OverlayPathStrategy)}
          >
            {STRATEGIES.map((s) => (
              <option key={s} value={s}>
                {STRATEGY_LABELS[s]}
              </option>
            ))}
          </select>
          <p className="mt-0.5 text-[11px] text-muted-foreground/80">
            Falls back to this when no routing policy matches.
          </p>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground">
            Status
          </label>
          <select
            className={inputCls}
            value={status}
            onChange={(e) => setStatus(e.target.value as OverlayStatus)}
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="sm:col-span-2">
          <label className="text-xs font-medium text-muted-foreground">
            Encryption profile
          </label>
          <input
            className={inputCls}
            value={encryptionProfile}
            onChange={(e) => setEncryptionProfile(e.target.value)}
            placeholder="e.g. aes-256-gcm-x509 / chacha20-poly1305-psk"
          />
          <p className="mt-0.5 text-[11px] text-muted-foreground/80">
            Free-form descriptor. Operators self-curate.
          </p>
        </div>
        <div className="sm:col-span-2">
          <label className="text-xs font-medium text-muted-foreground">
            Notes
          </label>
          <textarea
            className={cn(inputCls, "min-h-[80px]")}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>
      </div>

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

// ── Page ───────────────────────────────────────────────────────────

export function OverlaysPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the overlay_network router asks write (delete) on 'overlay_network'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "overlay_network"),
    "Requires write permission on overlay networks",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "overlay_network"),
    "Requires delete permission on overlay networks",
  );
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<OverlayStatus | "">("");
  const [kindFilter, setKindFilter] = useState<OverlayKind | "">("");
  const [customerFilter, setCustomerFilter] = useState("");
  const [editing, setEditing] = useState<OverlayRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [tagFilters, setTagFilters] = useState<string[]>([]);

  const customersQ = useQuery({
    queryKey: ["customers", "all"],
    queryFn: () => customersApi.list({ limit: 500 }),
    staleTime: 60_000,
  });

  const query = useQuery({
    queryKey: [
      "overlays",
      search,
      statusFilter,
      kindFilter,
      customerFilter,
      tagFilters,
    ],
    queryFn: () =>
      overlaysApi.list({
        limit: 500,
        search: search || undefined,
        status: (statusFilter || undefined) as OverlayStatus | undefined,
        kind: (kindFilter || undefined) as OverlayKind | undefined,
        customer_id: customerFilter || undefined,
        tag: tagFilters.length > 0 ? tagFilters : undefined,
      }),
  });

  const items = query.data?.items ?? [];

  const allChecked = useMemo(
    () => items.length > 0 && items.every((s) => selectedIds.has(s.id)),
    [items, selectedIds],
  );

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => overlaysApi.bulkDelete(ids),
    onSuccess: () => {
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["overlays"] });
    },
  });

  const removeOne = useMutation({
    mutationFn: (id: string) => overlaysApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["overlays"] }),
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
    else setSelectedIds(new Set(items.map((s) => s.id)));
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold">SD-WAN overlays</h1>
            <p className="text-sm text-muted-foreground">
              Logical overlay networks layered over heterogeneous underlay
              transports — vendor SD-WAN, IPsec / WireGuard / GRE meshes, DMVPN,
              VXLAN-EVPN. SpatiumDDI is the vendor-neutral source of truth for
              topology and routing-policy intent; vendor config push and live
              telemetry stay out of scope.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
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
              New overlay
            </HeaderButton>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            className={cn(inputCls, "max-w-xs")}
            placeholder="Search name…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className={cn(inputCls, "max-w-[200px]")}
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value as OverlayKind | "")}
          >
            <option value="">All kinds</option>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_LABELS[k]}
              </option>
            ))}
          </select>
          <select
            className={cn(inputCls, "max-w-[180px]")}
            value={statusFilter}
            onChange={(e) =>
              setStatusFilter(e.target.value as OverlayStatus | "")
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
            value={customerFilter}
            onChange={(e) => setCustomerFilter(e.target.value)}
          >
            <option value="">All customers</option>
            {(customersQ.data?.items ?? []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
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
                  title: "Delete overlays",
                  message: `Delete ${ids.length} overlay${ids.length === 1 ? "" : "s"}?`,
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
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-left">Customer</th>
                <th className="px-3 py-2 text-left">Vendor</th>
                <th className="px-3 py-2 text-left">Strategy</th>
                <th className="px-3 py-2 text-left">Sites</th>
                <th className="px-3 py-2 text-left">Policies</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="w-24 px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {query.isLoading && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={10}
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!query.isLoading && items.length === 0 && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={10}
                  >
                    <ListEmpty
                      error={query.error}
                      what="overlays"
                      filtered={
                        search !== "" ||
                        statusFilter !== "" ||
                        kindFilter !== "" ||
                        customerFilter !== "" ||
                        tagFilters.length > 0
                      }
                      onClearFilters={() => {
                        setSearch("");
                        setStatusFilter("");
                        setKindFilter("");
                        setCustomerFilter("");
                        setTagFilters([]);
                      }}
                    >
                      No overlays yet — click "New overlay" to add one.
                    </ListEmpty>
                  </td>
                </tr>
              )}
              {items.map((o) => (
                <tr key={o.id} className="border-t">
                  <td className="px-3 py-2 align-top">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(o.id)}
                      onChange={() => toggle(o.id)}
                    />
                  </td>
                  <td className="px-3 py-2 align-top break-words">
                    <Link
                      to={`/network/overlays/${o.id}`}
                      className="font-medium hover:underline"
                    >
                      {o.name}
                    </Link>
                  </td>
                  <td className="px-3 py-2 align-top">
                    <KindBadge kind={o.kind} />
                  </td>
                  <td className="px-3 py-2 align-top">
                    {o.customer_id ? (
                      <CustomerChip customerId={o.customer_id} />
                    ) : (
                      <span className="text-muted-foreground/50">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground">
                    {o.vendor ?? "—"}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground">
                    {STRATEGY_LABELS[o.default_path_strategy]}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                    {o.site_count}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                    {o.policy_count}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <StatusBadge status={o.status} />
                  </td>
                  <td className="px-3 py-2 align-top text-right">
                    <button
                      type="button"
                      title="Edit"
                      onClick={() => setEditing(o)}
                      className="rounded p-1 hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                      {...writeGate}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      title="Delete"
                      onClick={() => {
                        setConfirm({
                          title: "Delete overlay",
                          message: `Delete overlay "${o.name}"?`,
                          confirmLabel: "Delete",
                          onConfirm: () => removeOne.mutate(o.id),
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
          <OverlayEditorModal
            existing={null}
            onClose={() => setShowNew(false)}
          />
        )}
        {editing && (
          <OverlayEditorModal
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
