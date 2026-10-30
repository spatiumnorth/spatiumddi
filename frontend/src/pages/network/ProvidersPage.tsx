import { ListEmpty } from "@/components/ui/list-read-error";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  asnsApi,
  formatApiError,
  providersApi,
  type ProviderCreate,
  type ProviderKind,
  type ProviderRead,
  type ProviderUpdate,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const KINDS: ProviderKind[] = [
  "transit",
  "peering",
  "carrier",
  "cloud",
  "registrar",
  "sdwan_vendor",
];

const KIND_LABELS: Record<ProviderKind, string> = {
  transit: "Transit",
  peering: "Peering",
  carrier: "Carrier",
  cloud: "Cloud",
  registrar: "Registrar",
  sdwan_vendor: "SD-WAN vendor",
};

function ProviderEditorModal({
  existing,
  onClose,
}: {
  existing: ProviderRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState<ProviderKind>(existing?.kind ?? "transit");
  const [accountNumber, setAccountNumber] = useState(
    existing?.account_number ?? "",
  );
  const [email, setEmail] = useState(existing?.contact_email ?? "");
  const [phone, setPhone] = useState(existing?.contact_phone ?? "");
  const [defaultAsnId, setDefaultAsnId] = useState(
    existing?.default_asn_id ?? "",
  );
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  // The ASN routes take read on `manage_asns`. A user without it is not
  // asked, and a stored Default ASN is shown as set-but-hidden, never as
  // none (#2703).
  const canReadAsns = usePermissions().can("read", "manage_asns");
  const asnsQuery = useQuery({
    queryKey: ["asns", "all"],
    queryFn: () => asnsApi.list({ limit: 500 }),
    enabled: canReadAsns,
  });

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      if (existing) {
        const body: ProviderUpdate = {
          name,
          kind,
          account_number: accountNumber || null,
          contact_email: email || null,
          contact_phone: phone || null,
          default_asn_id: defaultAsnId || null,
          notes,
        };
        return providersApi.update(existing.id, body);
      }
      const body: ProviderCreate = {
        name,
        kind,
        account_number: accountNumber || null,
        contact_email: email || null,
        contact_phone: phone || null,
        default_asn_id: defaultAsnId || null,
        notes,
      };
      return providersApi.create(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providers"] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  return (
    <Modal
      onClose={onClose}
      title={existing ? "Edit provider" : "New provider"}
      wide
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1 sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Name
            </label>
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus={!existing}
              placeholder="Cogent / Cloudflare / GoDaddy / …"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Kind
            </label>
            <select
              className={inputCls}
              value={kind}
              onChange={(e) => setKind(e.target.value as ProviderKind)}
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Account number
            </label>
            <input
              className={inputCls}
              value={accountNumber}
              onChange={(e) => setAccountNumber(e.target.value)}
              placeholder="optional"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Contact email
            </label>
            <input
              className={inputCls}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Contact phone
            </label>
            <input
              className={inputCls}
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
            />
          </div>
          <div className="space-y-1 sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Default ASN
            </label>
            <select
              className={inputCls}
              value={defaultAsnId}
              onChange={(e) => setDefaultAsnId(e.target.value)}
              disabled={asnsQuery.isLoading || !canReadAsns}
              title={
                canReadAsns ? undefined : "You may not read ASNs (manage_asns)"
              }
            >
              <option value="">— none —</option>
              {!canReadAsns && defaultAsnId && (
                <option value={defaultAsnId}>
                  set — you may not read ASNs
                </option>
              )}
              {(asnsQuery.data?.items ?? []).map((a) => (
                <option key={a.id} value={a.id}>
                  AS{a.number}
                  {a.name ? ` — ${a.name}` : ""}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-muted-foreground/80">
              Optional FK to the provider's main BGP AS for peering /
              attribution.
            </p>
          </div>
          <div className="space-y-1 sm:col-span-2">
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
        {error && <p className="text-sm text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
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
      </div>
    </Modal>
  );
}

export function ProvidersPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the provider router asks write (delete) on 'provider'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "provider"),
    "Requires write permission on providers",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "provider"),
    "Requires delete permission on providers",
  );
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState<ProviderKind | "">("");
  const [editing, setEditing] = useState<ProviderRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const query = useQuery({
    queryKey: ["providers", search, kindFilter],
    queryFn: () =>
      providersApi.list({
        limit: 500,
        search: search || undefined,
        kind: (kindFilter || undefined) as ProviderKind | undefined,
      }),
  });

  // The ASN routes take read on `manage_asns`. A user without it is not
  // asked, and a stored Default ASN is shown as set-but-hidden, never as
  // none (#2703).
  const canReadAsns = usePermissions().can("read", "manage_asns");
  const asnsQuery = useQuery({
    queryKey: ["asns", "all"],
    queryFn: () => asnsApi.list({ limit: 500 }),
    enabled: canReadAsns,
  });

  const items = query.data?.items ?? [];

  const asnByNumber = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of asnsQuery.data?.items ?? []) m.set(a.id, a.number);
    return m;
  }, [asnsQuery.data]);

  const allChecked = useMemo(
    () => items.length > 0 && items.every((c) => selectedIds.has(c.id)),
    [items, selectedIds],
  );

  // #2707 — a refused delete (409 while circuits reference the provider, 403)
  // used to close the confirm and say nothing.
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => providersApi.bulkDelete(ids),
    onMutate: () => setDeleteError(null),
    onSuccess: () => {
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
    onError: (e: unknown) =>
      setDeleteError(formatApiError(e, "Failed to delete providers")),
  });

  const removeOne = useMutation({
    mutationFn: (id: string) => providersApi.remove(id),
    onMutate: () => setDeleteError(null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
    onError: (e: unknown) =>
      setDeleteError(formatApiError(e, "Failed to delete provider")),
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
    if (allChecked) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map((c) => c.id)));
    }
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-semibold">Providers</h1>
            <p className="text-sm text-muted-foreground">
              External organisations supplying network capacity, cloud regions,
              domain registrations, or SD-WAN services. Tag ASNs and Domains to
              make "what does Cogent supply us?" a one-click filter.
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
              New provider
            </HeaderButton>
          </div>
        </div>

        {deleteError && (
          <p role="alert" className="text-sm text-destructive">
            {deleteError}
          </p>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <input
            className={cn(inputCls, "max-w-xs")}
            placeholder="Search name / account / email…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className={cn(inputCls, "max-w-[180px]")}
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value as ProviderKind | "")}
          >
            <option value="">All kinds</option>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_LABELS[k]}
              </option>
            ))}
          </select>
        </div>

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
                  title: "Delete providers",
                  message: `Delete ${ids.length} provider${ids.length === 1 ? "" : "s"}?`,
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
                <th className="px-3 py-2 text-left">Account</th>
                <th className="px-3 py-2 text-left">Default ASN</th>
                <th className="px-3 py-2 text-left">Contact</th>
                <th className="w-24 px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {query.isLoading && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={7}
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!query.isLoading && items.length === 0 && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={7}
                  >
                    <ListEmpty
                      error={query.error}
                      what="providers"
                      filtered={search !== "" || kindFilter !== ""}
                      onClearFilters={() => {
                        setSearch("");
                        setKindFilter("");
                      }}
                    >
                      No providers yet — click "New provider" to add one.
                    </ListEmpty>
                  </td>
                </tr>
              )}
              {items.map((p) => {
                const asnNum = p.default_asn_id
                  ? asnByNumber.get(p.default_asn_id)
                  : undefined;
                return (
                  <tr key={p.id} className="border-t">
                    <td className="px-3 py-2 align-top">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(p.id)}
                        onChange={() => toggle(p.id)}
                      />
                    </td>
                    <td className="px-3 py-2 align-top break-words font-medium">
                      {p.name}
                    </td>
                    <td className="px-3 py-2 align-top text-muted-foreground">
                      {KIND_LABELS[p.kind]}
                    </td>
                    <td className="px-3 py-2 align-top break-all text-muted-foreground">
                      {p.account_number ?? "—"}
                    </td>
                    <td className="px-3 py-2 align-top text-muted-foreground tabular-nums">
                      {asnNum !== undefined ? (
                        `AS${asnNum}`
                      ) : p.default_asn_id && !canReadAsns ? (
                        <span title="You may not read ASNs (manage_asns)">
                          set, hidden
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="px-3 py-2 align-top break-all text-muted-foreground">
                      {p.contact_email ?? p.contact_phone ?? "—"}
                    </td>
                    <td className="px-3 py-2 align-top text-right">
                      <button
                        type="button"
                        title="Edit"
                        onClick={() => setEditing(p)}
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
                            title: "Delete provider",
                            message: `Delete provider "${p.name}"?`,
                            confirmLabel: "Delete",
                            onConfirm: () => removeOne.mutate(p.id),
                          });
                        }}
                        className="ml-1 rounded p-1 text-destructive hover:bg-destructive/10 disabled:cursor-not-allowed disabled:opacity-50"
                        {...deleteGate}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {showNew && (
          <ProviderEditorModal
            existing={null}
            onClose={() => setShowNew(false)}
          />
        )}
        {editing && (
          <ProviderEditorModal
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
