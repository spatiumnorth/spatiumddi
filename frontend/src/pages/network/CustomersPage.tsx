import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  customersApi,
  type CustomerCreate,
  type CustomerRead,
  type CustomerStatus,
  type CustomerUpdate,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const STATUSES: CustomerStatus[] = ["active", "inactive", "decommissioning"];

function StatusBadge({ status }: { status: CustomerStatus }) {
  const styles: Record<CustomerStatus, string> = {
    active:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    inactive: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    decommissioning:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
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

function CustomerEditorModal({
  existing,
  onClose,
}: {
  existing: CustomerRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [accountNumber, setAccountNumber] = useState(
    existing?.account_number ?? "",
  );
  const [email, setEmail] = useState(existing?.contact_email ?? "");
  const [phone, setPhone] = useState(existing?.contact_phone ?? "");
  const [address, setAddress] = useState(existing?.contact_address ?? "");
  const [status, setStatus] = useState<CustomerStatus>(
    existing?.status ?? "active",
  );
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      if (existing) {
        const body: CustomerUpdate = {
          name,
          account_number: accountNumber || null,
          contact_email: email || null,
          contact_phone: phone || null,
          contact_address: address || null,
          status,
          notes,
        };
        return customersApi.update(existing.id, body);
      }
      const body: CustomerCreate = {
        name,
        account_number: accountNumber || null,
        contact_email: email || null,
        contact_phone: phone || null,
        contact_address: address || null,
        status,
        notes,
      };
      return customersApi.create(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["customers"] });
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
      title={existing ? "Edit customer" : "New customer"}
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
              placeholder="Acme Corp"
            />
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
              Status
            </label>
            <select
              className={inputCls}
              value={status}
              onChange={(e) => setStatus(e.target.value as CustomerStatus)}
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Contact email
            </label>
            <input
              className={inputCls}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="ops@acme.example"
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
              placeholder="+1 555 123 4567"
            />
          </div>
          <div className="space-y-1 sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Address
            </label>
            <textarea
              className={cn(inputCls, "min-h-[60px]")}
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="optional"
            />
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

export function CustomersPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the customer router asks write (delete) on 'customer'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "customer"),
    "Requires write permission on customers",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "customer"),
    "Requires delete permission on customers",
  );
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<CustomerStatus | "">("");
  const [editing, setEditing] = useState<CustomerRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const query = useQuery({
    queryKey: ["customers", search, statusFilter],
    queryFn: () =>
      customersApi.list({
        limit: 500,
        search: search || undefined,
        status: (statusFilter || undefined) as CustomerStatus | undefined,
      }),
  });

  const items = query.data?.items ?? [];

  const allChecked = useMemo(
    () => items.length > 0 && items.every((c) => selectedIds.has(c.id)),
    [items, selectedIds],
  );

  const bulkDelete = useMutation({
    mutationFn: (ids: string[]) => customersApi.bulkDelete(ids),
    onSuccess: () => {
      setSelectedIds(new Set());
      qc.invalidateQueries({ queryKey: ["customers"] });
    },
  });

  const removeOne = useMutation({
    mutationFn: (id: string) => customersApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["customers"] });
    },
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
            <h1 className="text-xl font-semibold">Customers</h1>
            <p className="text-sm text-muted-foreground">
              Logical owners of network resources. Tag subnets, blocks, VRFs,
              DNS zones, and ASNs to group them by who owns the IP space.
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
              New customer
            </HeaderButton>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            className={cn(inputCls, "max-w-xs")}
            placeholder="Search name / account / email…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className={cn(inputCls, "max-w-[180px]")}
            value={statusFilter}
            onChange={(e) =>
              setStatusFilter(e.target.value as CustomerStatus | "")
            }
          >
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
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
                  title: "Delete customers",
                  message: `Soft-delete ${ids.length} customer${ids.length === 1 ? "" : "s"}? Subnets, zones and ASNs that name them are not changed and keep pointing at the hidden customer.`,
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
                <th className="px-3 py-2 text-left">Account</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Contact</th>
                <th className="w-24 px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {query.isLoading && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={6}
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!query.isLoading && items.length === 0 && (
                <tr>
                  <td
                    className="px-3 py-6 text-center text-muted-foreground"
                    colSpan={6}
                  >
                    No customers yet — click "New customer" to add one.
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
                  <td className="px-3 py-2 align-top break-all text-muted-foreground">
                    {c.account_number ?? "—"}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <StatusBadge status={c.status} />
                  </td>
                  <td className="px-3 py-2 align-top break-all text-muted-foreground">
                    {c.contact_email ?? c.contact_phone ?? "—"}
                  </td>
                  <td className="px-3 py-2 align-top text-right">
                    <button
                      type="button"
                      title="Edit"
                      onClick={() => setEditing(c)}
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
                          title: "Delete customer",
                          message: `Soft-delete customer "${c.name}"? Anything that names it is not changed and keeps pointing at the hidden customer.`,
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
          <CustomerEditorModal
            existing={null}
            onClose={() => setShowNew(false)}
          />
        )}
        {editing && (
          <CustomerEditorModal
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
