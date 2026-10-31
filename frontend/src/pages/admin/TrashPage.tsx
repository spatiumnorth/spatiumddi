import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronLeft,
  ChevronRight,
  RotateCcw,
  Search,
  Trash2,
} from "lucide-react";
import {
  formatApiError,
  trashApi,
  type TrashEntry,
  type TrashEntryType,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ListReadError } from "@/components/ui/list-read-error";

const TYPE_LABELS: Record<TrashEntryType, string> = {
  ip_space: "IP Space",
  ip_block: "IP Block",
  subnet: "Subnet",
  dns_zone: "DNS Zone",
  dns_record: "DNS Record",
  dhcp_scope: "DHCP Scope",
  customer: "Customer",
  overlay_network: "Overlay",
  network_service: "Service",
};

const TYPE_BADGE: Record<TrashEntryType, string> = {
  ip_space: "bg-indigo-500/15 text-indigo-700 dark:text-indigo-300",
  ip_block: "bg-blue-500/15 text-blue-700 dark:text-blue-300",
  subnet: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-300",
  dns_zone: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  dns_record: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  dhcp_scope: "bg-amber-500/15 text-amber-700 dark:text-amber-300",
  customer: "bg-violet-500/15 text-violet-700 dark:text-violet-300",
  overlay_network: "bg-fuchsia-500/15 text-fuchsia-700 dark:text-fuchsia-300",
  network_service: "bg-rose-500/15 text-rose-700 dark:text-rose-300",
};

const PAGE_SIZE = 100;

function formatTs(ts: string) {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function ConfirmRestoreModal({
  entry,
  onClose,
}: {
  entry: TrashEntry;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  // Set after a 409: the batch holds rows that clash with live ones. The
  // operator can then restore the others and leave the clashing rows behind.
  //
  // Only offered when the SERVER says it will accept it (#1960). A bulk record
  // delete (#963) stamps N independent siblings under one id, so leaving one
  // behind is sound; every other batch is a cascade (a zone AND its records,
  // a scope AND its pools) where a partial restore can bring a child back
  // without its parent, and the server refuses it with a 422. A record row of a
  // deleted zone's batch is a dns_record too, so the clicked row's type cannot
  // tell the two apart: the 409 carries `skip_conflicts_allowed` instead.
  const [canSkipConflicts, setCanSkipConflicts] = useState(false);
  // Set after a 409 whose clash is a parent still in the Trash (#1957): the
  // server names that parent's Trash row, so the dialog can restore it and then
  // this row in one click instead of sending the operator to find it (it may
  // well be on another page of the list).
  const [blocker, setBlocker] = useState<{
    type: TrashEntryType;
    id: string;
    display: string;
  } | null>(null);

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["trash"] });
    qc.invalidateQueries({ queryKey: ["ipam"] });
    qc.invalidateQueries({ queryKey: ["dns"] });
    qc.invalidateQueries({ queryKey: ["dhcp"] });
  };

  const showError = (err: unknown) => {
    const detail = (err as { response?: { data?: { detail?: unknown } } })
      ?.response?.data?.detail;
    setBlocker(null);
    setCanSkipConflicts(false);
    if (detail && typeof detail === "object" && "conflicts" in detail) {
      const conflicts = (
        detail as {
          conflicts: Array<{
            display: string;
            reason: string;
            parent_type?: TrashEntryType | null;
            parent_id?: string | null;
            parent_display?: string | null;
          }>;
        }
      ).conflicts;
      const allowed = (detail as { skip_conflicts_allowed?: boolean })
        .skip_conflicts_allowed;
      setError(
        `Cannot restore: ${conflicts
          .map((c) => `${c.display} — ${c.reason}`)
          .join("; ")}`,
      );
      setCanSkipConflicts(
        allowed === true && entry.batch_size > conflicts.length,
      );
      const withParent = conflicts.find((c) => c.parent_type && c.parent_id);
      if (withParent?.parent_type && withParent.parent_id) {
        setBlocker({
          type: withParent.parent_type,
          id: withParent.parent_id,
          display: withParent.parent_display ?? withParent.parent_id,
        });
      }
    } else if (typeof detail === "string") {
      setError(detail);
    } else {
      setError("Restore failed");
    }
  };

  const mut = useMutation({
    mutationFn: (skipConflicts: boolean) =>
      trashApi.restore(entry.type, entry.id, { skipConflicts }),
    onSuccess: () => {
      invalidate();
      onClose();
    },
    onError: showError,
  });

  // Restore the blocking parent, then retry this row. A parent with a trashed
  // parent of its own answers 409 the same way, and the dialog offers that one.
  const parentMut = useMutation({
    mutationFn: (p: { type: TrashEntryType; id: string }) =>
      trashApi.restore(p.type, p.id),
    onSuccess: () => {
      invalidate();
      setError(null);
      setBlocker(null);
      mut.mutate(false);
    },
    onError: showError,
  });
  const pending = mut.isPending || parentMut.isPending;

  return (
    <Modal title="Restore from trash?" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm">
          Restore{" "}
          <span className="font-mono font-medium">{entry.name_or_cidr}</span> (
          {TYPE_LABELS[entry.type]})
          {entry.batch_size > 1
            ? ` and the ${entry.batch_size - 1} other row${entry.batch_size - 1 === 1 ? "" : "s"} deleted with it`
            : ""}
          ?
        </p>
        {error && (
          <p className="rounded bg-red-500/15 p-2 text-xs text-red-700 dark:text-red-300">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm"
          >
            Cancel
          </button>
          {blocker && (
            <button
              onClick={() => {
                setError(null);
                parentMut.mutate({ type: blocker.type, id: blocker.id });
              }}
              disabled={pending}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
              title="Restore the parent from the Trash (with the rows deleted with it), then this row"
            >
              Restore {blocker.display} first
            </button>
          )}
          {canSkipConflicts && (
            <button
              onClick={() => {
                setError(null);
                mut.mutate(true);
              }}
              disabled={pending}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
              title="Restore every row in the batch except the ones that clash with a live row"
            >
              Restore the others
            </button>
          )}
          <button
            onClick={() => {
              setError(null);
              mut.mutate(false);
            }}
            disabled={pending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {pending ? "Restoring…" : "Restore"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// What a permanent delete takes with the row, beyond the row itself. These are
// the rows its foreign keys cascade to, most of which the Trash does not list.
// It names no count of "other rows deleted with it": the purge takes this
// row's own subtree, never the rest of its deletion batch (its parent block,
// its siblings), so a batch count named rows that stay (#2736).
function purgeScope(entry: TrashEntry): string {
  switch (entry.type) {
    case "subnet":
      return ` Its DHCP scopes (with their pools and static assignments), its addresses and the DNS records published for them are removed with it.`;
    case "dns_zone":
      return ` All of its DNS records and its DNS pools are removed with it.`;
    case "dhcp_scope":
      return ` Its pools and static assignments are removed with it.`;
    case "customer":
      return ` Subnets, zones, overlays and other rows that name it are left with no customer. A customer that a service still names cannot be purged until that service is gone.`;
    default:
      return "";
  }
}

function ConfirmPermanentDeleteModal({
  entry,
  onClose,
}: {
  entry: TrashEntry;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: () => trashApi.permanentDelete(entry.type, entry.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["trash"] });
      onClose();
    },
    onError: (err: unknown) => {
      setError(formatApiError(err, "Permanent delete failed"));
    },
  });

  return (
    <Modal title="Permanently delete?" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm">
          This permanently removes{" "}
          <span className="font-mono font-medium">{entry.name_or_cidr}</span> (
          {TYPE_LABELS[entry.type]}).
          {entry.type === "ip_block" || entry.type === "ip_space"
            ? " The subnets and blocks in the Trash under it, with their addresses, DHCP scopes and DNS records, are removed with it."
            : ""}
          {purgeScope(entry)} It cannot be restored.
        </p>
        {error && (
          <p className="rounded bg-red-500/15 p-2 text-xs text-red-700 dark:text-red-300">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              setError(null);
              mut.mutate();
            }}
            disabled={mut.isPending}
            className="rounded-md bg-red-600 px-3 py-1.5 text-sm text-white hover:bg-red-700 disabled:opacity-50"
          >
            {mut.isPending ? "Deleting…" : "Delete permanently"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function TrashPage() {
  const [filterType, setFilterType] = useState<TrashEntryType | "all">("all");
  const [filterSince, setFilterSince] = useState<string>("");
  const [filterQ, setFilterQ] = useState<string>("");
  const [pendingPermanent, setPendingPermanent] = useState<TrashEntry | null>(
    null,
  );
  const [pendingRestore, setPendingRestore] = useState<TrashEntry | null>(null);

  // Paged (#1961): the API answers a window and the total. "Oldest first" is
  // the order the retention purge removes rows in, so the rows closest to being
  // lost are reachable.
  const [page, setPage] = useState(0);
  const [sort, setSort] = useState<"newest" | "oldest">("newest");

  const params = useMemo(
    () => ({
      type: filterType === "all" ? undefined : filterType,
      since: filterSince ? new Date(filterSince).toISOString() : undefined,
      q: filterQ.trim() || undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
      sort,
    }),
    [filterType, filterSince, filterQ, page, sort],
  );
  const filtered =
    filterType !== "all" || filterSince !== "" || filterQ.trim() !== "";

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["trash", params],
    queryFn: () => trashApi.list(params),
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  // A restore or purge that empties the last page would otherwise leave the
  // operator on a page past the end, told the Trash is empty while it is not.
  useEffect(() => {
    if (data && page > 0 && page >= totalPages) setPage(totalPages - 1);
  }, [data, page, totalPages]);

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-5xl space-y-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <Trash2 className="h-5 w-5" />
            Trash
          </h1>
          <p className="text-sm text-muted-foreground">
            Soft-deleted IPAM, DNS, DHCP, customer, overlay and service rows.
            Restore by row to bring back every cascaded child in the same batch.
            The nightly purge sweep permanently removes anything older than the
            platform retention window (default 30 days).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground">Type</label>
            <select
              className="rounded-md border bg-background px-2 py-1 text-sm"
              value={filterType}
              onChange={(e) => {
                setFilterType(e.target.value as TrashEntryType | "all");
                setPage(0);
              }}
            >
              <option value="all">All</option>
              {(Object.keys(TYPE_LABELS) as TrashEntryType[]).map((t) => (
                <option key={t} value={t}>
                  {TYPE_LABELS[t]}
                </option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground">Since</label>
            <input
              type="datetime-local"
              value={filterSince}
              onChange={(e) => {
                setFilterSince(e.target.value);
                setPage(0);
              }}
              className="rounded-md border bg-background px-2 py-1 text-sm"
            />
          </div>
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search name / CIDR…"
              value={filterQ}
              onChange={(e) => {
                setFilterQ(e.target.value);
                setPage(0);
              }}
              className="rounded-md border bg-background px-2 py-1 text-sm"
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-muted-foreground">Order</label>
          <select
            aria-label="Order"
            className="rounded-md border bg-background px-2 py-1 text-sm"
            value={sort}
            onChange={(e) => {
              setSort(e.target.value as "newest" | "oldest");
              setPage(0);
            }}
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first (purged first)</option>
          </select>
        </div>

        <div className="overflow-x-auto rounded border">
          <table className="min-w-[800px] w-full text-sm">
            <thead>
              <tr className="bg-muted/40 text-left">
                <th className="px-2 py-1 font-medium">Type</th>
                <th className="px-2 py-1 font-medium">Name / CIDR</th>
                <th className="px-2 py-1 font-medium">Deleted at</th>
                <th className="px-2 py-1 font-medium">Deleted by</th>
                <th className="px-2 py-1 font-medium">Batch size</th>
                <th className="px-2 py-1 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {isLoading && (
                <tr>
                  <td colSpan={6} className="px-2 py-4 text-muted-foreground">
                    Loading…
                  </td>
                </tr>
              )}
              {!isLoading && items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-2 py-4 text-muted-foreground">
                    {/* A refused or failed read is not an empty trash (#1343). */}
                    {isError ? (
                      <ListReadError error={error} what="the trash" />
                    ) : (
                      <>
                        {filtered
                          ? "No rows match these filters."
                          : "Trash is empty."}
                      </>
                    )}
                  </td>
                </tr>
              )}
              {items.map((item) => (
                <tr key={`${item.type}:${item.id}`}>
                  <td className="px-2 py-1">
                    <span
                      className={cn(
                        "inline-flex rounded px-1.5 py-0.5 text-xs font-medium",
                        TYPE_BADGE[item.type],
                      )}
                    >
                      {TYPE_LABELS[item.type]}
                    </span>
                  </td>
                  <td className="px-2 py-1 font-mono">{item.name_or_cidr}</td>
                  <td className="px-2 py-1 text-muted-foreground">
                    {formatTs(item.deleted_at)}
                  </td>
                  <td className="px-2 py-1 text-muted-foreground">
                    {item.deleted_by_username ?? "—"}
                  </td>
                  <td className="px-2 py-1 text-center">{item.batch_size}</td>
                  <td className="px-2 py-1 text-right space-x-2">
                    <button
                      onClick={() => setPendingRestore(item)}
                      title="Restore this row + its batch siblings"
                      className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted"
                    >
                      <RotateCcw className="h-3 w-3" />
                      Restore
                    </button>
                    <button
                      onClick={() => setPendingPermanent(item)}
                      title="Permanently delete (cannot be undone)"
                      className="inline-flex items-center gap-1 rounded-md border border-red-500/40 px-2 py-1 text-xs text-red-700 hover:bg-red-500/10 dark:text-red-300"
                    >
                      <Trash2 className="h-3 w-3" />
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {total > 0 && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">
              Showing {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + items.length}{" "}
              of {total}
              {totalPages > 1 ? ` · page ${page + 1} of ${totalPages}` : ""}
            </span>
            {totalPages > 1 && (
              <div className="flex items-center gap-2">
                <button
                  aria-label="Previous page"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="flex h-8 w-8 items-center justify-center rounded-md border text-muted-foreground hover:bg-accent disabled:pointer-events-none disabled:opacity-40"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  aria-label="Next page"
                  onClick={() =>
                    setPage((p) => Math.min(totalPages - 1, p + 1))
                  }
                  disabled={page >= totalPages - 1}
                  className="flex h-8 w-8 items-center justify-center rounded-md border text-muted-foreground hover:bg-accent disabled:pointer-events-none disabled:opacity-40"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            )}
          </div>
        )}

        {pendingRestore && (
          <ConfirmRestoreModal
            entry={pendingRestore}
            onClose={() => setPendingRestore(null)}
          />
        )}
        {pendingPermanent && (
          <ConfirmPermanentDeleteModal
            entry={pendingPermanent}
            onClose={() => setPendingPermanent(null)}
          />
        )}
      </div>
    </div>
  );
}
