import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RotateCcw, Search, Trash2 } from "lucide-react";
import { trashApi, type TrashEntry, type TrashEntryType } from "@/lib/api";
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
};

const TYPE_BADGE: Record<TrashEntryType, string> = {
  ip_space: "bg-indigo-500/15 text-indigo-700 dark:text-indigo-300",
  ip_block: "bg-blue-500/15 text-blue-700 dark:text-blue-300",
  subnet: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-300",
  dns_zone: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  dns_record: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  dhcp_scope: "bg-amber-500/15 text-amber-700 dark:text-amber-300",
};

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
  // Only offered for a dns_record batch — a bulk record delete (#963) stamps
  // N independent siblings under one id, so leaving one behind is sound. Every
  // other batch is a cascade (a zone AND its records, a scope AND its pools)
  // where a partial restore can bring a child back without its parent; the
  // server refuses those with a 422, and this keeps the button off the screen
  // rather than showing one that always errors.
  const [canSkipConflicts, setCanSkipConflicts] = useState(false);
  const mut = useMutation({
    mutationFn: (skipConflicts: boolean) =>
      trashApi.restore(entry.type, entry.id, { skipConflicts }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["trash"] });
      qc.invalidateQueries({ queryKey: ["ipam"] });
      qc.invalidateQueries({ queryKey: ["dns"] });
      qc.invalidateQueries({ queryKey: ["dhcp"] });
      onClose();
    },
    onError: (err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: unknown } } })
        ?.response?.data?.detail;
      if (detail && typeof detail === "object" && "conflicts" in detail) {
        const conflicts = (
          detail as { conflicts: Array<{ display: string; reason: string }> }
        ).conflicts;
        setError(
          `Cannot restore: ${conflicts
            .map((c) => `${c.display} — ${c.reason}`)
            .join("; ")}`,
        );
        setCanSkipConflicts(
          entry.type === "dns_record" && entry.batch_size > conflicts.length,
        );
      } else if (typeof detail === "string") {
        setError(detail);
      } else {
        setError("Restore failed");
      }
    },
  });

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
          {canSkipConflicts && (
            <button
              onClick={() => {
                setError(null);
                mut.mutate(true);
              }}
              disabled={mut.isPending}
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
            disabled={mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Restoring…" : "Restore"}
          </button>
        </div>
      </div>
    </Modal>
  );
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
      const detail = (err as { response?: { data?: { detail?: unknown } } })
        ?.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Permanent delete failed");
    },
  });

  return (
    <Modal title="Permanently delete?" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm">
          This permanently removes{" "}
          <span className="font-mono font-medium">{entry.name_or_cidr}</span> (
          {TYPE_LABELS[entry.type]}). It cannot be restored.
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

  const params = useMemo(
    () => ({
      type: filterType === "all" ? undefined : filterType,
      since: filterSince ? new Date(filterSince).toISOString() : undefined,
      q: filterQ || undefined,
      limit: 200,
    }),
    [filterType, filterSince, filterQ],
  );

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["trash", params],
    queryFn: () => trashApi.list(params),
  });

  const items = data?.items ?? [];

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-5xl space-y-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <Trash2 className="h-5 w-5" />
            Trash
          </h1>
          <p className="text-sm text-muted-foreground">
            Soft-deleted IPAM / DNS / DHCP rows. Restore by row to bring back
            every cascaded child in the same batch. The nightly purge sweep
            permanently removes anything older than the platform retention
            window (default 30 days).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground">Type</label>
            <select
              className="rounded-md border bg-background px-2 py-1 text-sm"
              value={filterType}
              onChange={(e) =>
                setFilterType(e.target.value as TrashEntryType | "all")
              }
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
              onChange={(e) => setFilterSince(e.target.value)}
              className="rounded-md border bg-background px-2 py-1 text-sm"
            />
          </div>
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search name / CIDR…"
              value={filterQ}
              onChange={(e) => setFilterQ(e.target.value)}
              className="rounded-md border bg-background px-2 py-1 text-sm"
            />
          </div>
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
                      "Trash is empty."
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
