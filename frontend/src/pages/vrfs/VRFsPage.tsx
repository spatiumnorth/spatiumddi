import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListEmpty } from "@/components/ui/list-read-error";
import {
  Check,
  Pencil,
  Plus,
  RefreshCw,
  Route as RouteIcon,
  Trash2,
  X,
} from "lucide-react";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { ServicesUsingButton } from "@/components/ServicesUsingButton";
import { TagFilterChips } from "@/components/TagFilterChips";
import { AsnPicker } from "@/components/ipam/asn-picker";
import { CustomerChip, CustomerPicker } from "@/components/ownership/pickers";
import {
  asnsApi,
  vrfsApi,
  type VRF,
  type VRFCreate,
  type VRFUpdate,
  formatApiError,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// RD / RT format. Two flavours, both ``X:N``:
//   * ASN:N — e.g. 65000:100 (uint ASN portion)
//   * IP:N  — e.g. 192.0.2.1:100 (dotted-IPv4 ASN portion)
// Mirrors the regex enforced server-side in
// ``backend/app/api/v1/vrfs/router.py``.
const RD_RT_RE = /^(\d+|(\d+\.){3}\d+):\d+$/;

function isValidRdRt(v: string): boolean {
  return RD_RT_RE.test(v.trim());
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
      {hint && (
        <div className="text-[11px] text-muted-foreground/80">{hint}</div>
      )}
    </div>
  );
}

function RtBadgeCount({ values, label }: { values: string[]; label: string }) {
  if (!values || values.length === 0) {
    return <span className="text-muted-foreground/50">—</span>;
  }
  return (
    <span
      className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[11px] font-mono"
      title={`${label}\n${values.join("\n")}`}
    >
      {values.length}
    </span>
  );
}

function CountBadge({
  count,
  emptyDash = true,
}: {
  count: number;
  emptyDash?: boolean;
}) {
  if (count === 0 && emptyDash) {
    return <span className="text-muted-foreground/50">—</span>;
  }
  return (
    <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[11px] tabular-nums">
      {count}
    </span>
  );
}

// Comma-separated string ↔ trimmed string[]. Preserves user-typed
// whitespace until submit so "65000:100, 65000:200" doesn't keep
// stripping mid-edit.
/** Resolves ``asn_id`` against the cached ASN list and renders
 * ``AS{number}`` instead of a UUID slice. Falls back to "—" when
 * the ASN list hasn't loaded yet or the row is missing. */
function AsnNumberCell({ asnId }: { asnId: string | null | undefined }) {
  const { data } = useQuery({
    queryKey: ["asns-picker"],
    queryFn: () => asnsApi.list({ limit: 500 }),
    staleTime: 60_000,
    enabled: !!asnId,
  });
  if (!asnId) {
    return <span className="text-muted-foreground/50">—</span>;
  }
  const asn = (data?.items ?? []).find((a) => a.id === asnId);
  if (!asn) {
    return (
      <span className="text-muted-foreground/50" title={asnId}>
        …
      </span>
    );
  }
  return (
    <Link
      to={`/network/asns/${asn.id}`}
      className="rounded bg-muted px-1.5 py-0.5 hover:bg-accent"
    >
      AS{asn.number}
      {asn.name ? ` — ${asn.name}` : ""}
    </Link>
  );
}

function csvToList(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter((x) => x.length > 0);
}

function listToCsv(xs: string[]): string {
  return (xs || []).join(", ");
}

// ── Editor modal ──────────────────────────────────────────────────────────────

export function VRFEditorModal({
  existing,
  onClose,
}: {
  existing: VRF | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [rd, setRd] = useState(existing?.route_distinguisher ?? "");
  const [importTargets, setImportTargets] = useState(
    listToCsv(existing?.import_targets ?? []),
  );
  const [exportTargets, setExportTargets] = useState(
    listToCsv(existing?.export_targets ?? []),
  );
  const [asnId, setAsnId] = useState<string | null>(existing?.asn_id ?? null);
  const [customerId, setCustomerId] = useState<string | null>(
    existing?.customer_id ?? null,
  );
  const [error, setError] = useState<string | null>(null);

  const rdValid = rd.trim() === "" || isValidRdRt(rd);
  const importItems = csvToList(importTargets);
  const exportItems = csvToList(exportTargets);
  const importInvalid = importItems.filter((x) => !isValidRdRt(x));
  const exportInvalid = exportItems.filter((x) => !isValidRdRt(x));

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) {
        throw new Error("name is required");
      }
      const body: VRFCreate | VRFUpdate = {
        name: name.trim(),
        description,
        route_distinguisher: rd.trim() === "" ? null : rd.trim(),
        import_targets: importItems,
        export_targets: exportItems,
        asn_id: asnId,
        customer_id: customerId,
      };
      if (existing) {
        return vrfsApi.update(existing.id, body);
      }
      return vrfsApi.create(body as VRFCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vrfs"] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  const canSave =
    name.trim().length > 0 &&
    rdValid &&
    importInvalid.length === 0 &&
    exportInvalid.length === 0;

  const rdHint = (
    <div className="flex items-center gap-1.5">
      {rd.trim() === "" ? (
        <span className="text-muted-foreground/80">
          Optional. Format: <code>ASN:N</code> (e.g. <code>65000:100</code>) or{" "}
          <code>IP:N</code> (e.g. <code>192.0.2.1:100</code>).
        </span>
      ) : rdValid ? (
        <>
          <Check className="h-3 w-3 text-emerald-600" />
          <span className="text-emerald-700 dark:text-emerald-400">
            Valid RD format
          </span>
        </>
      ) : (
        <>
          <X className="h-3 w-3 text-destructive" />
          <span className="text-destructive">
            Must be <code>ASN:N</code> or <code>IP:N</code>
          </span>
        </>
      )}
    </div>
  );

  return (
    <Modal onClose={onClose} title={existing ? "Edit VRF" : "New VRF"} wide>
      <div className="space-y-4">
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. PROD-CUST-001"
            autoFocus
          />
        </Field>
        <Field label="Description">
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <Field
          label="Origin ASN"
          hint={
            <span>
              Optional. Cross-cutting validators check that any{" "}
              <code>ASN:N</code> RD / RT below uses this ASN's number.
            </span>
          }
        >
          <AsnPicker className={inputCls} value={asnId} onChange={setAsnId} />
        </Field>
        <Field label="Customer" hint="Optional logical owner of this VRF.">
          <CustomerPicker
            className={inputCls}
            value={customerId}
            onChange={setCustomerId}
          />
        </Field>
        <Field label="Route distinguisher (RD)" hint={rdHint}>
          <input
            className={cn(inputCls, !rdValid && "border-destructive")}
            value={rd}
            onChange={(e) => setRd(e.target.value)}
            placeholder="65000:100"
          />
        </Field>
        <Field
          label="Import RTs"
          hint={
            <span>
              Comma-separated RT list — same <code>ASN:N</code> /{" "}
              <code>IP:N</code> format as RD.
              {importInvalid.length > 0 && (
                <span className="block text-destructive">
                  Invalid: {importInvalid.join(", ")}
                </span>
              )}
            </span>
          }
        >
          <input
            className={cn(
              inputCls,
              importInvalid.length > 0 && "border-destructive",
            )}
            value={importTargets}
            onChange={(e) => setImportTargets(e.target.value)}
            placeholder="65000:100, 65000:200"
          />
        </Field>
        <Field
          label="Export RTs"
          hint={
            <span>
              Comma-separated RT list. Some operators run a single RT for both
              directions; in that case copy the same value into Import + Export.
              {exportInvalid.length > 0 && (
                <span className="block text-destructive">
                  Invalid: {exportInvalid.join(", ")}
                </span>
              )}
            </span>
          }
        >
          <input
            className={cn(
              inputCls,
              exportInvalid.length > 0 && "border-destructive",
            )}
            value={exportTargets}
            onChange={(e) => setExportTargets(e.target.value)}
            placeholder="65000:100, 65000:200"
          />
        </Field>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => mut.mutate()}
            disabled={!canSave || mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Bulk-delete confirmation ──────────────────────────────────────────────────

function BulkDeleteModal({
  rows,
  onClose,
}: {
  rows: VRF[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const anyLinked = rows.some(
    (r) => (r.space_count || 0) + (r.block_count || 0) > 0,
  );
  const [force, setForce] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: async () => {
      return vrfsApi.bulkDelete(
        rows.map((r) => r.id),
        anyLinked && force,
      );
    },
    onSuccess: (resp) => {
      qc.invalidateQueries({ queryKey: ["vrfs"] });
      if (resp.refused.length > 0) {
        setError(
          `Refused ${resp.refused.length} VRF${resp.refused.length === 1 ? "" : "s"} ` +
            "with linked spaces or blocks. Tick force-detach to proceed.",
        );
        return;
      }
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Bulk delete failed"));
    },
  });

  return (
    <Modal title={`Delete ${rows.length} VRFs?`} onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          You are about to delete the following VRFs:
        </p>
        <div className="max-h-40 overflow-y-auto rounded border bg-muted/40 p-2 font-mono text-xs">
          {rows.map((r) => (
            <div key={r.id} className="flex items-center justify-between">
              <span>{r.name}</span>
              {(r.space_count || r.block_count) > 0 && (
                <span className="text-muted-foreground">
                  {r.space_count} spaces · {r.block_count} blocks
                </span>
              )}
            </div>
          ))}
        </div>
        {anyLinked && (
          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={force}
              onChange={(e) => setForce(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              <span className="font-medium">Force-detach.</span> Linked IP
              spaces / IP blocks will have their <code>vrf_id</code> set to NULL
              via <code>ON DELETE SET NULL</code>. Without this, VRFs with
              linked rows are skipped.
            </span>
          </label>
        )}
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex items-center justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => mut.mutate()}
            disabled={mut.isPending || (anyLinked && !force)}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {mut.isPending ? "Deleting…" : `Delete ${rows.length}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function VRFsPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'vrf'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "vrf"),
    "Requires write permission on VRFs",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "vrf"),
    "Requires delete permission on VRFs",
  );
  const qc = useQueryClient();
  const [editing, setEditing] = useState<VRF | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmBulk, setConfirmBulk] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [tagFilters, setTagFilters] = useState<string[]>([]);

  const {
    data: vrfs = [],
    isFetching,
    refetch,
    error: listError,
  } = useQuery({
    queryKey: ["vrfs", tagFilters],
    queryFn: () =>
      vrfsApi.list(tagFilters.length > 0 ? { tag: tagFilters } : undefined),
  });

  const allSelected = vrfs.length > 0 && vrfs.every((v) => selected.has(v.id));
  const someSelected = !allSelected && vrfs.some((v) => selected.has(v.id));

  function toggleAll() {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(vrfs.map((v) => v.id)));
    }
  }
  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const selectedRows = useMemo(
    () => vrfs.filter((v) => selected.has(v.id)),
    [vrfs, selected],
  );

  function refresh() {
    refetch();
    qc.invalidateQueries({ queryKey: ["vrfs"] });
  }

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)]">
      {/* Header */}
      <header className="flex items-center justify-between border-b bg-card px-4 py-3 gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <RouteIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-base font-semibold">VRFs</h1>
          <span className="text-xs text-muted-foreground">
            {listError ? "—" : `${vrfs.length} total`}
            {selected.size > 0 && (
              <span className="ml-2 text-primary">
                {selected.size} selected
              </span>
            )}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <HeaderButton
            variant="secondary"
            onClick={refresh}
            disabled={isFetching}
            title="Refresh"
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
            />
            Refresh
          </HeaderButton>
          <HeaderButton
            variant="primary"
            onClick={() => setShowCreate(true)}
            {...writeGate}
          >
            <Plus className="h-3.5 w-3.5" /> New VRF
          </HeaderButton>
        </div>
      </header>

      {/* Tag filter row */}
      <div className="border-b bg-card px-4 py-2">
        <TagFilterChips
          value={tagFilters}
          onChange={setTagFilters}
          placeholder="Filter by tag — try env or env:prod…"
        />
      </div>

      {/* Bulk toolbar */}
      {selected.size > 0 && (
        <div className="flex items-center justify-between border-b bg-muted/40 px-4 py-2">
          <span className="text-xs">{selected.size} selected</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setConfirmBulk(true)}
              className="inline-flex items-center gap-1 rounded-md bg-destructive px-2 py-1 text-xs text-destructive-foreground hover:bg-destructive/90 disabled:cursor-not-allowed disabled:opacity-50"
              {...deleteGate}
            >
              <Trash2 className="h-3 w-3" /> Delete {selected.size}
            </button>
            <button
              onClick={() => setSelected(new Set())}
              className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-card border-b z-10">
            <tr className="text-left text-xs uppercase tracking-wider text-muted-foreground">
              <th className="w-8 px-2 py-2">
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={(el) => {
                    if (el) el.indeterminate = someSelected;
                  }}
                  onChange={toggleAll}
                />
              </th>
              <th className="px-2 py-2">Name</th>
              <th className="px-2 py-2">ASN</th>
              <th className="px-2 py-2">RD</th>
              <th className="px-2 py-2">Import RTs</th>
              <th className="px-2 py-2">Export RTs</th>
              <th className="px-2 py-2">Spaces</th>
              <th className="px-2 py-2">Blocks</th>
              <th className="px-2 py-2">Modified</th>
              <th className="w-10 px-2 py-2 text-right" />
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {vrfs.length === 0 && (
              <tr>
                <td
                  colSpan={10}
                  className="px-4 py-8 text-center text-muted-foreground"
                >
                  <ListEmpty
                    error={listError}
                    what="VRFs"
                    filtered={tagFilters.length > 0}
                    onClearFilters={() => setTagFilters([])}
                  >
                    No VRFs yet. Click <strong>+ New VRF</strong> to create one.
                  </ListEmpty>
                </td>
              </tr>
            )}
            {vrfs.map((v) => {
              const sel = selected.has(v.id);
              return (
                <tr
                  key={v.id}
                  className={cn(
                    "border-b last:border-0",
                    sel && "bg-primary/5",
                  )}
                >
                  <td className="px-2 py-1.5">
                    <input
                      type="checkbox"
                      checked={sel}
                      onChange={() => toggleOne(v.id)}
                    />
                  </td>
                  <td className="px-2 py-1.5 font-mono text-xs">
                    <span className="inline-flex items-center gap-1.5">
                      <Link
                        to={`/network/vrfs/${v.id}`}
                        className="hover:text-primary hover:underline"
                      >
                        {v.name}
                      </Link>
                      <CustomerChip customerId={v.customer_id} />
                    </span>
                  </td>
                  <td className="px-2 py-1.5 font-mono text-[11px]">
                    <AsnNumberCell asnId={v.asn_id} />
                  </td>
                  <td className="px-2 py-1.5 font-mono text-[11px]">
                    {v.route_distinguisher ?? (
                      <span className="text-muted-foreground/50">—</span>
                    )}
                  </td>
                  <td className="px-2 py-1.5">
                    <RtBadgeCount
                      values={v.import_targets ?? []}
                      label="Import RTs"
                    />
                  </td>
                  <td className="px-2 py-1.5">
                    <RtBadgeCount
                      values={v.export_targets ?? []}
                      label="Export RTs"
                    />
                  </td>
                  <td className="px-2 py-1.5">
                    <CountBadge count={v.space_count} />
                  </td>
                  <td className="px-2 py-1.5">
                    <CountBadge count={v.block_count} />
                  </td>
                  <td className="px-2 py-1.5 text-xs text-muted-foreground tabular-nums">
                    {v.modified_at
                      ? new Date(v.modified_at).toLocaleString()
                      : "—"}
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    <ServicesUsingButton
                      kind="vrf"
                      resourceId={v.id}
                      label={v.name}
                      compact
                    />
                    <button
                      onClick={() => setEditing(v)}
                      className="ml-1 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                      title="Edit VRF"
                      {...writeGate}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {showCreate && (
        <VRFEditorModal existing={null} onClose={() => setShowCreate(false)} />
      )}
      {editing && (
        <VRFEditorModal existing={editing} onClose={() => setEditing(null)} />
      )}
      {confirmBulk && selectedRows.length > 0 && (
        <BulkDeleteModal
          rows={selectedRows}
          onClose={() => {
            setConfirmBulk(false);
            setSelected(new Set());
          }}
        />
      )}
    </div>
  );
}
