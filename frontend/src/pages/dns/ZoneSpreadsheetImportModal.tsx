import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Modal } from "@/components/ui/modal";
import { confirmsZone } from "@/lib/dnsNames";
import {
  dnsApi,
  formatApiError,
  type DNSSheetImportMode,
  type DNSSheetImportPreview,
  type DNSSheetRecordChange,
  type DNSSheetRowIssue,
  type DNSZone,
} from "@/lib/api";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function ChangeTable({
  label,
  items,
  color,
}: {
  label: string;
  items: DNSSheetRecordChange[];
  color: string;
}) {
  if (items.length === 0) return null;
  return (
    <details className="rounded border" open={items.length <= 10}>
      <summary
        className={`cursor-pointer px-2 py-1 text-xs font-medium ${color}`}
      >
        {label} ({items.length})
      </summary>
      <div className="max-h-48 overflow-auto">
        <table className="w-full min-w-[32rem] text-xs">
          <tbody>
            {items.map((c, i) => (
              <tr key={i} className="border-t">
                <td className="px-2 py-0.5 text-muted-foreground">
                  {c.row != null ? `row ${c.row}` : "—"}
                </td>
                <td className="px-2 py-0.5 font-mono break-all">{c.name}</td>
                <td className="px-2 py-0.5">{c.record_type}</td>
                <td className="px-2 py-0.5 font-mono text-muted-foreground break-all">
                  {c.value}
                </td>
                <td className="px-2 py-0.5 text-muted-foreground">
                  {c.view ?? ""}
                </td>
                <td className="px-2 py-0.5 text-muted-foreground">
                  {c.changed_fields.length > 0
                    ? c.changed_fields.join(", ")
                    : c.read_only
                      ? "read-only"
                      : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function IssueList({
  label,
  items,
  color,
}: {
  label: string;
  items: DNSSheetRowIssue[];
  color: string;
}) {
  if (items.length === 0) return null;
  return (
    <details className="rounded border" open>
      <summary
        className={`cursor-pointer px-2 py-1 text-xs font-medium ${color}`}
      >
        {label} ({items.length})
      </summary>
      <ul className="max-h-48 space-y-0.5 overflow-auto px-2 py-1 text-xs">
        {items.map((s, i) => (
          <li key={i} className="break-all">
            <span className="font-medium">
              {s.row != null ? `Row ${s.row}` : "Record"}
            </span>
            {s.name ? ` (${s.name} ${s.record_type ?? ""})` : ""}: {s.reason}
          </li>
        ))}
      </ul>
    </details>
  );
}

/** Import a CSV / XLSX records sheet into one zone (#2139): preview the
 *  diff with per-row errors, then commit. ``replace`` deletes records the
 *  sheet does not list, so it asks for the zone's name typed back. */
export function ZoneSpreadsheetImportModal({
  groupId,
  zone,
  onClose,
}: {
  groupId: string;
  zone: DNSZone;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<DNSSheetImportMode>("merge");
  const [confirm, setConfirm] = useState("");
  const [preview, setPreview] = useState<DNSSheetImportPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [providerWarning, setProviderWarning] = useState<string | null>(null);

  const previewMut = useMutation({
    mutationFn: () =>
      dnsApi.importZoneSheetPreview(groupId, zone.id, file!, mode),
    onSuccess: (data) => {
      setPreview(data);
      setError(null);
    },
    onError: (err) => {
      setPreview(null);
      setError(formatApiError(err, "Could not read the file"));
    },
  });

  const commitMut = useMutation({
    mutationFn: () =>
      dnsApi.importZoneSheetCommit(
        groupId,
        zone.id,
        file!,
        mode,
        mode === "replace" ? confirm : undefined,
      ),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
      qc.invalidateQueries({ queryKey: ["dns-zones", groupId] });
      // #1538 / #1539 — on an agentless group the provider is called after
      // the commit; a change it refused is retried in the background, and
      // until then it is not served. Say so rather than close as if clean.
      if (res.provider_warning) {
        setProviderWarning(res.provider_warning);
        setPreview(null);
        return;
      }
      onClose();
    },
    onError: (err) => setError(formatApiError(err, "Import failed")),
  });

  const hasErrors = (preview?.errors.length ?? 0) > 0;
  const confirmed = mode !== "replace" || confirmsZone(confirm, zone.name);
  const nothingToDo =
    preview != null &&
    preview.to_create.length +
      preview.to_update.length +
      preview.to_delete.length ===
      0;

  return (
    <Modal
      title={`Import records (CSV / XLSX) — ${zone.name}`}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Start from <span className="font-medium">Export CSV / XLSX</span> or
          the <span className="font-medium">template</span>. Rows with an{" "}
          <code>id</code> update that record; rows without one match by view,
          name, type and value, or are added. Template rows marked{" "}
          <code>EXAMPLE</code> are ignored. Records IPAM or an integration
          manages are never changed.
        </p>
        <div className="space-y-1">
          <label className="block text-xs font-medium text-muted-foreground">
            File
          </label>
          <input
            type="file"
            accept=".csv,.xlsx,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
              setPreview(null);
              setError(null);
            }}
            className="text-xs"
          />
        </div>
        <div className="space-y-1">
          <label className="block text-xs font-medium text-muted-foreground">
            Mode
          </label>
          <select
            className={inputCls}
            value={mode}
            onChange={(e) => {
              setMode(e.target.value as DNSSheetImportMode);
              setPreview(null);
            }}
          >
            <option value="merge">Merge — add and update; never delete</option>
            <option value="replace">
              Replace — also delete records the sheet does not list
            </option>
          </select>
        </div>
        {mode === "replace" && (
          <div className="space-y-1">
            <label className="block text-xs font-medium text-muted-foreground">
              Type the zone name ({zone.name.replace(/\.$/, "")}) to confirm a
              replace
            </label>
            <input
              className={inputCls}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              aria-label="Confirm zone name"
            />
          </div>
        )}

        {providerWarning && (
          <div
            role="status"
            className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 break-words dark:text-amber-400"
          >
            The records were saved, but the DNS provider has not taken every
            change yet; it will be retried: {providerWarning}
          </div>
        )}
        {error && (
          <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive break-words">
            {error}
          </div>
        )}

        {preview && (
          <div className="space-y-2">
            <div className="text-xs text-muted-foreground">
              Read {preview.row_count} row
              {preview.row_count !== 1 ? "s" : ""} from the{" "}
              {preview.format.toUpperCase()} file
              {preview.examples_ignored > 0 &&
                ` (${preview.examples_ignored} example row${preview.examples_ignored !== 1 ? "s" : ""} ignored)`}
              .
            </div>
            <IssueList
              label="Errors — fix these; nothing is imported while any remain"
              items={preview.errors}
              color="text-destructive"
            />
            <ChangeTable
              label="Create"
              items={preview.to_create}
              color="text-emerald-600"
            />
            <ChangeTable
              label="Update"
              items={preview.to_update}
              color="text-amber-600"
            />
            <ChangeTable
              label="Delete"
              items={preview.to_delete}
              color="text-destructive"
            />
            <ChangeTable
              label="Unchanged"
              items={preview.unchanged}
              color="text-muted-foreground"
            />
            <IssueList
              label="Skipped"
              items={preview.skipped}
              color="text-amber-600"
            />
          </div>
        )}

        <div className="flex flex-wrap justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            {providerWarning ? "Close" : "Cancel"}
          </button>
          <button
            onClick={() => previewMut.mutate()}
            disabled={!file || previewMut.isPending}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            {previewMut.isPending ? "Reading…" : "Preview"}
          </button>
          <button
            onClick={() => commitMut.mutate()}
            disabled={
              !preview ||
              providerWarning != null ||
              hasErrors ||
              nothingToDo ||
              !confirmed ||
              commitMut.isPending
            }
            title={
              hasErrors
                ? "Fix the rows with errors first"
                : !confirmed
                  ? "Type the zone name to confirm a replace"
                  : undefined
            }
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {commitMut.isPending ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
