import { useState } from "react";
import {
  Upload,
  Download,
  X,
  AlertCircle,
  CheckCircle2,
  FileWarning,
  ChevronDown,
  Printer,
} from "lucide-react";
import {
  ipamIoApi,
  type AddressImportCommitResponse,
  type ImportPreviewResponse,
  type ImportStrategy,
  type IPSpace,
  type Subnet,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { permissionGate } from "@/hooks/usePermissions";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";

// ─── Import Modal ────────────────────────────────────────────────────────────

export function ImportModal({
  spaces,
  defaultSpaceId,
  onClose,
  onCommitted,
}: {
  spaces: IPSpace[];
  defaultSpaceId?: string;
  onClose: () => void;
  onCommitted: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [spaceId, setSpaceId] = useState<string>(
    defaultSpaceId ?? spaces[0]?.id ?? "",
  );
  const [strategy, setStrategy] = useState<ImportStrategy>("fail");
  const [preview, setPreview] = useState<ImportPreviewResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [committed, setCommitted] = useState<{
    created: number;
    updated: number;
    skipped: number;
    blocks: number;
  } | null>(null);

  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);

  async function handlePreview() {
    if (!file || !spaceId) return;
    setBusy(true);
    setError(null);
    setPreview(null);
    try {
      const result = await ipamIoApi.preview(file, {
        space_id: spaceId,
        strategy,
      });
      setPreview(result);
    } catch (e) {
      const err = e as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      setError(err.response?.data?.detail ?? err.message ?? "Preview failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleCommit() {
    if (!file || !spaceId) return;
    setBusy(true);
    setError(null);
    try {
      const result = await ipamIoApi.commit(file, {
        space_id: spaceId,
        strategy,
      });
      setCommitted({
        created: result.created_subnets,
        updated: result.updated_subnets,
        skipped: result.skipped,
        blocks: result.auto_created_blocks,
      });
      onCommitted();
    } catch (e) {
      const err = e as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      setError(err.response?.data?.detail ?? err.message ?? "Import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        className="flex max-h-[90vh] w-full max-w-[95vw] sm:max-w-[760px] flex-col rounded-lg bg-background shadow-xl focus:outline-none"
        style={dialogStyle}
      >
        <div
          {...dragHandleProps}
          className={cn(
            "flex items-center justify-between border-b p-4",
            dragHandleProps.className,
          )}
        >
          <h2
            {...titleProps}
            className="flex items-center gap-2 text-base font-semibold"
          >
            <Upload className="h-4 w-4" /> Import IPAM data
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {committed ? (
            <div className="rounded border border-green-300 bg-green-50 p-4 dark:border-green-900 dark:bg-green-900/20">
              <div className="flex items-center gap-2 font-medium text-green-800 dark:text-green-300">
                <CheckCircle2 className="h-4 w-4" /> Import complete
              </div>
              <ul className="mt-2 text-xs text-green-900 dark:text-green-200 space-y-0.5">
                <li>Created: {committed.created} subnets</li>
                <li>Updated: {committed.updated} subnets</li>
                <li>Skipped: {committed.skipped}</li>
                <li>Auto-created parent blocks: {committed.blocks}</li>
              </ul>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs font-medium">
                    Target IP Space
                  </label>
                  <select
                    value={spaceId}
                    onChange={(e) => setSpaceId(e.target.value)}
                    className="w-full rounded border bg-background px-2 py-1 text-sm"
                  >
                    {spaces.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium">
                    Conflict strategy
                  </label>
                  <select
                    value={strategy}
                    onChange={(e) =>
                      setStrategy(e.target.value as ImportStrategy)
                    }
                    className="w-full rounded border bg-background px-2 py-1 text-sm"
                  >
                    <option value="fail">Fail on conflict</option>
                    <option value="skip">Skip existing</option>
                    <option value="overwrite">Overwrite existing</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="mb-1 block text-xs font-medium">
                  File (CSV, JSON, or XLSX)
                </label>
                <input
                  type="file"
                  accept=".csv,.json,.xlsx,text/csv,application/json"
                  onChange={(e) => {
                    setFile(e.target.files?.[0] ?? null);
                    setPreview(null);
                  }}
                  className="w-full text-sm"
                />
              </div>

              {error && (
                <div className="flex items-start gap-2 rounded border border-red-300 bg-red-50 p-2 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-300">
                  <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {preview && <PreviewTable preview={preview} />}
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t p-3">
          <button
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted"
          >
            Close
          </button>
          {!committed && (
            <>
              <button
                disabled={!file || !spaceId || busy}
                onClick={handlePreview}
                className="rounded border bg-muted px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
              >
                {busy ? "Working…" : "Preview"}
              </button>
              <button
                disabled={!preview || busy || preview.summary.errors > 0}
                onClick={handleCommit}
                className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {busy ? "Importing…" : "Commit import"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function PreviewTable({ preview }: { preview: ImportPreviewResponse }) {
  const rows = [
    ...preview.creates.map((r) => ({ ...r, _class: "create" as const })),
    ...preview.updates.map((r) => ({ ...r, _class: "update" as const })),
    ...preview.conflicts.map((r) => ({ ...r, _class: "conflict" as const })),
    ...preview.errors.map((r) => ({ ...r, _class: "error" as const })),
  ];
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2 text-xs">
        <Badge color="green" label={`${preview.summary.creates} create`} />
        <Badge color="blue" label={`${preview.summary.updates} update`} />
        <Badge color="amber" label={`${preview.summary.conflicts} conflict`} />
        <Badge color="red" label={`${preview.summary.errors} error`} />
      </div>
      <div className="max-h-72 overflow-auto rounded border">
        <table className="w-full text-xs">
          <thead className="bg-muted/50 sticky top-0">
            <tr>
              <th className="px-2 py-1 text-left">Action</th>
              <th className="px-2 py-1 text-left">Kind</th>
              <th className="px-2 py-1 text-left">Network</th>
              <th className="px-2 py-1 text-left">Name / Reason</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr
                key={i}
                className={cn(
                  "border-t",
                  r._class === "create" &&
                    "bg-green-50/60 dark:bg-green-900/10",
                  r._class === "update" && "bg-blue-50/60 dark:bg-blue-900/10",
                  r._class === "conflict" &&
                    "bg-amber-50/60 dark:bg-amber-900/10",
                  r._class === "error" && "bg-red-50/60 dark:bg-red-900/10",
                )}
              >
                <td className="px-2 py-1 font-mono">{r.action}</td>
                <td className="px-2 py-1">{r.kind}</td>
                <td className="px-2 py-1 font-mono">{r.network}</td>
                <td className="px-2 py-1">{r.name || r.reason || ""}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={4}
                  className="px-2 py-3 text-center text-muted-foreground"
                >
                  <FileWarning className="mr-1 inline h-3.5 w-3.5" /> No rows in
                  payload
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Badge({
  color,
  label,
}: {
  color: "green" | "blue" | "amber" | "red";
  label: string;
}) {
  const c = {
    green:
      "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
    blue: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
    amber:
      "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300",
    red: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
  }[color];
  return (
    <span className={cn("rounded-full px-2 py-0.5 font-medium", c)}>
      {label}
    </span>
  );
}

// ─── Export Button ───────────────────────────────────────────────────────────

export function ExportButton({
  scope,
  label = "Export",
}: {
  scope: { space_id?: string; block_id?: string; subnet_id?: string };
  label?: string;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [includeAddrs, setIncludeAddrs] = useState(false);

  const [error, setError] = useState<string | null>(null);

  async function run(format: "csv" | "json" | "xlsx") {
    setBusy(true);
    setError(null);
    try {
      await ipamIoApi.download({
        ...scope,
        format,
        include_addresses: includeAddrs,
      });
      setOpen(false);
    } finally {
      setBusy(false);
    }
  }

  // #82 — the tree report. This is the larger half of the issue (a whole
  // space or block as a handover document), so it has to be reachable
  // from the space/block header, not just the subnet one. Honours the
  // "include IP addresses" checkbox, which appends a scope-wide address
  // table to the PDF.
  async function runPdf() {
    setBusy(true);
    setError(null);
    try {
      await ipamIoApi.downloadPdf({
        ...scope,
        include_addresses: includeAddrs,
      });
      setOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "PDF export failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        title="Export"
      >
        <Download className="h-3.5 w-3.5" /> {label}
      </button>
      {open && (
        <div className="absolute right-0 z-40 mt-1 w-56 rounded-md border bg-background p-2 shadow-lg">
          <label className="mb-2 flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={includeAddrs}
              onChange={(e) => setIncludeAddrs(e.target.checked)}
            />
            Include IP addresses
          </label>
          <div className="space-y-1">
            {(["csv", "json", "xlsx"] as const).map((fmt) => (
              <button
                key={fmt}
                disabled={busy}
                onClick={() => run(fmt)}
                className="block w-full rounded px-2 py-1 text-left text-xs hover:bg-muted disabled:opacity-50"
              >
                Download .{fmt}
              </button>
            ))}
          </div>
          <div className="my-1 border-t" />
          <button
            disabled={busy}
            onClick={runPdf}
            title="Print-ready report of this subtree"
            className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs hover:bg-muted disabled:opacity-50"
          >
            <Printer className="h-3.5 w-3.5" />
            Print / PDF…
          </button>
          {error && (
            <p className="mt-1 px-2 text-[11px] text-destructive">{error}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Address Import Modal (subnet-scoped) ────────────────────────────────────

export function AddressImportModal({
  subnet,
  onClose,
  onCommitted,
}: {
  subnet: Subnet;
  onClose: () => void;
  onCommitted: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [strategy, setStrategy] = useState<ImportStrategy>("fail");
  const [preview, setPreview] = useState<ImportPreviewResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [committed, setCommitted] =
    useState<AddressImportCommitResponse | null>(null);

  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);

  async function handlePreview() {
    if (!file) return;
    setBusy(true);
    setError(null);
    setPreview(null);
    try {
      const result = await ipamIoApi.previewAddresses(file, {
        subnet_id: subnet.id,
        strategy,
      });
      setPreview(result);
    } catch (e) {
      const err = e as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      setError(err.response?.data?.detail ?? err.message ?? "Preview failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleCommit() {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const result = await ipamIoApi.commitAddresses(file, {
        subnet_id: subnet.id,
        strategy,
      });
      setCommitted(result);
      onCommitted();
    } catch (e) {
      const err = e as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      setError(err.response?.data?.detail ?? err.message ?? "Import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        className="flex max-h-[90vh] w-full max-w-[95vw] sm:max-w-[760px] flex-col rounded-lg bg-background shadow-xl focus:outline-none"
        style={dialogStyle}
      >
        <div
          {...dragHandleProps}
          className={cn(
            "flex items-center justify-between border-b p-4",
            dragHandleProps.className,
          )}
        >
          <h2
            {...titleProps}
            className="flex items-center gap-2 text-base font-semibold"
          >
            <Upload className="h-4 w-4" /> Import IP addresses into{" "}
            <span className="font-mono text-sm">{subnet.network}</span>
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {committed ? (
            <div className="rounded border border-green-300 bg-green-50 p-4 dark:border-green-900 dark:bg-green-900/20">
              <div className="flex items-center gap-2 font-medium text-green-800 dark:text-green-300">
                <CheckCircle2 className="h-4 w-4" /> Import complete
              </div>
              <ul className="mt-2 text-xs text-green-900 dark:text-green-200 space-y-0.5">
                <li>Created: {committed.created} addresses</li>
                <li>Updated: {committed.updated} addresses</li>
                <li>Skipped: {committed.skipped}</li>
                <li>DNS records published: {committed.dns_synced}</li>
                {committed.errors.length > 0 && (
                  <li className="mt-1 text-amber-700 dark:text-amber-400">
                    {committed.errors.length} non-fatal error
                    {committed.errors.length === 1 ? "" : "s"} — first:{" "}
                    {committed.errors[0]}
                  </li>
                )}
              </ul>
            </div>
          ) : (
            <>
              <div className="rounded border bg-muted/30 p-3 text-xs text-muted-foreground">
                <p className="mb-1 font-medium text-foreground">
                  Expected columns
                </p>
                <code className="font-mono text-[11px]">
                  address, hostname, mac_address, description, status, tags
                </code>
                <p className="mt-2">
                  <strong>address</strong> (or <strong>ip</strong>) is required;
                  anything else is optional. Unrecognised columns become custom
                  fields. All rows must fall within {subnet.network}.
                </p>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">
                  Conflict strategy
                </label>
                <select
                  value={strategy}
                  onChange={(e) =>
                    setStrategy(e.target.value as ImportStrategy)
                  }
                  className="w-full rounded border bg-background px-2 py-1 text-sm"
                >
                  <option value="fail">Fail if any IP already exists</option>
                  <option value="skip">Skip existing IPs</option>
                  <option value="overwrite">Overwrite existing IPs</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium">
                  File (CSV, JSON, or XLSX)
                </label>
                <input
                  type="file"
                  accept=".csv,.json,.xlsx,text/csv,application/json"
                  onChange={(e) => {
                    setFile(e.target.files?.[0] ?? null);
                    setPreview(null);
                  }}
                  className="w-full text-sm"
                />
              </div>

              {error && (
                <div className="flex items-start gap-2 rounded border border-red-300 bg-red-50 p-2 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-300">
                  <AlertCircle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {preview && <PreviewTable preview={preview} />}
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t p-3">
          <button
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted"
          >
            Close
          </button>
          {!committed && (
            <>
              <button
                disabled={!file || busy}
                onClick={handlePreview}
                className="rounded border bg-muted px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
              >
                {busy ? "Working…" : "Preview"}
              </button>
              <button
                disabled={!preview || busy || preview.summary.errors > 0}
                onClick={handleCommit}
                className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {busy ? "Importing…" : "Commit import"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Combined Import/Export Button (subnet-scoped) ───────────────────────────

export function SubnetImportExportButton({
  subnet,
  canImport = true,
  onCommitted,
}: {
  subnet: Subnet;
  /** #1155 — false when the caller's grants cannot write addresses here:
   *  the import entry stays listed, disabled, with the reason. Export is
   *  a read and is always offered. */
  canImport?: boolean;
  onCommitted: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [includeAddrs, setIncludeAddrs] = useState(true);
  const [showImport, setShowImport] = useState(false);

  const [error, setError] = useState<string | null>(null);

  async function download(format: "csv" | "json" | "xlsx") {
    setBusy(true);
    setError(null);
    try {
      await ipamIoApi.download({
        subnet_id: subnet.id,
        format,
        include_addresses: includeAddrs,
      });
      setOpen(false);
    } finally {
      setBusy(false);
    }
  }

  // #82 — the subnet detail report. Ignores the "include IP addresses"
  // checkbox on purpose: a subnet PDF with no addresses is a page of
  // metadata nobody asked for, so the backend always includes them here.
  async function downloadPdf() {
    setBusy(true);
    setError(null);
    try {
      await ipamIoApi.downloadPdf({ subnet_id: subnet.id });
      setOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "PDF export failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="relative">
        <button
          onClick={() => setOpen((o) => !o)}
          className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm whitespace-nowrap hover:bg-muted"
          title="Import or export IP addresses"
        >
          Import / Export
          <ChevronDown className="h-3.5 w-3.5" />
        </button>
        {open && (
          <div className="absolute right-0 z-40 mt-1 w-64 rounded-md border bg-background p-2 shadow-lg">
            <button
              onClick={() => {
                setShowImport(true);
                setOpen(false);
              }}
              className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:bg-transparent"
              {...permissionGate(
                canImport,
                "Requires write permission on this subnet or on an address set in it",
              )}
            >
              <Upload className="h-3.5 w-3.5" />
              Import IP addresses…
            </button>
            <div className="my-1 border-t" />
            <label className="mb-1 flex items-center gap-2 px-2 text-xs">
              <input
                type="checkbox"
                checked={includeAddrs}
                onChange={(e) => setIncludeAddrs(e.target.checked)}
              />
              Include IP addresses
            </label>
            <div className="space-y-0.5">
              {(["csv", "json", "xlsx"] as const).map((fmt) => (
                <button
                  key={fmt}
                  disabled={busy}
                  onClick={() => download(fmt)}
                  className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs hover:bg-muted disabled:opacity-50"
                >
                  <Download className="h-3.5 w-3.5" />
                  Export .{fmt}
                </button>
              ))}
            </div>
            <div className="my-1 border-t" />
            <button
              disabled={busy}
              onClick={downloadPdf}
              title="Print-ready report of this subnet and its addresses"
              className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs hover:bg-muted disabled:opacity-50"
            >
              <Printer className="h-3.5 w-3.5" />
              Print / PDF…
            </button>
            {error && (
              <p className="mt-1 px-2 text-[11px] text-destructive">{error}</p>
            )}
          </div>
        )}
      </div>
      {showImport && (
        <AddressImportModal
          subnet={subnet}
          onClose={() => setShowImport(false)}
          onCommitted={onCommitted}
        />
      )}
    </>
  );
}
