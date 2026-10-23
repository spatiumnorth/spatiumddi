// Fleet → Upgrade images (#2410): one table of every release and staged
// image, with grouping, filters, staged / in-use columns and a bulk
// toolbar (the ZonesTab pattern). The air-gap upload lives behind a header
// button in the shared draggable Modal.

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronUp,
  DownloadCloud,
  Loader2,
  Trash2,
  Upload,
} from "lucide-react";

import {
  applianceUpgradeImagesApi,
  formatApiError,
  type FleetArchitectures,
  type UpgradeImageChannel,
} from "@/lib/api";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { useSessionState } from "@/lib/useSessionState";
import { cn } from "@/lib/utils";
import {
  DEFAULT_FILTERS,
  DEFAULT_SORT,
  applyFilters,
  buildRows,
  bulkActions,
  canImport,
  fleetNote,
  hiddenNightlyCount,
  inUseReason,
  isInUse,
  pruneSelection,
  sortRows,
  uploadArchitectureOptions,
  type ImageFilters,
  type ImageRow,
  type SortKey,
  type SortState,
} from "@/lib/upgrade-image-rows";

const MIB = 1024 * 1024;

function fmtMiB(bytes: number | null): string {
  return bytes == null ? "—" : `${(bytes / MIB).toFixed(0)} MiB`;
}

function fmtDate(iso: string | null): string {
  return iso ? new Date(iso).toISOString().slice(0, 10) : "—";
}

const ARCH_LABEL: Record<string, string> = {
  amd64: "amd64 (x86-64)",
  arm64: "arm64 (AArch64)",
};

const CHANNEL_CLS: Record<UpgradeImageChannel, string> = {
  stable: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  prerelease: "bg-amber-500/10 text-amber-700 dark:text-amber-300",
  nightly: "bg-muted text-muted-foreground",
};

type BulkOutcome = {
  key: string;
  version: string;
  result: "deleted" | "imported" | "refused" | "not found" | "failed";
  detail?: string;
};

function httpStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } })?.response?.status;
}

export function UpgradeImagesTable() {
  const qc = useQueryClient();
  const [filters, setFilters] = useSessionState<ImageFilters>(
    "fleet.upgradeImages.filters",
    DEFAULT_FILTERS,
  );
  const [sort, setSort] = useSessionState<SortState>(
    "fleet.upgradeImages.sort",
    DEFAULT_SORT,
  );
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [showUpload, setShowUpload] = useState(false);
  // Rows queued for a delete confirmation (one row, or the bulk selection).
  const [deleteRows, setDeleteRows] = useState<ImageRow[] | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [outcomes, setOutcomes] = useState<BulkOutcome[]>([]);
  const [running, setRunning] = useState(false);
  // What a running bulk/single action is doing right now, shown above the
  // table so it is visible without scrolling to the row's Actions cell.
  const [activity, setActivity] = useState<{
    verb: "Importing" | "Deleting";
    label: string;
    index: number;
    total: number;
  } | null>(null);

  const imagesQuery = useQuery({
    queryKey: ["appliance", "upgrade-images"],
    queryFn: applianceUpgradeImagesApi.list,
    staleTime: 30_000,
  });
  // "All architectures" asks the server for the rows it would otherwise
  // filter out; the key carries the flag so the two answers do not share
  // a cache entry.
  const allArch = filters.archScope === "all";
  const availableQuery = useQuery({
    queryKey: ["appliance", "upgrade-images", "available", allArch],
    queryFn: () => applianceUpgradeImagesApi.listAvailable(allArch),
    staleTime: 60_000,
  });

  const fleet = availableQuery.data?.fleet;
  const githubReachable = availableQuery.data?.github_reachable ?? false;

  const allRows = useMemo(
    () =>
      buildRows(imagesQuery.data ?? [], availableQuery.data?.available ?? []),
    [imagesQuery.data, availableQuery.data],
  );
  const shown = useMemo(
    () => sortRows(applyFilters(allRows, filters), sort),
    [allRows, filters, sort],
  );
  const hiddenNightlies = hiddenNightlyCount(allRows, filters);

  // A filter that hides a selected row unselects it: the count below and
  // every bulk action then cover exactly the rows on screen, and a hidden
  // row cannot rejoin a later action when the filter is relaxed.
  useEffect(() => {
    setSelected((prev) => pruneSelection(prev, shown));
  }, [shown]);

  const selectedRows = shown.filter((r) => selected.has(r.key));
  const { toDelete, toImport } = bulkActions(selectedRows);
  const allShownSelected =
    shown.length > 0 && shown.every((r) => selected.has(r.key));
  const someShownSelected = shown.some((r) => selected.has(r.key));

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["appliance", "upgrade-images"] });

  function toggleAll() {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allShownSelected) shown.forEach((r) => next.delete(r.key));
      else shown.forEach((r) => next.add(r.key));
      return next;
    });
  }
  function toggleOne(key: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }
  function toggleSort(key: SortKey) {
    setSort((s) =>
      s.key === key
        ? { key, dir: s.dir === "asc" ? "desc" : "asc" }
        : { key, dir: key === "released" || key === "size" ? "desc" : "asc" },
    );
  }

  // Deletes run one at a time through the single-image endpoint so every
  // image gets its own audit row (non-negotiable #4). Refused (in use) and
  // missing rows stay selected and say why.
  async function runDeletes(rows: ImageRow[], force: boolean) {
    setRunning(true);
    const results: BulkOutcome[] = [];
    const done = new Set<string>();
    const todo = rows.filter((r) => r.staged);
    for (const [i, r] of todo.entries()) {
      setBusyKey(r.key);
      setActivity({
        verb: "Deleting",
        label: `${r.version} (${r.architecture ?? "unknown"})`,
        index: i + 1,
        total: todo.length,
      });
      const staged = r.staged;
      if (!staged) continue;
      try {
        await applianceUpgradeImagesApi.remove(staged.id, force);
        results.push({ key: r.key, version: r.version, result: "deleted" });
        done.add(r.key);
      } catch (err) {
        const st = httpStatus(err);
        results.push({
          key: r.key,
          version: r.version,
          result: st === 409 ? "refused" : st === 404 ? "not found" : "failed",
          detail: formatApiError(err),
        });
        // Gone already is as good as deleted for selection purposes.
        if (st === 404) done.add(r.key);
      }
    }
    setBusyKey(null);
    setActivity(null);
    setRunning(false);
    setSelected((prev) => {
      const next = new Set(prev);
      done.forEach((k) => next.delete(k));
      return next;
    });
    setOutcomes(results);
    setDeleteRows(null);
    invalidate();
  }

  // Imports are minutes-long downloads, so they run strictly in sequence.
  async function runImports(rows: ImageRow[]) {
    setRunning(true);
    const results: BulkOutcome[] = [];
    const done = new Set<string>();
    const todo = rows.filter((r) => r.available);
    for (const [i, r] of todo.entries()) {
      setBusyKey(r.key);
      setActivity({
        verb: "Importing",
        label: `${r.version} (${r.architecture ?? "unknown"})`,
        index: i + 1,
        total: todo.length,
      });
      const av = r.available;
      if (!av) continue;
      try {
        await applianceUpgradeImagesApi.importFromGithub(
          av.tag,
          av.architecture,
        );
        results.push({ key: r.key, version: r.version, result: "imported" });
        done.add(r.key);
      } catch (err) {
        results.push({
          key: r.key,
          version: r.version,
          result: "failed",
          detail: formatApiError(err),
        });
      }
    }
    setBusyKey(null);
    setActivity(null);
    setRunning(false);
    setSelected((prev) => {
      const next = new Set(prev);
      done.forEach((k) => next.delete(k));
      return next;
    });
    setOutcomes(results);
    invalidate();
  }

  const loading = imagesQuery.isLoading || availableQuery.isLoading;
  const sortIcon = (key: SortKey) =>
    sort.key !== key ? null : sort.dir === "asc" ? (
      <ChevronUp className="inline h-3 w-3" />
    ) : (
      <ChevronDown className="inline h-3 w-3" />
    );
  const th = (key: SortKey, label: string) => (
    <th className="py-1.5 pr-2 font-medium">
      <button
        type="button"
        onClick={() => toggleSort(key)}
        className="inline-flex items-center gap-0.5 uppercase tracking-wider hover:text-foreground"
      >
        {label}
        {sortIcon(key)}
      </button>
    </th>
  );
  const chip = (active: boolean) =>
    cn(
      "rounded-md border px-2 py-1 text-xs hover:bg-accent",
      active && "border-primary bg-primary/10 text-primary",
    );

  return (
    <div className="space-y-3 text-xs">
      <p className="text-muted-foreground">
        Stage an appliance OS upgrade image: connected installs import it
        straight from a GitHub release (the control plane downloads and verifies
        it), air-gapped installs upload the <code>.raw.xz</code> and its{" "}
        <code>.sha256</code> out-of-band. The backend verifies the SHA-256
        before storing, and an appliance pulls through the control plane via an
        authenticated internal URL when an OS upgrade is scheduled.
      </p>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <button
            type="button"
            className={chip(filters.archScope === "fleet")}
            onClick={() =>
              setFilters((f) => ({
                ...f,
                archScope: f.archScope === "fleet" ? "all" : "fleet",
              }))
            }
            title={fleetNote(fleet)}
          >
            {filters.archScope === "fleet"
              ? "This fleet's architecture"
              : "All architectures"}
          </button>
          <button
            type="button"
            className={chip(filters.showNightly)}
            onClick={() =>
              setFilters((f) => ({ ...f, showNightly: !f.showNightly }))
            }
          >
            {filters.showNightly
              ? "Nightlies shown"
              : `Nightlies (${hiddenNightlies} hidden)`}
          </button>
          <select
            value={filters.staged}
            onChange={(e) =>
              setFilters((f) => ({
                ...f,
                staged: e.target.value as ImageFilters["staged"],
              }))
            }
            aria-label="Staged filter"
            className="rounded-md border bg-background px-2 py-1"
          >
            <option value="any">Staged or not</option>
            <option value="staged">Staged only</option>
            <option value="unstaged">Not staged</option>
          </select>
          <input
            value={filters.text}
            onChange={(e) =>
              setFilters((f) => ({ ...f, text: e.target.value }))
            }
            placeholder="Filter version…"
            aria-label="Filter by version"
            className="w-40 min-w-0 rounded-md border bg-background px-2 py-1"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {selectedRows.length > 0 && (
            <>
              <span className="text-primary">
                {selectedRows.length} selected
                {(toDelete.length > 0 || toImport.length > 0) &&
                  ` (${toDelete.length} staged, ${toImport.length} to import)`}
              </span>
              {toImport.length > 0 && (
                <button
                  type="button"
                  disabled={running}
                  onClick={() => runImports(toImport)}
                  className="flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-2 py-1 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <DownloadCloud className="h-3 w-3" /> Import {toImport.length}
                </button>
              )}
              {toDelete.length > 0 && (
                <button
                  type="button"
                  disabled={running}
                  onClick={() => setDeleteRows(toDelete)}
                  className="flex items-center gap-1 rounded-md bg-destructive px-2 py-1 text-destructive-foreground hover:bg-destructive/90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Trash2 className="h-3 w-3" /> Delete {toDelete.length}
                </button>
              )}
              <button
                type="button"
                onClick={() => setSelected(new Set())}
                className="rounded-md border px-2 py-1 hover:bg-accent"
              >
                Clear
              </button>
              <span className="h-4 w-px bg-border" />
            </>
          )}
          <HeaderButton
            variant="secondary"
            icon={Upload}
            onClick={() => setShowUpload(true)}
          >
            Upload image…
          </HeaderButton>
        </div>
      </div>

      {fleet && (
        <p className="text-[11px] text-muted-foreground">{fleetNote(fleet)}</p>
      )}
      {!availableQuery.isLoading && !githubReachable && (
        <p className="text-[11px] text-muted-foreground">
          GitHub isn&apos;t reachable from the control plane, so only staged
          images are listed. Use <strong>Upload image…</strong> for an air-gap
          copy.
        </p>
      )}

      {activity && (
        <div
          className="flex min-w-0 flex-wrap items-center gap-2 rounded-md border border-primary/40 bg-primary/5 p-2"
          role="status"
        >
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
          <span className="min-w-0 break-all font-medium">
            {activity.verb} {activity.label}
          </span>
          {activity.total > 1 && (
            <span className="text-muted-foreground">
              {activity.index} of {activity.total}
            </span>
          )}
          {activity.verb === "Importing" && (
            <span className="text-muted-foreground">
              Downloading and verifying on the control plane; this can take
              several minutes.
            </span>
          )}
        </div>
      )}

      {outcomes.length > 0 && (
        <div className="rounded-md border p-2" role="status">
          <div className="mb-1 flex items-center justify-between">
            <span className="font-medium">
              {
                outcomes.filter(
                  (o) => o.result === "deleted" || o.result === "imported",
                ).length
              }{" "}
              of {outcomes.length} succeeded
            </span>
            <button
              type="button"
              onClick={() => setOutcomes([])}
              className="text-muted-foreground hover:text-foreground"
            >
              Dismiss
            </button>
          </div>
          <ul className="space-y-0.5">
            {outcomes.map((o) => (
              <li
                key={o.key}
                className={cn(
                  o.result === "deleted" || o.result === "imported"
                    ? "text-muted-foreground"
                    : "text-rose-700 dark:text-rose-300",
                )}
              >
                <span className="font-mono">{o.version}</span>: {o.result}
                {o.detail && o.result !== "deleted" && o.result !== "imported"
                  ? ` — ${o.detail}`
                  : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
        </div>
      ) : shown.length === 0 ? (
        <p className="italic text-muted-foreground">
          {allRows.length === 0
            ? "No upgrade images yet."
            : "No images match the current filters."}
        </p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full min-w-[900px] text-xs">
            <thead>
              <tr className="border-b bg-muted/30 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="w-8 px-2 py-1.5">
                  <input
                    type="checkbox"
                    checked={allShownSelected}
                    ref={(el) => {
                      if (el)
                        el.indeterminate =
                          someShownSelected && !allShownSelected;
                    }}
                    onChange={toggleAll}
                    aria-label="Select all filtered images"
                  />
                </th>
                {th("version", "Version")}
                {th("arch", "Arch")}
                {th("channel", "Channel")}
                {th("released", "Released")}
                {th("size", "Size")}
                {th("staged", "Staged")}
                <th className="py-1.5 pr-2 font-medium">Fleet</th>
                <th className="py-1.5 pr-2 font-medium">In use</th>
                <th className="sticky right-0 bg-muted py-1.5 pl-2 pr-2 text-right font-medium">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {shown.map((r) => (
                <ImageTableRow
                  key={r.key}
                  row={r}
                  selected={selected.has(r.key)}
                  busy={busyKey === r.key}
                  disabled={running}
                  expanded={expanded.has(r.key)}
                  onToggleSelect={() => toggleOne(r.key)}
                  onToggleExpand={() =>
                    setExpanded((prev) => {
                      const next = new Set(prev);
                      if (next.has(r.key)) next.delete(r.key);
                      else next.add(r.key);
                      return next;
                    })
                  }
                  onImport={() => runImports([r])}
                  onDelete={() => setDeleteRows([r])}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {deleteRows && (
        <DeleteImagesModal
          rows={deleteRows}
          running={running}
          onConfirm={(force) => runDeletes(deleteRows, force)}
          onClose={() => setDeleteRows(null)}
        />
      )}
      {showUpload && (
        <UploadImageModal
          fleet={fleet}
          onClose={() => setShowUpload(false)}
          onUploaded={() => {
            invalidate();
            setShowUpload(false);
          }}
        />
      )}
    </div>
  );
}

function ImageTableRow({
  row: r,
  selected,
  busy,
  disabled,
  expanded,
  onToggleSelect,
  onToggleExpand,
  onImport,
  onDelete,
}: {
  row: ImageRow;
  selected: boolean;
  busy: boolean;
  disabled: boolean;
  expanded: boolean;
  onToggleSelect: () => void;
  onToggleExpand: () => void;
  onImport: () => void;
  onDelete: () => void;
}) {
  const notes = r.staged?.notes || r.available?.body || "";
  return (
    <>
      <tr className={cn(selected && "bg-primary/5")}>
        <td className="px-2 py-1">
          <input
            type="checkbox"
            checked={selected}
            onChange={onToggleSelect}
            aria-label={`Select ${r.version} ${r.architecture ?? "unknown"}`}
          />
        </td>
        <td className="min-w-0 py-1 pr-2">
          {r.htmlUrl ? (
            <a
              href={r.htmlUrl}
              target="_blank"
              rel="noreferrer"
              className="break-all font-mono hover:underline"
            >
              {r.version}
            </a>
          ) : (
            <span className="break-all font-mono">{r.version}</span>
          )}
          {r.isControlPlane && (
            <span
              className="ml-1 rounded bg-primary/10 px-1 text-[10px] text-primary"
              title="The control plane itself runs this version"
            >
              control plane
            </span>
          )}
        </td>
        <td className="py-1 pr-2 font-mono">
          {r.architecture ?? (
            <span className="text-muted-foreground">unknown</span>
          )}
        </td>
        <td className="py-1 pr-2">
          <span
            className={cn(
              "rounded px-1.5 py-0.5 text-[10px]",
              CHANNEL_CLS[r.channel],
            )}
          >
            {r.channel === "prerelease" ? "pre-release" : r.channel}
          </span>
        </td>
        <td className="py-1 pr-2">{fmtDate(r.publishedAt)}</td>
        <td className="py-1 pr-2 font-mono">{fmtMiB(r.sizeBytes)}</td>
        <td className="py-1 pr-2">
          {r.staged ? (
            <div>
              <span className="text-emerald-700 dark:text-emerald-300">
                yes
              </span>{" "}
              <span className="text-muted-foreground">
                {fmtDate(r.staged.uploaded_at)}
              </span>
              <div className="break-all font-mono text-[10px] text-muted-foreground">
                {r.staged.sha256.slice(0, 12)}…{r.staged.sha256.slice(-6)}
              </div>
            </div>
          ) : (
            <span className="text-muted-foreground">no</span>
          )}
        </td>
        <td className="py-1 pr-2">
          {r.fleet === "matches" ? (
            <span>
              {r.fleetNodes} node{r.fleetNodes === 1 ? "" : "s"}
            </span>
          ) : r.fleet === "no_node" ? (
            <span className="text-amber-700 dark:text-amber-300">
              no node runs this
            </span>
          ) : (
            <span className="text-muted-foreground">unknown</span>
          )}
        </td>
        <td className="py-1 pr-2">
          {r.installedOn.length > 0 && (
            <div className="break-words">
              installed on {r.installedOn.join(", ")}
            </div>
          )}
          {r.scheduledFor.length > 0 && (
            <div className="break-words text-amber-700 dark:text-amber-300">
              scheduled for {r.scheduledFor.join(", ")}
            </div>
          )}
          {r.rollingRunId && (
            <div className="break-all text-amber-700 dark:text-amber-300">
              rolling run {r.rollingRunId.slice(0, 8)}
            </div>
          )}
        </td>
        <td className="sticky right-0 bg-background py-1 pl-2 pr-2 text-right">
          <div className="flex flex-wrap justify-end gap-1">
            {!r.staged && r.available && (
              <button
                type="button"
                onClick={onImport}
                disabled={disabled || !canImport(r)}
                title={
                  r.fleet === "no_node"
                    ? "No approved appliance runs this architecture"
                    : "Download and verify on the control plane"
                }
                className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-2 py-0.5 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <DownloadCloud className="h-3 w-3" />
                )}
                Import
              </button>
            )}
            {r.staged && (
              <button
                type="button"
                onClick={onDelete}
                disabled={disabled}
                className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-0.5 hover:bg-muted disabled:opacity-50"
              >
                {busy ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Trash2 className="h-3 w-3" />
                )}
                Delete
              </button>
            )}
            {notes && (
              <button
                type="button"
                onClick={onToggleExpand}
                className="rounded-md border bg-background px-2 py-0.5 hover:bg-muted"
              >
                Notes
              </button>
            )}
          </div>
        </td>
      </tr>
      {expanded && notes && (
        <tr className="bg-muted/20">
          <td />
          <td colSpan={9} className="py-1.5 pr-2">
            <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words text-[11px] text-muted-foreground">
              {notes}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

function DeleteImagesModal({
  rows,
  running,
  onConfirm,
  onClose,
}: {
  rows: ImageRow[];
  running: boolean;
  onConfirm: (force: boolean) => void;
  onClose: () => void;
}) {
  const totalBytes = rows.reduce((n, r) => n + (r.sizeBytes ?? 0), 0);
  const inUse = rows.filter(isInUse);
  const installed = rows.filter((r) => r.installedOn.length > 0);
  // A single in-use image can be force-deleted after an explicit tick (an
  // operator who already cancelled the upgrade on the host). In a bulk
  // delete the in-use rows are simply refused and reported.
  const single = rows.length === 1;
  return (
    <ConfirmModal
      open
      title={single ? "Delete upgrade image?" : `Delete ${rows.length} images?`}
      message={
        <>
          <p className="text-sm">
            Removes the on-server copy of{" "}
            {rows.length === 1 ? "this image" : `these ${rows.length} images`} (
            {fmtMiB(totalBytes)} in total). Re-staging means another download or
            upload.
          </p>
          <ul className="mt-2 max-h-40 space-y-0.5 overflow-auto text-xs">
            {rows.map((r) => (
              <li key={r.key} className="break-all">
                <span className="font-mono text-foreground">{r.version}</span>{" "}
                {r.architecture ?? "unknown"} · {fmtMiB(r.sizeBytes)}
                {isInUse(r) && (
                  <span className="text-rose-700 dark:text-rose-300">
                    {" "}
                    — in use: {inUseReason(r)}
                  </span>
                )}
              </li>
            ))}
          </ul>
          {inUse.length > 0 && (
            <p className="mt-2 text-xs text-rose-700 dark:text-rose-300">
              {single
                ? "An appliance will 404 on its next fetch of this image. Tick the box below only if the upgrade has already been cancelled on the host."
                : `${inUse.length} in-use image${inUse.length === 1 ? " is" : "s are"} refused by the server and stay selected.`}
            </p>
          )}
          {installed.length > 0 && (
            <p className="mt-2 text-xs text-muted-foreground">
              {installed.length} installed on a slot already — the bytes are
              written, so deleting is fine.
            </p>
          )}
        </>
      }
      confirmLabel={single ? "Delete" : `Delete ${rows.length}`}
      tone="destructive"
      loading={running}
      requireCheckboxLabel={
        single && inUse.length > 0
          ? "Delete it anyway (the upgrade is already cancelled)"
          : undefined
      }
      onConfirm={() => onConfirm(single && inUse.length > 0)}
      onClose={onClose}
    />
  );
}

function UploadImageModal({
  fleet,
  onClose,
  onUploaded,
}: {
  fleet: FleetArchitectures | undefined;
  onClose: () => void;
  onUploaded: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [sha256, setSha256] = useState("");
  const [applianceVersion, setApplianceVersion] = useState("");
  // #1026 — declared, like the version beside it. Empty means UNKNOWN: the
  // control-plane gate does not block, and spatium-upgrade-slot still
  // re-checks the real image against the node's own uname before writing.
  const [architecture, setArchitecture] = useState("");
  const [notes, setNotes] = useState("");
  const [progress, setProgress] = useState<{
    loaded: number;
    total: number;
  } | null>(null);

  const upload = useMutation({
    mutationFn: () =>
      applianceUpgradeImagesApi.upload(
        file!,
        sha256.trim().toLowerCase(),
        applianceVersion.trim(),
        notes.trim() || undefined,
        (loaded, total) => setProgress({ loaded, total }),
        architecture || undefined,
      ),
    onSuccess: onUploaded,
    onError: () => setProgress(null),
  });

  return (
    <Modal title="Upload upgrade image (air-gap)" onClose={onClose} wide>
      <div className="space-y-3 text-xs">
        <div className="grid gap-2 sm:grid-cols-2">
          <div>
            <label className="text-muted-foreground">.raw.xz file</label>
            <input
              type="file"
              accept=".xz,.raw.xz,application/octet-stream"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="mt-1 block w-full text-xs"
            />
            {file && (
              <p className="mt-1 text-[11px] text-muted-foreground">
                {file.name} · {(file.size / MIB).toFixed(1)} MiB
              </p>
            )}
          </div>
          <div>
            <label className="text-muted-foreground">Appliance version</label>
            <input
              value={applianceVersion}
              onChange={(e) => setApplianceVersion(e.target.value)}
              placeholder="e.g. 2026.06.01-1"
              className="mt-1 w-full rounded-md border bg-background px-2 py-1"
            />
          </div>
          <div>
            <label className="text-muted-foreground">Architecture</label>
            <select
              value={architecture}
              onChange={(e) => setArchitecture(e.target.value)}
              className="mt-1 w-full rounded-md border bg-background px-2 py-1"
            >
              <option value="">Unknown (don&apos;t check)</option>
              {uploadArchitectureOptions(fleet).map((a) => (
                <option key={a} value={a}>
                  {ARCH_LABEL[a] ?? a}
                </option>
              ))}
            </select>
            <p className="mt-1 text-[11px] text-muted-foreground">
              From the asset name you downloaded.{" "}
              {fleet?.restricted
                ? `Only ${fleet.architectures.join(" and ")} ${fleet.architectures.length === 1 ? "is" : "are"} offered: no approved appliance runs anything else, and the server would refuse it after the upload. `
                : ""}
              The control plane also refuses an upgrade for a node of the other
              architecture; the appliance re-checks the real image either way.
            </p>
          </div>
          <div className="sm:col-span-2">
            <label className="text-muted-foreground">SHA-256 (hex)</label>
            <input
              value={sha256}
              onChange={(e) => setSha256(e.target.value)}
              placeholder="paste from the .sha256 sidecar (64 lowercase hex chars)"
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono"
            />
          </div>
          <div className="sm:col-span-2">
            <label className="text-muted-foreground">Notes (optional)</label>
            <input
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="e.g. RC1 — verified by ops on 2026-06-01"
              className="mt-1 w-full rounded-md border bg-background px-2 py-1"
            />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => upload.mutate()}
            disabled={
              !file ||
              sha256.trim().length !== 64 ||
              !applianceVersion.trim() ||
              upload.isPending
            }
            className="inline-flex items-center gap-1 rounded-md border border-primary bg-primary/10 px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {upload.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Upload className="h-3.5 w-3.5" />
            )}
            Upload
          </button>
          {progress && progress.total > 0 && (
            <span className="text-[11px] text-muted-foreground">
              {((progress.loaded / progress.total) * 100).toFixed(0)}% ·{" "}
              {(progress.loaded / MIB).toFixed(1)} /{" "}
              {(progress.total / MIB).toFixed(1)} MiB
            </span>
          )}
          {upload.error && (
            <span className="text-rose-700 dark:text-rose-300">
              {formatApiError(upload.error)}
            </span>
          )}
        </div>
      </div>
    </Modal>
  );
}
