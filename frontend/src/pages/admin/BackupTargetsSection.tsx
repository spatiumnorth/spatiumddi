import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  Loader2,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ServerCrash,
  Trash2,
  Wifi,
  X,
} from "lucide-react";

import {
  backupTargetsApi,
  type BackupArchiveListing,
  type BackupTarget,
  type BackupTargetCreate,
  type BackupTargetKind,
  type BackupTargetUpdate,
} from "@/lib/api";
import { useModalDialog } from "@/components/ui/use-draggable-modal";
import { BackupSectionsPicker } from "./BackupSectionsPicker";

/**
 * Backup Targets section on the Backup admin page (issue #117
 * Phase 1b). Lists configured destinations with last-run state +
 * next-run schedule, plus per-row Run / Test / Edit / Delete and
 * a per-row Archives drawer that lists what's currently stored.
 *
 * The kind picker reflects on ``GET /backup/targets/kinds`` so
 * any new driver (Tier 1 local/S3/SCP/Azure, Tier 2 SMB/FTP/GCS,
 * future kinds) appears without frontend changes once
 * registered server-side.
 */

// Friendly preset list for the schedule dropdown. UTC times so
// operators don't have to think about TZ when they pick "daily
// at 02:00". Same expressions croniter parses on the backend.
const CRON_PRESETS: { label: string; value: string }[] = [
  { label: "Hourly", value: "0 * * * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Every 12 hours", value: "0 */12 * * *" },
  { label: "Daily 02:00 UTC", value: "0 2 * * *" },
  { label: "Daily 04:00 UTC", value: "0 4 * * *" },
  { label: "Weekly Sunday 03:00 UTC", value: "0 3 * * 0" },
  { label: "Monthly 1st 03:00 UTC", value: "0 3 1 * *" },
];

export function BackupTargetsSection() {
  const qc = useQueryClient();
  const targetsQ = useQuery({
    queryKey: ["backup-targets"],
    queryFn: backupTargetsApi.list,
  });
  const [editing, setEditing] = useState<
    { mode: "create" } | { mode: "edit"; target: BackupTarget } | null
  >(null);

  return (
    <section className="rounded-lg border bg-card p-5">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">Scheduled targets</h2>
          <p className="text-xs text-muted-foreground">
            Build backups on a cron schedule + write them to a local volume.
            Operators add S3 / SCP / Azure destinations once those drivers ship.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setEditing({ mode: "create" })}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-3.5 w-3.5" />
          Add target
        </button>
      </div>

      {targetsQ.isLoading ? (
        <div className="rounded-md border border-dashed px-3 py-4 text-center text-xs text-muted-foreground">
          <Loader2 className="mr-1 inline h-3.5 w-3.5 animate-spin" />
          Loading…
        </div>
      ) : targetsQ.isError ? (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          Failed to load backup targets.
        </div>
      ) : (targetsQ.data ?? []).length === 0 ? (
        <div className="rounded-md border border-dashed px-3 py-4 text-center text-xs text-muted-foreground">
          No backup targets configured. Click <strong>Add target</strong> to
          schedule a recurring backup to a local volume.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {(targetsQ.data ?? []).map((t) => (
            <TargetRow
              key={t.id}
              target={t}
              onEdit={() => setEditing({ mode: "edit", target: t })}
              onAfterChange={() =>
                qc.invalidateQueries({ queryKey: ["backup-targets"] })
              }
            />
          ))}
        </div>
      )}

      {editing && (
        <TargetFormModal
          mode={editing.mode}
          existing={editing.mode === "edit" ? editing.target : undefined}
          onClose={() => setEditing(null)}
          onSaved={() => {
            qc.invalidateQueries({ queryKey: ["backup-targets"] });
            setEditing(null);
          }}
        />
      )}
    </section>
  );
}

// ── Target row ─────────────────────────────────────────────────────────

function TargetRow({
  target,
  onEdit,
  onAfterChange,
}: {
  target: BackupTarget;
  onEdit: () => void;
  onAfterChange: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const runMut = useMutation({
    mutationFn: () => backupTargetsApi.runNow(target.id),
    onSettled: onAfterChange,
  });
  const testMut = useMutation({
    mutationFn: () => backupTargetsApi.test(target.id),
  });
  const deleteMut = useMutation({
    mutationFn: () => backupTargetsApi.remove(target.id),
    onSuccess: onAfterChange,
  });

  return (
    <div className="rounded-md border">
      <div className="flex items-center gap-2 px-3 py-2">
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="rounded p-1 hover:bg-accent"
          title={expanded ? "Collapse" : "Expand archives"}
        >
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-medium">{target.name}</span>
            <KindBadge kind={target.kind} />
            {!target.enabled && <DisabledBadge />}
            <StatusBadge status={target.last_run_status} />
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-[11px] text-muted-foreground">
            {target.schedule_cron ? (
              <span>
                schedule:{" "}
                <code className="font-mono">{target.schedule_cron}</code>
              </span>
            ) : (
              <span className="opacity-70">manual only</span>
            )}
            {target.next_run_at && target.enabled && target.schedule_cron && (
              <span>next: {new Date(target.next_run_at).toLocaleString()}</span>
            )}
            {target.last_run_at && (
              <span>
                last: {new Date(target.last_run_at).toLocaleString()}{" "}
                {target.last_run_filename && (
                  <code className="font-mono">
                    (
                    {(target.last_run_bytes ?? 0) / 1024 / 1024 < 1
                      ? `${target.last_run_bytes} B`
                      : `${((target.last_run_bytes ?? 0) / 1024 / 1024).toFixed(
                          2,
                        )} MB`}
                    )
                  </code>
                )}
              </span>
            )}
            {target.retention_keep_last_n != null && (
              <span>retain: last {target.retention_keep_last_n}</span>
            )}
            {target.retention_keep_days != null && (
              <span>retain: {target.retention_keep_days} d</span>
            )}
            {target.write_only && (
              <span
                className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 text-emerald-700 dark:text-emerald-300"
                title="SpatiumDDI writes archives here but never deletes them. Retention is the destination's own policy, and restore drills cannot verify it from this side."
              >
                write-only
              </span>
            )}
          </div>
          {target.last_run_error && (
            <div className="mt-1 line-clamp-2 text-[11px] text-destructive">
              {target.last_run_error}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
          <IconButton
            title="Run now"
            icon={
              runMut.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Play className="h-3.5 w-3.5" />
              )
            }
            onClick={() => runMut.mutate()}
            disabled={!target.enabled || runMut.isPending}
          />
          <IconButton
            title="Test connection"
            icon={
              testMut.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Wifi className="h-3.5 w-3.5" />
              )
            }
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending}
          />
          <IconButton
            title="Edit"
            icon={<Pencil className="h-3.5 w-3.5" />}
            onClick={onEdit}
          />
          <IconButton
            title="Delete"
            icon={<Trash2 className="h-3.5 w-3.5 text-destructive" />}
            onClick={() => {
              if (
                confirm(
                  `Delete target "${target.name}"? Archives stored at the destination are NOT deleted.`,
                )
              ) {
                deleteMut.mutate();
              }
            }}
          />
        </div>
      </div>
      {testMut.data && (
        <div
          className={`border-t px-3 py-1.5 text-xs ${
            testMut.data.ok
              ? "bg-emerald-500/5 text-emerald-700 dark:text-emerald-300"
              : "bg-destructive/5 text-destructive"
          }`}
        >
          {testMut.data.ok ? (
            <>
              <CheckCircle2 className="mr-1 inline h-3.5 w-3.5" />
              {testMut.data.detail || "ok"}
            </>
          ) : (
            <>
              <ServerCrash className="mr-1 inline h-3.5 w-3.5" />
              {testMut.data.error || "failed"}
            </>
          )}
        </div>
      )}
      {runMut.data && (
        <div
          className={`border-t px-3 py-1.5 text-xs ${
            runMut.data.success
              ? "bg-emerald-500/5 text-emerald-700 dark:text-emerald-300"
              : "bg-destructive/5 text-destructive"
          }`}
        >
          {runMut.data.success ? (
            <>
              <CheckCircle2 className="mr-1 inline h-3.5 w-3.5" />
              wrote <code className="font-mono">{runMut.data.filename}</code>
              {runMut.data.bytes != null && (
                <>
                  {" — "}
                  {(runMut.data.bytes / 1024 / 1024).toFixed(2)} MB in{" "}
                  {runMut.data.duration_ms} ms
                </>
              )}
              {runMut.data.deleted > 0 && (
                <> — pruned {runMut.data.deleted} per retention</>
              )}
            </>
          ) : (
            <>
              <ServerCrash className="mr-1 inline h-3.5 w-3.5" />
              {runMut.data.error || "failed"}
            </>
          )}
        </div>
      )}
      {expanded && (
        <ArchiveList targetId={target.id} onAfterChange={onAfterChange} />
      )}
    </div>
  );
}

function ArchiveList({
  targetId,
  onAfterChange,
}: {
  targetId: string;
  onAfterChange: () => void;
}) {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["backup-target-archives", targetId],
    queryFn: () => backupTargetsApi.listArchives(targetId),
  });
  const deleteMut = useMutation({
    mutationFn: (filename: string) =>
      backupTargetsApi.deleteArchive(targetId, filename),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["backup-target-archives", targetId],
      });
      onAfterChange();
    },
  });
  // Download streams the archive bytes through the api (which
  // proxies the destination's ``download(filename)``) so operators
  // never need direct credentials for the underlying S3 / SCP /
  // Azure account.
  const downloadMut = useMutation({
    mutationFn: (filename: string) =>
      backupTargetsApi.downloadArchive(targetId, filename),
  });
  const [restoring, setRestoring] = useState<string | null>(null);

  return (
    <div className="border-t bg-muted/30 px-3 py-2 text-xs">
      <div className="mb-1 flex items-center justify-between">
        <span className="font-medium">Archives at destination</span>
        <button
          type="button"
          onClick={() =>
            qc.invalidateQueries({
              queryKey: ["backup-target-archives", targetId],
            })
          }
          className="rounded p-1 hover:bg-accent"
          title="Refresh"
        >
          <RefreshCw
            className={`h-3 w-3 ${q.isFetching ? "animate-spin" : ""}`}
          />
        </button>
      </div>
      {q.isLoading ? (
        <div className="text-muted-foreground">
          <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />
          Loading…
        </div>
      ) : q.isError ? (
        <div className="text-destructive">
          {(q.error as Error)?.message || "failed to list"}
        </div>
      ) : (q.data ?? []).length === 0 ? (
        <div className="text-muted-foreground">
          No archives at this destination yet.
        </div>
      ) : (
        <ul className="space-y-1">
          {(q.data ?? []).map((a: BackupArchiveListing) => (
            <li
              key={a.filename}
              className="flex items-center gap-2 rounded border bg-background px-2 py-1"
            >
              <code className="flex-1 truncate font-mono">{a.filename}</code>
              <span className="text-muted-foreground">
                {(a.size_bytes / 1024 / 1024).toFixed(2)} MB
              </span>
              <span className="text-muted-foreground">
                {new Date(a.created_at).toLocaleString()}
              </span>
              <button
                type="button"
                onClick={() => downloadMut.mutate(a.filename)}
                disabled={
                  downloadMut.isPending && downloadMut.variables === a.filename
                }
                title="Download to your computer"
                className="rounded p-1 hover:bg-accent disabled:opacity-50"
              >
                {downloadMut.isPending &&
                downloadMut.variables === a.filename ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Download className="h-3 w-3" />
                )}
              </button>
              <button
                type="button"
                onClick={() => setRestoring(a.filename)}
                title="Restore from this archive"
                className="rounded p-1 hover:bg-primary/10"
              >
                <RefreshCw className="h-3 w-3 text-primary" />
              </button>
              <button
                type="button"
                onClick={() => {
                  if (confirm(`Delete archive ${a.filename}?`)) {
                    deleteMut.mutate(a.filename);
                  }
                }}
                title="Delete"
                className="rounded p-1 hover:bg-destructive/10"
              >
                <Trash2 className="h-3 w-3 text-destructive" />
              </button>
            </li>
          ))}
        </ul>
      )}
      {restoring && (
        <RestoreFromArchiveModal
          targetId={targetId}
          filename={restoring}
          onClose={() => setRestoring(null)}
          onSuccess={() => {
            setRestoring(null);
            onAfterChange();
          }}
        />
      )}
    </div>
  );
}

function RestoreFromArchiveModal({
  targetId,
  filename,
  onClose,
  onSuccess,
}: {
  targetId: string;
  filename: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [mode, setMode] = useState<"full" | "selective">("full");
  const [sections, setSections] = useState<string[]>([]);
  const restoreMut = useMutation({
    mutationFn: () =>
      backupTargetsApi.restoreFromArchive(targetId, {
        filename,
        passphrase,
        confirmation_phrase: confirm,
        sections: mode === "selective" ? sections : null,
      }),
    onSuccess,
  });

  const canSubmit =
    passphrase.length >= 8 &&
    confirm === "RESTORE-FROM-BACKUP" &&
    !restoreMut.isPending &&
    (mode !== "selective" || sections.length > 0);

  const { dialogProps, titleProps } = useModalDialog(onClose);

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/30 text-sm">
      <div
        {...dialogProps}
        className="max-h-[90vh] w-full max-w-lg overflow-auto rounded-lg border bg-card p-5 shadow-lg focus:outline-none"
      >
        <div className="mb-3 flex items-center gap-2">
          <RefreshCw className="h-4 w-4 text-primary" />
          <h3 {...titleProps} className="font-semibold">
            Restore from archive
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="ml-auto rounded p-1 text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          {mode === "full" ? (
            <>
              <strong>Hard overwrite.</strong> Every table on this install will
              be replaced with the contents of{" "}
              <code className="font-mono">{filename}</code>. A pre-restore
              safety dump runs first; nothing about the destination archive is
              changed.
            </>
          ) : (
            <>
              <strong>Selective restore.</strong> The selected sections will be
              wiped + re-loaded from{" "}
              <code className="font-mono">{filename}</code>. The rest of the
              install is left untouched (with the FK-cascade caveat in the
              section picker below).
            </>
          )}
        </div>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSubmit) restoreMut.mutate();
          }}
        >
          <BackupSectionsPicker
            mode={mode}
            onModeChange={setMode}
            selected={sections}
            onChange={setSections}
          />
          <Field label="Passphrase" required>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              autoComplete="off"
              autoFocus
            />
          </Field>
          <Field
            label="Confirmation phrase"
            help={
              <>
                Type{" "}
                <code className="rounded bg-muted px-1 py-0.5 text-[11px]">
                  RESTORE-FROM-BACKUP
                </code>{" "}
                exactly to enable Apply.
              </>
            }
            required
          >
            <input
              type="text"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="RESTORE-FROM-BACKUP"
              className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              autoComplete="off"
            />
          </Field>
          {restoreMut.isError && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {(restoreMut.error as Error)?.message || "restore failed"}
            </div>
          )}
          {restoreMut.data && (
            <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
              Restored <code className="font-mono">{filename}</code> in{" "}
              {restoreMut.data.duration_ms} ms.
            </div>
          )}
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              className="rounded-md bg-destructive px-3 py-1.5 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
            >
              {restoreMut.isPending ? (
                <>
                  <Loader2 className="mr-1 inline h-3.5 w-3.5 animate-spin" />
                  Restoring…
                </>
              ) : (
                "Apply restore"
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Target form modal ─────────────────────────────────────────────────

function TargetFormModal({
  mode,
  existing,
  onClose,
  onSaved,
}: {
  mode: "create" | "edit";
  existing?: BackupTarget;
  onClose: () => void;
  onSaved: () => void;
}) {
  const kindsQ = useQuery({
    queryKey: ["backup-target-kinds"],
    queryFn: backupTargetsApi.listKinds,
    staleTime: 60_000,
  });

  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [kind, setKind] = useState(existing?.kind ?? "local_volume");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [config, setConfig] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      Object.entries(existing?.config ?? {}).map(([k, v]) => [k, String(v)]),
    ),
  );
  // ``existing.config`` redacts secret fields to ``"<set>"`` so
  // operators can see whether a value is configured. We don't
  // want that sentinel echoed back into a password input — it
  // looks like real text and would be sent on save (the backend's
  // merge does drop it, but better to never offer the confusion).
  // Once ``kindMeta`` loads, blank out any secret fields in the
  // form state so the input is empty + the placeholder explains
  // the merge semantics.
  const kindsData = kindsQ.data;
  useEffect(() => {
    if (!kindsData) return;
    const meta = kindsData.find((k) => k.kind === kind);
    if (!meta) return;
    const secretNames = meta.config_fields
      .filter((f) => f.secret)
      .map((f) => f.name);
    if (secretNames.length === 0) return;
    setConfig((prev) => {
      const next = { ...prev };
      let dirty = false;
      for (const name of secretNames) {
        if (next[name]) {
          next[name] = "";
          dirty = true;
        }
      }
      return dirty ? next : prev;
    });
  }, [kindsData, kind]);
  const [passphrase, setPassphrase] = useState("");
  const [passphraseHint, setPassphraseHint] = useState(
    existing?.passphrase_hint ?? "",
  );
  const [scheduleCron, setScheduleCron] = useState(
    existing?.schedule_cron ?? "",
  );
  const [retentionMode, setRetentionMode] = useState<
    "none" | "last_n" | "days"
  >(
    existing?.retention_keep_last_n != null
      ? "last_n"
      : existing?.retention_keep_days != null
        ? "days"
        : "none",
  );
  const [retentionLastN, setRetentionLastN] = useState(
    existing?.retention_keep_last_n?.toString() ?? "7",
  );
  const [retentionDays, setRetentionDays] = useState(
    existing?.retention_keep_days?.toString() ?? "30",
  );
  const [writeOnly, setWriteOnly] = useState(existing?.write_only ?? false);
  const [error, setError] = useState<string | null>(null);

  const kindMeta = useMemo<BackupTargetKind | undefined>(
    () => kindsQ.data?.find((k) => k.kind === kind),
    [kindsQ.data, kind],
  );
  // A kind with no listing and no delete is write-only whatever the
  // operator picks — the server forces it, so the form shows the real
  // resulting state rather than a choice that gets silently overridden.
  const forcedWriteOnly = kindMeta?.inherently_write_only ?? false;
  const effectiveWriteOnly = forcedWriteOnly || writeOnly;

  const saveMut = useMutation({
    mutationFn: async () => {
      const trimmedCron = scheduleCron.trim();
      const sharedFields: BackupTargetUpdate = {
        name,
        description,
        enabled,
        config,
        passphrase_hint: passphraseHint,
        schedule_cron: trimmedCron === "" ? null : trimmedCron,
        // A write-only target never prunes, and the API refuses the
        // combination outright — so the mode is forced to "none" here
        // rather than posting a number that comes back as a 422 the
        // operator has to decode.
        retention_keep_last_n:
          !effectiveWriteOnly && retentionMode === "last_n"
            ? Number(retentionLastN)
            : null,
        retention_keep_days:
          !effectiveWriteOnly && retentionMode === "days"
            ? Number(retentionDays)
            : null,
        write_only: effectiveWriteOnly,
      };
      if (mode === "create") {
        if (passphrase.length < 8) {
          throw new Error("passphrase must be at least 8 characters");
        }
        const body: BackupTargetCreate = {
          ...sharedFields,
          kind,
          passphrase,
        } as BackupTargetCreate;
        return backupTargetsApi.create(body);
      }
      const body: BackupTargetUpdate = { ...sharedFields };
      if (passphrase.length > 0) {
        if (passphrase.length < 8) {
          throw new Error("passphrase must be at least 8 characters");
        }
        body.passphrase = passphrase;
      }
      return backupTargetsApi.update(existing!.id, body);
    },
    onSuccess: onSaved,
    onError: (err: Error) => setError(err.message || "save failed"),
  });

  const { dialogProps, titleProps } = useModalDialog(onClose);

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/30">
      <div
        {...dialogProps}
        className="max-h-[90vh] w-full max-w-lg overflow-auto rounded-lg border bg-card p-5 shadow-lg focus:outline-none"
      >
        <div className="mb-3 flex items-center justify-between gap-2">
          <h3 {...titleProps} className="text-sm font-semibold">
            {mode === "create"
              ? "Add backup target"
              : `Edit "${existing!.name}"`}
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded p-1 text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            setError(null);
            saveMut.mutate();
          }}
          className="space-y-3"
        >
          <Field label="Name" required>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              autoFocus
            />
          </Field>
          <Field label="Description">
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </Field>
          {mode === "create" && (
            <Field label="Destination kind" required>
              <select
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value);
                  setConfig({});
                }}
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                {(kindsQ.data ?? []).map((k) => (
                  <option key={k.kind} value={k.kind}>
                    {k.label} ({k.kind})
                  </option>
                ))}
              </select>
            </Field>
          )}

          {kindMeta?.config_fields.map((f) => {
            // A ``notice`` field is prose that belongs to the destination
            // kind rather than to any one input — NFS's "AUTH_SYS has no
            // credential at all", for instance. Rendering it through the
            // branch below would give the operator a text box whose value
            // is then posted into ``config`` and rejected by the driver's
            // validator, so it gets its own no-input shape.
            if (f.type === "notice") {
              return (
                <div
                  key={f.name}
                  className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-200"
                >
                  <div className="font-medium">{f.label}</div>
                  {f.description && <p className="mt-0.5">{f.description}</p>}
                </div>
              );
            }
            const isSecretInEdit = f.secret && mode === "edit";
            return (
              <Field
                key={f.name}
                label={f.label}
                required={f.required && !isSecretInEdit}
                help={f.description}
              >
                <input
                  type={f.type === "password" || f.secret ? "password" : "text"}
                  value={config[f.name] ?? ""}
                  onChange={(e) =>
                    setConfig({ ...config, [f.name]: e.target.value })
                  }
                  placeholder={
                    isSecretInEdit
                      ? "(set — leave empty to keep, type to replace)"
                      : undefined
                  }
                  autoComplete={f.secret ? "new-password" : undefined}
                  className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </Field>
            );
          })}

          <Field
            label={mode === "create" ? "Passphrase" : "Passphrase (optional)"}
            required={mode === "create"}
            help={
              mode === "edit"
                ? "Leave empty to keep the existing passphrase. Min 8 chars to rotate."
                : "Min 8 chars. Same passphrase you'd use for a manual backup — required for restore."
            }
          >
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </Field>
          <Field label="Passphrase hint">
            <input
              type="text"
              value={passphraseHint}
              onChange={(e) => setPassphraseHint(e.target.value)}
              maxLength={200}
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="e.g. corp-vault-2026"
            />
          </Field>

          <Field
            label="Schedule (cron, UTC)"
            help={
              <>
                5-field UTC cron expression — pick a preset or type your own.
                Leave blank for manual-only.
              </>
            }
          >
            <div className="space-y-1.5">
              <select
                value={
                  CRON_PRESETS.find((p) => p.value === scheduleCron)?.value ??
                  (scheduleCron ? "__custom__" : "")
                }
                onChange={(e) => {
                  if (e.target.value === "__custom__") return;
                  setScheduleCron(e.target.value);
                }}
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Manual only (no schedule)</option>
                {CRON_PRESETS.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label} ({p.value})
                  </option>
                ))}
                {scheduleCron &&
                  !CRON_PRESETS.some((p) => p.value === scheduleCron) && (
                    <option value="__custom__">Custom: {scheduleCron}</option>
                  )}
              </select>
              <input
                type="text"
                value={scheduleCron}
                onChange={(e) => setScheduleCron(e.target.value)}
                className="w-full rounded-md border bg-background px-3 py-1.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="0 2 * * *"
              />
            </div>
          </Field>

          <fieldset className="space-y-2 rounded-md border bg-muted/30 px-3 py-2">
            <legend className="px-1 text-xs font-medium">Immutability</legend>
            <label className="flex items-start gap-2 text-xs">
              <input
                type="checkbox"
                checked={effectiveWriteOnly}
                disabled={forcedWriteOnly}
                onChange={(e) => setWriteOnly(e.target.checked)}
                className="mt-0.5 disabled:opacity-60"
              />
              <span>
                <span className="font-medium">Write-only destination</span>
                <span className="block text-muted-foreground">
                  SpatiumDDI writes archives here but never deletes them:
                  retention is skipped, the archive-delete action is refused,
                  and pull-mode download is unavailable. Use with an S3 bucket
                  under Object Lock and a key without <code>DeleteObject</code>,
                  so nothing this install holds can shorten retention.{" "}
                  <span className="text-amber-600 dark:text-amber-400">
                    Restore drills cannot run against a destination we cannot
                    read, so recovery readiness will report this target as
                    unverified.
                  </span>
                  {forcedWriteOnly && (
                    <span className="mt-1 block font-medium">
                      This destination kind has no listing and no delete, so
                      write-only is always on.
                    </span>
                  )}
                </span>
              </span>
            </label>
          </fieldset>

          <fieldset
            className="space-y-2 rounded-md border bg-muted/30 px-3 py-2 disabled:opacity-60"
            disabled={effectiveWriteOnly}
          >
            <legend className="px-1 text-xs font-medium">
              Retention
              {effectiveWriteOnly && (
                <span className="ml-1 font-normal text-muted-foreground">
                  — the destination&apos;s own policy on a write-only target
                </span>
              )}
            </legend>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="radio"
                checked={retentionMode === "none"}
                onChange={() => setRetentionMode("none")}
              />
              Keep all archives (no auto-prune)
            </label>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="radio"
                checked={retentionMode === "last_n"}
                onChange={() => setRetentionMode("last_n")}
              />
              Keep the last
              <input
                type="number"
                min={0}
                max={10000}
                value={retentionLastN}
                onChange={(e) => setRetentionLastN(e.target.value)}
                disabled={retentionMode !== "last_n"}
                className="w-20 rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
              />
              archives
            </label>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="radio"
                checked={retentionMode === "days"}
                onChange={() => setRetentionMode("days")}
              />
              Keep archives newer than
              <input
                type="number"
                min={0}
                max={10000}
                value={retentionDays}
                onChange={(e) => setRetentionDays(e.target.value)}
                disabled={retentionMode !== "days"}
                className="w-20 rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
              />
              days
            </label>
          </fieldset>

          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled (the schedule fires)
          </label>

          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saveMut.isPending}
              className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {saveMut.isPending
                ? "Saving…"
                : mode === "create"
                  ? "Create"
                  : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Building blocks ────────────────────────────────────────────────────

function KindBadge({ kind }: { kind: string }) {
  return (
    <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
      {kind}
    </span>
  );
}

function DisabledBadge() {
  return (
    <span className="rounded bg-zinc-500/15 px-1.5 py-0.5 text-[10px] text-zinc-600 dark:text-zinc-400">
      disabled
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (status === "never") return null;
  const cls =
    status === "success"
      ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
      : status === "failed"
        ? "bg-rose-500/15 text-rose-700 dark:text-rose-300"
        : status === "in_progress"
          ? "bg-sky-500/15 text-sky-700 dark:text-sky-300"
          : "bg-muted text-muted-foreground";
  return (
    <span className={`rounded px-1.5 py-0.5 text-[10px] ${cls}`}>{status}</span>
  );
}

function IconButton({
  title,
  icon,
  onClick,
  disabled,
}: {
  title: string;
  icon: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="rounded p-1 hover:bg-accent disabled:opacity-50"
    >
      {icon}
    </button>
  );
}

function Field({
  label,
  help,
  required,
  children,
}: {
  label: string;
  help?: React.ReactNode;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium">
        {label}
        {required && <span className="ml-1 text-destructive">*</span>}
      </span>
      {children}
      {help && <p className="mt-1 text-[11px] text-muted-foreground">{help}</p>}
    </label>
  );
}
