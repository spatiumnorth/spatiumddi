import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  AlertTriangle,
  Database,
  Download,
  FileArchive,
  Loader2,
  Lock,
  RefreshCw,
  Upload,
} from "lucide-react";

import {
  backupApi,
  type BackupManifestPreviewResponse,
  type BackupRestoreResponse,
} from "@/lib/api";
import { BackupSectionsPicker } from "./BackupSectionsPicker";
import { BackupTargetsSection } from "./BackupTargetsSection";
import { FactoryResetSection } from "./FactoryResetSection";
import { RestoreDrillsSection } from "./RestoreDrillsSection";

/**
 * Admin → Platform → Backup (issue #117 Phase 1a).
 *
 * Two stacked cards:
 *
 * 1. **Create + download** — passphrase + optional hint, sends the
 *    request, browser triggers a zip download. The passphrase is
 *    only used for the per-backup ``secrets.enc`` envelope; we
 *    never send it back to the operator. Lose it and the secrets
 *    payload is unrecoverable.
 *
 * 2. **Restore from file** — three-stage flow: upload + preview
 *    manifest, type the passphrase, type the confirmation phrase
 *    ``RESTORE-FROM-BACKUP``. The destructive apply is gated
 *    behind all three.
 *
 * Phase 1a out-of-scope but coming later: scheduled targets
 * (S3 / SCP / Azure), backup-target rows, selective restore.
 */
type Tab = "manual" | "destinations" | "drills" | "factory-reset";

export function BackupPage() {
  const [tab, setTab] = useState<Tab>("manual");
  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center gap-2">
          <Database className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold">Backup &amp; Restore</h1>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          <strong>Manual</strong> — one-off download + restore-from-file.{" "}
          <strong>Destinations</strong> — configure local volumes, S3, SCP,
          Azure Blob. Schedule a recurring backup, view archives at the
          destination, restore from any archive. <strong>Restore Drills</strong>{" "}
          — prove an archive is actually restorable by test-restoring it into a
          throwaway database. <strong>Factory Reset</strong> — wipe
          configuration back to defaults per-section or everything-at-once.
        </p>
        <div className="-mb-px mt-3 flex gap-1 border-b">
          {(
            [
              ["manual", "Manual"],
              ["destinations", "Destinations"],
              ["drills", "Restore Drills"],
              ["factory-reset", "Factory Reset"],
            ] as const
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${
                tab === key
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="mx-auto flex max-w-6xl flex-col gap-6">
          {tab === "manual" && (
            <>
              {/* Manual download + restore — stack on narrow, sit
                  side-by-side on lg+ where there's room for both. */}
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <CreateBackupCard />
                <RestoreBackupCard />
              </div>
              <SecurityNotes />
            </>
          )}
          {tab === "destinations" && (
            <>
              <BackupTargetsSection />
              <SecurityNotes />
            </>
          )}
          {tab === "drills" && <RestoreDrillsSection />}
          {tab === "factory-reset" && <FactoryResetSection />}
        </div>
      </div>
    </div>
  );
}

// ── Create card ────────────────────────────────────────────────────────

function CreateBackupCard() {
  const [passphrase, setPassphrase] = useState("");
  const [passphrase2, setPassphrase2] = useState("");
  const [hint, setHint] = useState("");
  const [excludeSecrets, setExcludeSecrets] = useState(false);

  const downloadMut = useMutation({
    mutationFn: () =>
      backupApi.createAndDownload(passphrase, hint, excludeSecrets),
  });

  const passphraseTooShort = passphrase.length > 0 && passphrase.length < 8;
  const passphraseMismatch =
    passphrase.length > 0 &&
    passphrase2.length > 0 &&
    passphrase !== passphrase2;
  const canSubmit =
    passphrase.length >= 8 &&
    passphrase === passphrase2 &&
    !downloadMut.isPending;

  return (
    <section className="rounded-lg border bg-card p-5">
      <div className="mb-2 flex items-center gap-2">
        <Download className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-sm font-semibold">Create + download backup</h2>
      </div>
      <p className="mb-4 text-xs text-muted-foreground">
        Builds a zip archive with the database dump, the running install&rsquo;s
        SECRET_KEY (passphrase-wrapped), and a manifest. The download starts as
        soon as
        <code className="mx-1 rounded bg-muted px-1 py-0.5 text-[11px]">
          pg_dump
        </code>
        finishes; for a typical install that&rsquo;s under 10 seconds.
      </p>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!canSubmit) return;
          downloadMut.mutate();
        }}
      >
        <Field label="Passphrase" required>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="At least 8 characters"
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            autoComplete="new-password"
          />
        </Field>
        <Field label="Confirm passphrase" required>
          <input
            type="password"
            value={passphrase2}
            onChange={(e) => setPassphrase2(e.target.value)}
            placeholder="Retype to catch typos"
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            autoComplete="new-password"
          />
          {passphraseMismatch && (
            <p className="mt-1 text-xs text-destructive">
              Passphrases don&rsquo;t match.
            </p>
          )}
          {passphraseTooShort && (
            <p className="mt-1 text-xs text-destructive">
              Passphrase must be at least 8 characters.
            </p>
          )}
        </Field>
        <Field
          label="Hint (optional)"
          help="A short label to remind you which passphrase decrypts this archive. Stored in the archive in clear text."
        >
          <input
            type="text"
            value={hint}
            onChange={(e) => setHint(e.target.value)}
            placeholder="e.g. corp-vault-2026"
            maxLength={200}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </Field>
        <label className="flex items-start gap-2 rounded-md border bg-muted/30 px-3 py-2 text-xs">
          <input
            type="checkbox"
            checked={excludeSecrets}
            onChange={(e) => setExcludeSecrets(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            <strong>Exclude secrets (diagnostic mode).</strong> NULL every
            credential / api-key / TSIG-key / TOTP secret in the archive at dump
            time. Use when sharing a snapshot with support / consultants — the
            archive is shareable but a restore yields an install with empty
            credential fields, so operators re-enter integration / auth-provider
            creds by hand.
          </span>
        </label>
        <div className="flex items-center gap-2">
          <button
            type="submit"
            disabled={!canSubmit}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {downloadMut.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            {downloadMut.isPending ? "Building…" : "Build + download"}
          </button>
          {downloadMut.isError && (
            <span className="text-xs text-destructive">
              {(downloadMut.error as Error)?.message ||
                "Backup failed — see api logs."}
            </span>
          )}
          {downloadMut.isSuccess && (
            <span className="text-xs text-emerald-600 dark:text-emerald-400">
              Download started.
            </span>
          )}
        </div>
      </form>
    </section>
  );
}

// ── Restore card ───────────────────────────────────────────────────────

const CONFIRM_PHRASE = "RESTORE-FROM-BACKUP";

function RestoreBackupCard() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<BackupManifestPreviewResponse | null>(
    null,
  );
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [outcome, setOutcome] = useState<BackupRestoreResponse | null>(null);
  const [mode, setMode] = useState<"full" | "selective">("full");
  const [sections, setSections] = useState<string[]>([]);

  const previewMut = useMutation({
    mutationFn: (f: File) => backupApi.previewManifest(f),
    onSuccess: (data) => {
      setPreview(data);
      setPreviewError(null);
    },
    onError: (err: Error) => {
      setPreviewError(err.message || "Manifest preview failed");
      setPreview(null);
    },
  });

  const restoreMut = useMutation({
    mutationFn: () => {
      if (!file) throw new Error("no archive selected");
      return backupApi.restore(
        file,
        passphrase,
        confirm,
        mode === "selective" ? sections : undefined,
      );
    },
    onSuccess: setOutcome,
  });

  function onPickFile(f: File | null) {
    setFile(f);
    setPreview(null);
    setPreviewError(null);
    setOutcome(null);
    if (f) previewMut.mutate(f);
  }

  const archiveIsCustomFormat =
    preview?.manifest?.format_version === 2 ||
    preview?.manifest?.format_version === undefined;
  const selectiveBlockedByPlainFormat =
    mode === "selective" && preview && !archiveIsCustomFormat;

  const canSubmit =
    !!file &&
    !!preview &&
    passphrase.length >= 8 &&
    confirm === CONFIRM_PHRASE &&
    !restoreMut.isPending &&
    !selectiveBlockedByPlainFormat &&
    (mode !== "selective" || sections.length > 0);

  return (
    <section className="rounded-lg border bg-card p-5">
      <div className="mb-2 flex items-center gap-2">
        <Upload className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-sm font-semibold">Restore from file</h2>
      </div>
      <div className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
        <div className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
          <div>
            Restore is a <strong>hard overwrite</strong>. Every table on this
            install is replaced with what&rsquo;s in the archive. A pre-restore
            safety dump is taken first so a botched restore can be rolled back,
            but you should still take a fresh backup before running this.
          </div>
        </div>
      </div>

      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!canSubmit) return;
          restoreMut.mutate();
        }}
      >
        <Field label="Archive file" required>
          <input
            type="file"
            accept=".zip"
            onChange={(e) => onPickFile(e.target.files?.[0] ?? null)}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
          />
        </Field>

        {previewMut.isPending && (
          <div className="text-xs text-muted-foreground">
            <Loader2 className="mr-1 inline h-3.5 w-3.5 animate-spin" />
            Inspecting archive…
          </div>
        )}
        {previewError && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {previewError}
          </div>
        )}
        {preview && <ManifestPreview preview={preview} />}

        {preview && (
          <BackupSectionsPicker
            mode={mode}
            onModeChange={setMode}
            selected={sections}
            onChange={setSections}
          />
        )}
        {selectiveBlockedByPlainFormat && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            Selective restore needs an archive whose database dump is in
            pg_dump&rsquo;s custom format. This archive&rsquo;s dump is plain
            SQL (an older build, or <em>Exclude secrets</em> diagnostic mode,
            wrote it) — switch to <em>Full restore</em>, or take a regular
            backup of the source install on a current build.
          </div>
        )}

        <Field label="Passphrase" required>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="The passphrase used at backup time"
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
            autoComplete="off"
          />
        </Field>

        <Field
          label="Confirmation phrase"
          help={
            <>
              Type{" "}
              <code className="rounded bg-muted px-1 py-0.5 text-[11px]">
                {CONFIRM_PHRASE}
              </code>{" "}
              exactly to enable the Apply button.
            </>
          }
          required
        >
          <input
            type="text"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder={CONFIRM_PHRASE}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
            autoComplete="off"
          />
        </Field>

        <div className="flex items-center gap-2">
          <button
            type="submit"
            disabled={!canSubmit}
            className="inline-flex items-center gap-1.5 rounded-md bg-destructive px-3 py-1.5 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {restoreMut.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            {restoreMut.isPending ? "Restoring…" : "Apply restore"}
          </button>
          {restoreMut.isError && (
            <span className="text-xs text-destructive">
              {(restoreMut.error as Error)?.message || "Restore failed."}
            </span>
          )}
        </div>

        {outcome && <RestoreResultCard outcome={outcome} />}
      </form>
    </section>
  );
}

function ManifestPreview({
  preview,
}: {
  preview: BackupManifestPreviewResponse;
}) {
  const m = preview.manifest;
  const recognised = preview.format_recognised;
  return (
    <div
      className={`rounded-md border px-3 py-2 text-xs ${
        recognised
          ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300"
          : "border-amber-500/40 bg-amber-500/5 text-amber-700 dark:text-amber-300"
      }`}
    >
      <div className="mb-1 flex items-center gap-1.5">
        <FileArchive className="h-3.5 w-3.5" />
        <span className="font-medium">
          {recognised
            ? "Recognised SpatiumDDI backup"
            : "Format unrecognised — proceed with care"}
        </span>
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-0.5">
        <Row label="Source hostname" value={m.hostname} />
        <Row label="Created" value={m.created_at} />
        <Row label="App version" value={m.app_version} />
        <Row label="Schema head" value={m.schema_version} />
        <Row label="Format version" value={m.format_version?.toString()} />
        <Row label="Hint" value={m.secret_passphrase_hint} />
        <Row
          label="Archive size"
          value={`${(preview.archive_bytes / 1024 / 1024).toFixed(2)} MB`}
        />
      </dl>
    </div>
  );
}

function Row({
  label,
  value,
}: {
  label: string;
  value: string | number | null | undefined;
}) {
  if (value == null || value === "") return null;
  return (
    <>
      <dt className="text-muted-foreground/80">{label}</dt>
      <dd className="font-mono">{value}</dd>
    </>
  );
}

function RestoreResultCard({ outcome }: { outcome: BackupRestoreResponse }) {
  const warnings = outcome.warnings ?? [];
  return (
    <div className="space-y-2">
      <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
        <div className="mb-1 font-medium">Restore complete</div>
        <div className="space-y-0.5">
          <div>Duration: {outcome.duration_ms} ms</div>
          {outcome.pre_restore_safety_path && (
            <div>
              Pre-restore safety dump:{" "}
              <code className="rounded bg-muted px-1 py-0.5 text-[11px]">
                {outcome.pre_restore_safety_path}
              </code>
            </div>
          )}
          <div className="mt-2 whitespace-pre-wrap text-foreground/80">
            {outcome.note}
          </div>
        </div>
      </div>
      {warnings.length > 0 && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
          <div className="mb-1 font-medium">Post-restore action required</div>
          <ul className="ml-4 list-disc space-y-1.5">
            {warnings.map((w, i) => (
              <li key={i} className="whitespace-pre-wrap">
                {w}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ── Security notes ─────────────────────────────────────────────────────

function SecurityNotes() {
  return (
    <section className="rounded-lg border border-dashed bg-muted/30 p-4 text-xs text-muted-foreground">
      <div className="mb-2 flex items-center gap-1.5 text-foreground">
        <Lock className="h-3.5 w-3.5" />
        <span className="font-medium">Security model</span>
      </div>
      <ul className="ml-5 list-disc space-y-1">
        <li>
          The archive embeds a passphrase-wrapped envelope (
          <code>secrets.enc</code>) carrying the source install&rsquo;s{" "}
          <code>SECRET_KEY</code>. PBKDF2-HMAC-SHA256 at 600 000 iterations,
          AES-256-GCM with a fresh per-backup salt + nonce.
        </li>
        <li>
          The database dump inside the zip is not encrypted — only{" "}
          <code>secrets.enc</code> is. Encrypt the archive at rest, or keep it
          at a destination that does, if you don&rsquo;t want operators with
          read access to the file to see IPAM / DNS / DHCP rows.
        </li>
        <li>
          Same-install restores work without any further steps. A restore into a
          different install re-encrypts the stored secrets (auth provider creds,
          agent PSKs, integration credentials) under the destination&rsquo;s own
          key. If that stops part-way, the restore result says so: recover the
          source key from the archive&rsquo;s <code>secrets.enc</code> and
          restore again, or re-enter the affected credentials.
        </li>
        <li>
          <strong>Lose the passphrase, lose the secrets payload.</strong> There
          is no recovery — that&rsquo;s by design.
        </li>
      </ul>
    </section>
  );
}

// ── Building blocks ────────────────────────────────────────────────────

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
