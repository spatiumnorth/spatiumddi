import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Eraser,
  Flame,
  Loader2,
  Lock,
  ShieldAlert,
} from "lucide-react";

import {
  factoryResetApi,
  type FactoryResetExecuteRequest,
  type FactoryResetSection,
} from "@/lib/api";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";

/**
 * Admin → Backup → Factory Reset tab (issue #116).
 *
 * Renders inside the Backup admin page as a third tab after
 * Destinations. The backup page owns the page chrome (header,
 * tabs, content scroller); this component renders only the
 * inner content (intro blurb + section cards + modal).
 *
 * One card per section + a separately-styled "Everything" card
 * at the bottom. Reset flow:
 *
 *   1. Click "Reset" on a card → modal opens, fires the preview.
 *   2. Modal shows the row counts that would be deleted.
 *   3. Operator types the section's confirm phrase + their
 *      account password.
 *   4. If no enabled backup target exists, a separate
 *      acknowledge-no-backup checkbox unlocks the submit button.
 *   5. Submit → POST /system/factory-reset/execute. On success we
 *      invalidate every cached query so the app re-loads cleanly
 *      against the wiped state.
 *
 * Hard guardrails (server-enforced):
 *  - Superadmin only.
 *  - Re-typed account password.
 *  - Per-section literal phrase match.
 *  - Mutex against in-flight backup / concurrent reset.
 *  - 6-hour cooldown.
 */
export function FactoryResetSection() {
  const sectionsQ = useQuery({
    queryKey: ["factory-reset-sections"],
    queryFn: factoryResetApi.listSections,
    staleTime: 5 * 60 * 1000,
  });
  const [active, setActive] = useState<FactoryResetSection | null>(null);

  const concrete = useMemo(
    () => (sectionsQ.data ?? []).filter((s) => s.kind !== "everything"),
    [sectionsQ.data],
  );
  const everything = useMemo(
    () => (sectionsQ.data ?? []).find((s) => s.kind === "everything"),
    [sectionsQ.data],
  );

  return (
    <>
      <section className="rounded-lg border bg-card p-4">
        <div className="flex items-start gap-2">
          <Eraser className="mt-0.5 h-4 w-4 text-destructive" />
          <div>
            <h2 className="text-sm font-semibold">About factory reset</h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Reset SpatiumDDI back to defaults — per-section or
              everything-at-once. The reset is destructive and there is no undo.
              Each section requires a typed-confirm phrase + a re-typed password
              before the destructive SQL runs. The calling superadmin and
              built-in roles are preserved regardless of which section runs.
              Configure a backup destination on the Destinations tab first;
              without one, you must explicitly acknowledge there is no recovery
              path.
            </p>
          </div>
        </div>
      </section>

      {sectionsQ.isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading section catalog…
        </div>
      ) : sectionsQ.isError ? (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive">
          Failed to load section catalog.
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {concrete.map((s) => (
              <SectionCard
                key={s.key}
                section={s}
                onClick={() => setActive(s)}
              />
            ))}
          </div>
          {everything && (
            <EverythingCard
              section={everything}
              onClick={() => setActive(everything)}
            />
          )}
        </div>
      )}

      {active && (
        <ResetModal section={active} onClose={() => setActive(null)} />
      )}
    </>
  );
}

// ── Section card ──────────────────────────────────────────────────────

function SectionCard({
  section,
  onClick,
}: {
  section: FactoryResetSection;
  onClick: () => void;
}) {
  return (
    <section className="rounded-lg border bg-card p-4">
      <div className="mb-2 flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold">{section.label}</h2>
          <p className="text-[11px] text-muted-foreground">
            kind: <code className="font-mono">{section.kind}</code>
            {section.table_count > 0 && (
              <>
                {" · "}
                {section.table_count} table
                {section.table_count === 1 ? "" : "s"}
              </>
            )}
          </p>
        </div>
        <button
          type="button"
          onClick={onClick}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-destructive/40 bg-destructive/5 px-3 py-1.5 text-xs font-medium text-destructive hover:bg-destructive/10"
        >
          <Eraser className="h-3.5 w-3.5" />
          Reset…
        </button>
      </div>
      <p className="text-xs text-muted-foreground">{section.description}</p>
      <div className="mt-2 flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <Lock className="h-3 w-3" /> Confirm phrase:{" "}
        <code className="rounded bg-muted px-1 py-0.5 font-mono">
          {section.phrase}
        </code>
      </div>
    </section>
  );
}

// ── Everything card ───────────────────────────────────────────────────

function EverythingCard({
  section,
  onClick,
}: {
  section: FactoryResetSection;
  onClick: () => void;
}) {
  return (
    <section className="rounded-lg border-2 border-destructive/60 bg-destructive/5 p-5">
      <div className="mb-2 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="h-5 w-5 text-destructive" />
            <h2 className="text-sm font-semibold text-destructive">
              {section.label}
            </h2>
          </div>
          <p className="mt-1 max-w-2xl text-xs text-muted-foreground">
            {section.description}
          </p>
        </div>
        <button
          type="button"
          onClick={onClick}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-destructive px-3 py-1.5 text-xs font-medium text-destructive-foreground hover:bg-destructive/90"
        >
          <Flame className="h-3.5 w-3.5" />
          Reset everything…
        </button>
      </div>
      <div className="mt-2 flex items-center gap-1.5 text-[11px] text-destructive">
        <Lock className="h-3 w-3" /> Confirm phrase:{" "}
        <code className="rounded bg-destructive/10 px-1 py-0.5 font-mono">
          {section.phrase}
        </code>
      </div>
    </section>
  );
}

// ── Reset modal ───────────────────────────────────────────────────────

function ResetModal({
  section,
  onClose,
}: {
  section: FactoryResetSection;
  onClose: () => void;
}) {
  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);
  const qc = useQueryClient();
  const [phrase, setPhrase] = useState("");
  const [password, setPassword] = useState("");
  const [acknowledgeNoBackup, setAcknowledgeNoBackup] = useState(false);

  const previewQ = useQuery({
    queryKey: ["factory-reset-preview", section.key],
    queryFn: () => factoryResetApi.preview([section.key]),
  });

  const executeMut = useMutation({
    mutationFn: (body: FactoryResetExecuteRequest) =>
      factoryResetApi.execute(body),
    onSuccess: () => {
      // The DB underneath us is gone — invalidate everything so
      // every page re-fetches against the wiped state.
      qc.invalidateQueries();
    },
  });

  const phraseMatches = phrase === section.phrase;
  const backupBlock = previewQ.data?.backup_warning && !acknowledgeNoBackup;
  const cooldownBlock = previewQ.data?.cooldown_blocking ?? false;
  const canSubmit =
    phraseMatches &&
    password.length > 0 &&
    !backupBlock &&
    !cooldownBlock &&
    !executeMut.isPending;

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    executeMut.mutate({
      section_keys: [section.key],
      password,
      confirm_phrases: { [section.key]: phrase },
      acknowledge_no_backup: acknowledgeNoBackup,
    });
  };

  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        style={dialogStyle}
        className="flex max-h-[85vh] w-full max-w-2xl flex-col rounded-lg border bg-card shadow-lg focus:outline-none"
      >
        <div
          {...dragHandleProps}
          className={`border-b px-5 py-3 ${dragHandleProps.className}`}
        >
          <h3
            {...titleProps}
            className="flex items-center gap-2 text-sm font-semibold"
          >
            {section.kind === "everything" ? (
              <Flame className="h-4 w-4 text-destructive" />
            ) : (
              <Eraser className="h-4 w-4 text-destructive" />
            )}
            Reset: {section.label}
          </h3>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Destructive + irreversible. Read the impact summary before
            confirming.
          </p>
        </div>

        <form
          onSubmit={onSubmit}
          className="flex flex-1 flex-col gap-4 overflow-auto p-5"
        >
          {/* Description */}
          <div className="text-xs text-muted-foreground">
            {section.description}
          </div>

          {/* Preview */}
          {previewQ.isLoading ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Computing impact…
            </div>
          ) : previewQ.isError ? (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              Failed to compute preview:{" "}
              {(previewQ.error as Error)?.message || "unknown"}
            </div>
          ) : (
            <PreviewBlock previewData={previewQ.data!} />
          )}

          {/* Backup warning */}
          {previewQ.data?.backup_warning && (
            <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs">
              <div className="mb-1 flex items-center gap-1.5 font-medium text-amber-700 dark:text-amber-400">
                <AlertTriangle className="h-3.5 w-3.5" />
                No enabled backup target
              </div>
              <p className="text-amber-700 dark:text-amber-300">
                {previewQ.data.backup_warning_detail}
              </p>
              <label className="mt-2 flex cursor-pointer items-center gap-2 text-xs text-amber-700 dark:text-amber-300">
                <input
                  type="checkbox"
                  checked={acknowledgeNoBackup}
                  onChange={(e) => setAcknowledgeNoBackup(e.target.checked)}
                />
                I understand there is no recoverable snapshot — proceed anyway
              </label>
            </div>
          )}

          {/* Cooldown */}
          {previewQ.data?.cooldown_blocking && (
            <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              <div className="mb-1 flex items-center gap-1.5 font-medium">
                <ShieldAlert className="h-3.5 w-3.5" />
                Cooldown in effect
              </div>
              <p>{previewQ.data.cooldown_detail}</p>
            </div>
          )}

          {/* Confirm phrase */}
          <div className="space-y-1">
            <label className="text-xs font-medium">Confirm phrase</label>
            <p className="text-[11px] text-muted-foreground">
              Type{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono">
                {section.phrase}
              </code>{" "}
              exactly to unlock the password field.
            </p>
            <input
              type="text"
              autoFocus
              value={phrase}
              onChange={(e) => setPhrase(e.target.value)}
              placeholder={section.phrase}
              className={`w-full rounded-md border bg-background px-3 py-1.5 font-mono text-sm focus:outline-none focus:ring-2 ${
                phrase && !phraseMatches
                  ? "border-destructive focus:ring-destructive"
                  : phraseMatches
                    ? "border-emerald-500 focus:ring-emerald-500"
                    : "focus:ring-ring"
              }`}
            />
          </div>

          {/* Password */}
          <div className="space-y-1">
            <label className="text-xs font-medium">
              Re-enter your password
            </label>
            <p className="text-[11px] text-muted-foreground">
              Bearer-token auth alone isn&rsquo;t enough — the server
              re-verifies your password for every reset.
            </p>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={!phraseMatches}
              autoComplete="current-password"
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
            />
          </div>

          {/* Error / success */}
          {executeMut.isError && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {(executeMut.error as Error)?.message || "Reset failed"}
            </div>
          )}
          {executeMut.isSuccess && executeMut.data && (
            <div className="rounded-md border border-emerald-500/30 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-700 dark:text-emerald-300">
              Reset complete. {executeMut.data.deleted_rows_total} row
              {executeMut.data.deleted_rows_total === 1 ? "" : "s"} deleted in{" "}
              {executeMut.data.duration_ms} ms across{" "}
              {executeMut.data.sections.length} section
              {executeMut.data.sections.length === 1 ? "" : "s"}. Audit anchor:{" "}
              <code className="font-mono">
                {executeMut.data.audit_anchor_id?.slice(0, 8) ?? "—"}
              </code>
              .
            </div>
          )}

          {/* Footer */}
          <div className="flex items-center justify-end gap-2 border-t pt-3">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
            >
              {executeMut.isSuccess ? "Close" : "Cancel"}
            </button>
            {!executeMut.isSuccess && (
              <button
                type="submit"
                disabled={!canSubmit}
                className="inline-flex items-center gap-1.5 rounded-md bg-destructive px-3 py-1.5 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                {executeMut.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : section.kind === "everything" ? (
                  <Flame className="h-3.5 w-3.5" />
                ) : (
                  <Eraser className="h-3.5 w-3.5" />
                )}
                {executeMut.isPending ? "Resetting…" : "Apply reset"}
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Preview block ─────────────────────────────────────────────────────

function PreviewBlock({
  previewData,
}: {
  previewData: NonNullable<
    ReturnType<typeof factoryResetApi.preview> extends Promise<infer T>
      ? T
      : never
  >;
}) {
  return (
    <div className="rounded-md border bg-muted/20 p-3">
      <div className="mb-1 text-xs font-medium">
        Impact: {previewData.deleted_rows_total} row
        {previewData.deleted_rows_total === 1 ? "" : "s"} will be deleted
      </div>
      <div className="space-y-2 text-[11px] text-muted-foreground">
        {previewData.sections.map((p) => (
          <div key={p.section_key}>
            <div className="text-foreground">
              <strong>{p.label}</strong> ({p.kind}) — {p.affected_rows} row
              {p.affected_rows === 1 ? "" : "s"}
            </div>
            {Object.keys(p.table_counts).length > 0 && (
              <div className="ml-4 grid grid-cols-2 gap-x-3">
                {Object.entries(p.table_counts)
                  .sort((a, b) => b[1] - a[1])
                  .map(([table, count]) => (
                    <div key={table}>
                      <code className="font-mono">{table}</code>: {count}
                    </div>
                  ))}
              </div>
            )}
            {p.notes.length > 0 && (
              <div className="ml-4 italic">{p.notes.join("; ")}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
