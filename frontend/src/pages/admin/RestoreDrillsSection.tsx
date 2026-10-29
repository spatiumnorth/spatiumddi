import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleSlash,
  Loader2,
  Play,
  RefreshCw,
  ShieldQuestion,
  XCircle,
} from "lucide-react";

import {
  backupTargetsApi,
  formatApiError,
  type BackupTarget,
  type RestoreDrill,
  type RestoreDrillAssertion,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { ListEmpty, ListReadError } from "@/components/ui/list-read-error";
import { isRefused } from "@/lib/refusal";

/**
 * Restore Drills section on the Backup admin page (issue #702).
 *
 * A drill replays a target's newest archive into a throwaway
 * database and asserts against the result. The live database is
 * never written to — the point is to prove the archive is
 * restorable *before* an operator needs it to be.
 *
 * Two cards:
 *
 * 1. **Readiness** — one row per backup target: is a drill
 *    scheduled, what did the last one say, how long ago did this
 *    target last *prove* it could be restored. A target that has
 *    never passed a drill reads as "never" rather than healthy,
 *    which is the honest framing: an untested backup is an
 *    unknown, not a pass. A target whose most recent drill merely
 *    errored keeps its previous proof — an error disproves
 *    nothing — but the row flags it as superseded once a real
 *    failure lands.
 *
 * 2. **History** — recent drills, expandable to the per-check
 *    verdicts.
 *
 * ``failed`` and ``error`` are shown differently on purpose.
 * ``failed`` means the archive did not survive the test restore —
 * a real finding. ``error`` means the drill could not run at all
 * (destination unreachable), which says nothing about the archive.
 */

// Slower than the backup presets: a drill replays a whole dump into
// a scratch database, so it costs far more than taking a backup.
// Weekly against nightly backups is the shape most installs want.
const DRILL_CRON_PRESETS: { label: string; value: string }[] = [
  { label: "Daily 05:00 UTC", value: "0 5 * * *" },
  { label: "Weekly Sunday 05:00 UTC", value: "0 5 * * 0" },
  { label: "Weekly Wednesday 05:00 UTC", value: "0 5 * * 3" },
  { label: "Fortnightly 1st + 15th 05:00 UTC", value: "0 5 1,15 * *" },
  { label: "Monthly 1st 05:00 UTC", value: "0 5 1 * *" },
];

function relativeAge(iso: string | null): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  const hours = (Date.now() - then) / 36e5;
  if (hours < 1) return "under an hour ago";
  if (hours < 48) return `${Math.round(hours)}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function StateChip({ state }: { state: string }) {
  const map: Record<
    string,
    { cls: string; icon: typeof CheckCircle2; label: string }
  > = {
    passed: {
      cls: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
      icon: CheckCircle2,
      label: "Passed",
    },
    failed: {
      cls: "bg-rose-500/10 text-rose-600 dark:text-rose-400",
      icon: XCircle,
      label: "Failed",
    },
    error: {
      cls: "bg-amber-500/10 text-amber-600 dark:text-amber-400",
      icon: AlertTriangle,
      label: "Could not run",
    },
    running: {
      cls: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
      icon: Loader2,
      label: "Running",
    },
    in_progress: {
      cls: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
      icon: Loader2,
      label: "Running",
    },
    // #989 — distinct from `never`. "Never verified" reads as "nobody has
    // scheduled a drill"; this one means the destination cannot be read
    // back at all, so no drill will ever run. Falling through to the
    // `never` mapping lost that entirely.
    cannot_drill: {
      cls: "bg-amber-500/10 text-amber-600 dark:text-amber-400",
      icon: ShieldQuestion,
      label: "Cannot verify",
    },
    never: {
      cls: "bg-muted text-muted-foreground",
      icon: ShieldQuestion,
      label: "Never verified",
    },
  };
  const e = map[state] ?? map.never;
  const Icon = e.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium ${e.cls}`}
    >
      <Icon
        className={`h-3 w-3 ${state === "running" || state === "in_progress" ? "animate-spin" : ""}`}
      />
      {e.label}
    </span>
  );
}

function AssertionRow({ a }: { a: RestoreDrillAssertion }) {
  const icon =
    a.status === "pass" ? (
      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
    ) : a.status === "fail" ? (
      <XCircle className="h-3.5 w-3.5 shrink-0 text-rose-600 dark:text-rose-400" />
    ) : (
      <CircleSlash className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
    );
  return (
    <li className="flex items-start gap-2 py-1">
      <span className="mt-0.5">{icon}</span>
      <span className="min-w-0 flex-1">
        <span className="font-mono text-xs">{a.name}</span>
        <span className="ml-2 break-words text-xs text-muted-foreground">
          {a.detail}
        </span>
      </span>
    </li>
  );
}

export function RestoreDrillsSection() {
  const qc = useQueryClient();
  const [scheduleFor, setScheduleFor] = useState<BackupTarget | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const targetsQ = useQuery({
    queryKey: ["backup-targets"],
    queryFn: () => backupTargetsApi.list(),
  });
  // "Last proven" must come from a per-target server-side lookup, not
  // from scanning the drill list: that list is globally capped, so on
  // an install with several targets a genuine pass scrolls out of the
  // window and the column would claim "never" for a target that
  // demonstrably passed — the exact opposite of what this card exists
  // to tell you.
  const readinessQ = useQuery({
    queryKey: ["restore-drill-readiness"],
    queryFn: () => backupTargetsApi.drillReadiness(),
  });
  const drillsQ = useQuery({
    queryKey: ["restore-drills"],
    queryFn: () => backupTargetsApi.listDrills({ limit: 50 }),
    // A drill is synchronous but slow; poll while one is in flight so
    // the row flips without the operator hitting Refresh.
    refetchInterval: (q) =>
      !isRefused(q.state.error) &&
      (q.state.data ?? []).some((d) => d.state === "running")
        ? 5000
        : false,
    retry: (n, err) => !isRefused(err) && n < 3,
  });

  const runDrill = useMutation({
    mutationFn: (id: string) => backupTargetsApi.runDrill(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["restore-drills"] });
      void qc.invalidateQueries({ queryKey: ["backup-targets"] });
      void qc.invalidateQueries({ queryKey: ["restore-drill-readiness"] });
    },
  });

  const targets = targetsQ.data ?? [];
  const drills = drillsQ.data ?? [];
  const readinessByTarget = new Map(
    (readinessQ.data?.targets ?? []).map((r) => [r.target_id, r]),
  );

  return (
    <div className="flex flex-col gap-6">
      <section className="rounded-lg border bg-card">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold">Recovery readiness</h2>
            <p className="mt-0.5 text-xs text-muted-foreground">
              A drill replays each target&rsquo;s newest archive into a
              throwaway database and checks the result. Your live database is
              never touched.
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              void qc.invalidateQueries({ queryKey: ["backup-targets"] });
              void qc.invalidateQueries({ queryKey: ["restore-drills"] });
              void qc.invalidateQueries({
                queryKey: ["restore-drill-readiness"],
              });
            }}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>

        {targetsQ.isLoading ? (
          <div className="px-4 py-6 text-sm text-muted-foreground">
            Loading targets&hellip;
          </div>
        ) : targets.length === 0 ? (
          <div className="px-4 py-6 text-sm text-muted-foreground">
            <ListEmpty error={targetsQ.error} what="backup targets">
              No backup targets configured yet. Add one on the{" "}
              <strong>Destinations</strong> tab — drills verify the archives a
              target has already written.
            </ListEmpty>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-b text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Target</th>
                  <th className="px-4 py-2 font-medium">Drill schedule</th>
                  <th className="px-4 py-2 font-medium">Latest verdict</th>
                  <th className="px-4 py-2 font-medium">Last proven</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => {
                  const readiness = readinessByTarget.get(t.id);
                  const busy =
                    t.drill_last_status === "in_progress" ||
                    (runDrill.isPending && runDrill.variables === t.id);
                  return (
                    <tr key={t.id} className="border-b last:border-0">
                      <td className="px-4 py-2">
                        <div className="font-medium">{t.name}</div>
                        <div className="text-xs text-muted-foreground">
                          {t.kind}
                        </div>
                      </td>
                      <td className="px-4 py-2">
                        {t.drill_enabled && t.drill_cron ? (
                          <span className="font-mono text-xs">
                            {t.drill_cron}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            not scheduled
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <StateChip state={t.drill_last_status} />
                      </td>
                      <td className="px-4 py-2 text-xs">
                        {readinessQ.isLoading ? (
                          <span className="text-muted-foreground">
                            &hellip;
                          </span>
                        ) : readiness?.undrillable_reason ? (
                          // Say WHY, and never show a bare timestamp: a
                          // target hardened to write-only after months of
                          // passing drills still has a `last_passed_at`,
                          // and rendering it alone claims a proof that can
                          // never be refreshed.
                          <span
                            className="text-amber-600 dark:text-amber-400"
                            title={readiness.undrillable_reason}
                          >
                            cannot be verified from here
                            {readiness.last_passed_at &&
                              ` (last passed ${relativeAge(readiness.last_passed_at)}, before it became write-only)`}
                          </span>
                        ) : readiness?.last_passed_at ? (
                          <span
                            className={
                              readiness.verified
                                ? "text-muted-foreground"
                                : "text-amber-600 dark:text-amber-400"
                            }
                          >
                            {relativeAge(readiness.last_passed_at)}
                            {!readiness.verified &&
                              " (superseded by a failure)"}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">never</span>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <div className="flex justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => setScheduleFor(t)}
                            className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
                          >
                            Schedule
                          </button>
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => runDrill.mutate(t.id)}
                            className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs hover:bg-accent disabled:opacity-50"
                          >
                            {busy ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <Play className="h-3 w-3" />
                            )}
                            Run drill
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {runDrill.isError && (
          <div className="border-t px-4 py-2 text-xs text-rose-600 dark:text-rose-400">
            {formatApiError(runDrill.error, "drill failed")}
          </div>
        )}
        <p className="border-t px-4 py-2 text-xs text-muted-foreground">
          A drill can take as long as a real restore. It runs synchronously —
          leave the tab open, or schedule it and check back.
        </p>
      </section>

      <section className="rounded-lg border bg-card">
        <div className="border-b px-4 py-3">
          <h2 className="text-sm font-semibold">Drill history</h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            <strong>Failed</strong> means the archive did not survive the test
            restore — that is a finding about your backup.{" "}
            <strong>Could not run</strong> means the drill itself was blocked
            (destination unreachable, for instance) and says nothing about the
            archive.
          </p>
        </div>
        {drillsQ.isLoading ? (
          <div className="px-4 py-6 text-sm text-muted-foreground">
            Loading&hellip;
          </div>
        ) : drillsQ.isError ? (
          <div className="px-4 py-6 text-sm">
            <ListReadError error={drillsQ.error} what="the drill history" />
          </div>
        ) : drills.length === 0 ? (
          <div className="px-4 py-6 text-sm text-muted-foreground">
            No drills have run yet.
          </div>
        ) : (
          <ul className="divide-y">
            {drills.map((d) => (
              <DrillRow
                key={d.id}
                drill={d}
                open={expanded.has(d.id)}
                onToggle={() =>
                  setExpanded((prev) => {
                    const next = new Set(prev);
                    if (next.has(d.id)) next.delete(d.id);
                    else next.add(d.id);
                    return next;
                  })
                }
              />
            ))}
          </ul>
        )}
      </section>

      {scheduleFor && (
        <ScheduleDrillModal
          target={scheduleFor}
          onClose={() => setScheduleFor(null)}
        />
      )}
    </div>
  );
}

function DrillRow({
  drill,
  open,
  onToggle,
}: {
  drill: RestoreDrill;
  open: boolean;
  onToggle: () => void;
}) {
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <li>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-2 px-4 py-2 text-left hover:bg-accent/50"
      >
        <Chevron className="h-4 w-4 shrink-0 text-muted-foreground" />
        <StateChip state={drill.state} />
        <span className="min-w-0 flex-1 truncate text-sm">
          {drill.target_name ?? "unknown target"}
          {drill.filename && (
            <span className="ml-2 font-mono text-xs text-muted-foreground">
              {drill.filename}
            </span>
          )}
        </span>
        <span className="shrink-0 text-xs text-muted-foreground">
          {relativeAge(drill.started_at)}
          {drill.duration_ms != null &&
            ` · ${(drill.duration_ms / 1000).toFixed(1)}s`}
        </span>
      </button>
      {open && (
        <div className="border-t bg-muted/30 px-4 py-3">
          {drill.error && (
            <p className="mb-2 break-words text-xs text-amber-600 dark:text-amber-400">
              {drill.error}
            </p>
          )}
          {drill.assertions.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No checks recorded — the drill stopped before it could run any.
            </p>
          ) : (
            <ul>
              {drill.assertions.map((a) => (
                <AssertionRow key={a.name} a={a} />
              ))}
            </ul>
          )}
          <p className="mt-2 text-xs text-muted-foreground">
            Triggered {drill.triggered_by}
            {drill.scratch_db && ` · scratch database ${drill.scratch_db}`}
          </p>
        </div>
      )}
    </li>
  );
}

function ScheduleDrillModal({
  target,
  onClose,
}: {
  target: BackupTarget;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [enabled, setEnabled] = useState(target.drill_enabled);
  const [cron, setCron] = useState(target.drill_cron ?? "0 5 * * 0");

  const save = useMutation({
    mutationFn: () =>
      backupTargetsApi.update(target.id, {
        drill_enabled: enabled,
        drill_cron: cron || null,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["backup-targets"] });
      onClose();
    },
  });

  return (
    <Modal title={`Drill schedule — ${target.name}`} onClose={onClose}>
      <div className="flex flex-col gap-3">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Run restore-verification drills on a schedule
        </label>

        <div>
          <label className="mb-1 block text-xs font-medium">
            Drill schedule
          </label>
          <select
            value={
              DRILL_CRON_PRESETS.find((p) => p.value === cron)?.value ??
              "__custom__"
            }
            onChange={(e) => {
              if (e.target.value !== "__custom__") setCron(e.target.value);
            }}
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            {DRILL_CRON_PRESETS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label} ({p.value})
              </option>
            ))}
            {!DRILL_CRON_PRESETS.some((p) => p.value === cron) && (
              <option value="__custom__">Custom: {cron}</option>
            )}
          </select>
          <input
            value={cron}
            onChange={(e) => setCron(e.target.value)}
            placeholder="0 5 * * 0"
            className="mt-2 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm"
          />
          <p className="mt-1 text-xs text-muted-foreground">
            5-field UTC cron expression. Drills are far more expensive than
            backups — weekly against nightly backups is a sensible default.
          </p>
        </div>

        {save.isError && (
          <p className="text-xs text-rose-600 dark:text-rose-400">
            {formatApiError(save.error)}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={save.isPending}
            onClick={() => save.mutate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Save
          </button>
        </div>
      </div>
    </Modal>
  );
}
