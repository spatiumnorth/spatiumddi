import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Bug,
  Check,
  ChevronDown,
  ChevronRight,
  Loader2,
  RefreshCw,
  Trash2,
  VolumeX,
} from "lucide-react";
import {
  diagnosticsApi,
  type InternalErrorDetail,
  type InternalErrorListItem,
  formatApiError,
} from "@/lib/api";
import { GithubMark } from "@/components/ui/github-mark";
import { copyToClipboard } from "@/lib/clipboard";
import { SupportBundleSection } from "./SupportBundleSection";

/**
 * Diagnostics → Errors (issue #123).
 *
 * Lists every uncaught exception captured from the API + worker into
 * the ``internal_error`` table. Operators can drill into a row to
 * see the full traceback + sanitised request/task context, ack it,
 * suppress it for 24 h to silence noisy crashes, delete it
 * outright, or click "Submit bug" to open a prefilled GitHub issue.
 *
 * Read-only for non-superadmin users — the backend will 403 and the
 * page renders the error state. Superadmin is the right blast
 * radius until / unless we add a dedicated ``diagnostics:read``
 * permission.
 */

const GITHUB_NEW_ISSUE_URL =
  "https://github.com/spatiumnorth/spatiumddi/issues/new";

// GitHub's ``/issues/new?body=`` query param works up to roughly 7 KB
// before the URL is rejected. Anything bigger we drop on the
// clipboard with a banner asking the operator to paste manually.
const GITHUB_BODY_URL_CAP = 6800;

type AckedFilter = "all" | "yes" | "no";
type ServiceFilter = "all" | "api" | "worker" | "beat";

type DiagTab = "errors" | "support-bundle";

export function DiagnosticsErrorsPage() {
  const qc = useQueryClient();
  // The support bundle lives here rather than on its own page: this is
  // where an operator already is when something has gone wrong, and the
  // "Submit bug" button below opens the GitHub issue the bundle is meant
  // to be attached to.
  const [tab, setTab] = useState<DiagTab>("errors");
  const [serviceFilter, setServiceFilter] = useState<ServiceFilter>("all");
  const [ackedFilter, setAckedFilter] = useState<AckedFilter>("all");
  const [sinceHours, setSinceHours] = useState<number | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const listQ = useQuery({
    queryKey: [
      "diagnostics-errors",
      { serviceFilter, ackedFilter, sinceHours },
    ],
    queryFn: () =>
      diagnosticsApi.list({
        service: serviceFilter === "all" ? undefined : serviceFilter,
        acknowledged: ackedFilter === "all" ? undefined : ackedFilter,
        since_hours: sinceHours ?? undefined,
        limit: 200,
      }),
  });

  const statsQ = useQuery({
    queryKey: ["diagnostics-errors", "stats"],
    queryFn: diagnosticsApi.stats,
    staleTime: 30_000,
  });

  const ackMut = useMutation({
    mutationFn: (id: string) => diagnosticsApi.acknowledge(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["diagnostics-errors"] });
    },
  });
  const suppressMut = useMutation({
    mutationFn: (id: string) => diagnosticsApi.suppress(id, 24),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["diagnostics-errors"] });
    },
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => diagnosticsApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["diagnostics-errors"] });
    },
  });

  const errors = listQ.data ?? [];

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-muted-foreground" />
            <h1 className="text-lg font-semibold">Diagnostics</h1>
          </div>
          {statsQ.data && (
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>
                <span className="font-medium text-foreground">
                  {statsQ.data.total}
                </span>{" "}
                total
              </span>
              <span>·</span>
              <span>
                <span className="font-medium text-foreground">
                  {statsQ.data.unacknowledged}
                </span>{" "}
                unacked
              </span>
              {statsQ.data.noisy_unacked > 0 && (
                <>
                  <span>·</span>
                  <span className="font-medium text-amber-600 dark:text-amber-400">
                    {statsQ.data.noisy_unacked} noisy
                  </span>
                </>
              )}
            </div>
          )}
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() =>
                qc.invalidateQueries({ queryKey: ["diagnostics-errors"] })
              }
              className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
              title="Refresh"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${listQ.isFetching ? "animate-spin" : ""}`}
              />
              Refresh
            </button>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs">
          <FilterPill label="Service">
            <select
              value={serviceFilter}
              onChange={(e) =>
                setServiceFilter(e.target.value as ServiceFilter)
              }
              className="rounded-md border bg-background px-2 py-1"
            >
              <option value="all">all</option>
              <option value="api">api</option>
              <option value="worker">worker</option>
              <option value="beat">beat</option>
            </select>
          </FilterPill>
          <FilterPill label="Acknowledged">
            <select
              value={ackedFilter}
              onChange={(e) => setAckedFilter(e.target.value as AckedFilter)}
              className="rounded-md border bg-background px-2 py-1"
            >
              <option value="all">all</option>
              <option value="no">unacked</option>
              <option value="yes">acked</option>
            </select>
          </FilterPill>
          <FilterPill label="Window">
            <select
              value={sinceHours ?? ""}
              onChange={(e) =>
                setSinceHours(e.target.value ? Number(e.target.value) : null)
              }
              className="rounded-md border bg-background px-2 py-1"
            >
              <option value="">all time</option>
              <option value="1">last 1h</option>
              <option value="24">last 24h</option>
              <option value="168">last 7d</option>
            </select>
          </FilterPill>
        </div>
      </div>

      <div className="border-b bg-card px-6">
        <div className="-mb-px flex gap-1">
          {(
            [
              ["errors", "Errors"],
              ["support-bundle", "Support bundle"],
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

      {tab === "support-bundle" ? (
        <div className="flex-1 overflow-auto p-6">
          <div className="mx-auto max-w-4xl">
            <SupportBundleSection />
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          {listQ.isLoading ? (
            <div className="p-6 text-sm text-muted-foreground">
              <Loader2 className="mr-2 inline h-3.5 w-3.5 animate-spin" />
              Loading…
            </div>
          ) : listQ.isError ? (
            <div className="p-6 text-sm text-destructive">
              Failed to load errors.
              {(listQ.error as Error)?.message
                ? ` ${formatApiError(listQ.error)}`
                : ""}
            </div>
          ) : errors.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">
              No errors recorded. The capture handler is wired and will land
              uncaught exceptions here as they happen.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 bg-card text-left text-xs text-muted-foreground">
                <tr className="border-b">
                  <th className="w-8 px-2 py-2"></th>
                  <th className="px-3 py-2">When</th>
                  <th className="px-3 py-2">Service</th>
                  <th className="px-3 py-2">Class</th>
                  <th className="px-3 py-2">Message</th>
                  <th className="px-3 py-2">Route / Task</th>
                  <th className="px-3 py-2 text-right">Count</th>
                  <th className="px-3 py-2">State</th>
                  <th className="px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {errors.map((row) => (
                  <ErrorRow
                    key={row.id}
                    row={row}
                    expanded={expandedId === row.id}
                    onToggleExpand={() =>
                      setExpandedId(expandedId === row.id ? null : row.id)
                    }
                    onAck={() => ackMut.mutate(row.id)}
                    onSuppress={() => suppressMut.mutate(row.id)}
                    onDelete={() => deleteMut.mutate(row.id)}
                    pendingAck={ackMut.isPending && ackMut.variables === row.id}
                    pendingSuppress={
                      suppressMut.isPending && suppressMut.variables === row.id
                    }
                    pendingDelete={
                      deleteMut.isPending && deleteMut.variables === row.id
                    }
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function FilterPill({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="inline-flex items-center gap-1.5">
      <span className="text-muted-foreground">{label}:</span>
      {children}
    </label>
  );
}

function ErrorRow({
  row,
  expanded,
  onToggleExpand,
  onAck,
  onSuppress,
  onDelete,
  pendingAck,
  pendingSuppress,
  pendingDelete,
}: {
  row: InternalErrorListItem;
  expanded: boolean;
  onToggleExpand: () => void;
  onAck: () => void;
  onSuppress: () => void;
  onDelete: () => void;
  pendingAck: boolean;
  pendingSuppress: boolean;
  pendingDelete: boolean;
}) {
  const isAcked = row.acknowledged_by !== null;
  const isSuppressed =
    row.suppressed_until !== null &&
    new Date(row.suppressed_until).getTime() > Date.now();

  return (
    <>
      <tr className="border-b align-top hover:bg-accent/40">
        <td className="px-2 py-2">
          <button
            type="button"
            onClick={onToggleExpand}
            className="rounded p-1 hover:bg-accent"
            aria-label={expanded ? "Collapse" : "Expand"}
          >
            {expanded ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
          </button>
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-xs text-muted-foreground">
          {new Date(row.last_seen_at).toLocaleString()}
        </td>
        <td className="px-3 py-2 text-xs">
          <span className="rounded bg-muted px-1.5 py-0.5 font-mono">
            {row.service}
          </span>
        </td>
        <td className="px-3 py-2 font-mono text-xs">{row.exception_class}</td>
        <td className="max-w-[360px] truncate px-3 py-2" title={row.message}>
          {row.message}
        </td>
        <td className="max-w-[240px] truncate px-3 py-2 font-mono text-xs">
          {row.route_or_task ?? "—"}
        </td>
        <td className="px-3 py-2 text-right text-xs">
          {row.occurrence_count > 1 && (
            <span
              className={
                row.occurrence_count >= 5
                  ? "font-medium text-amber-600 dark:text-amber-400"
                  : "text-muted-foreground"
              }
            >
              {row.occurrence_count}×
            </span>
          )}
        </td>
        <td className="px-3 py-2 text-xs">
          {isAcked && (
            <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-1.5 py-0.5 text-emerald-700 dark:text-emerald-300">
              <Check className="h-3 w-3" />
              acked
            </span>
          )}
          {!isAcked && isSuppressed && (
            <span className="inline-flex items-center gap-1 rounded bg-zinc-500/10 px-1.5 py-0.5 text-muted-foreground">
              <VolumeX className="h-3 w-3" />
              suppressed
            </span>
          )}
          {!isAcked && !isSuppressed && (
            <span className="text-amber-600 dark:text-amber-400">open</span>
          )}
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-right">
          <div className="inline-flex items-center gap-1">
            {!isAcked && (
              <button
                type="button"
                onClick={onAck}
                disabled={pendingAck}
                title="Acknowledge"
                className="rounded p-1 hover:bg-accent disabled:opacity-50"
              >
                {pendingAck ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Check className="h-3.5 w-3.5" />
                )}
              </button>
            )}
            <button
              type="button"
              onClick={onSuppress}
              disabled={pendingSuppress}
              title="Suppress 24h"
              className="rounded p-1 hover:bg-accent disabled:opacity-50"
            >
              {pendingSuppress ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <VolumeX className="h-3.5 w-3.5" />
              )}
            </button>
            <button
              type="button"
              onClick={() => {
                if (
                  confirm(
                    "Delete this error row? Suppress is the gentler option for noisy crashes.",
                  )
                ) {
                  onDelete();
                }
              }}
              disabled={pendingDelete}
              title="Delete"
              className="rounded p-1 hover:bg-destructive/10 disabled:opacity-50"
            >
              {pendingDelete ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Trash2 className="h-3.5 w-3.5 text-destructive" />
              )}
            </button>
          </div>
        </td>
      </tr>
      {expanded && <ErrorDetailRow id={row.id} />}
    </>
  );
}

function ErrorDetailRow({ id }: { id: string }) {
  const detailQ = useQuery({
    queryKey: ["diagnostics-error", id],
    queryFn: () => diagnosticsApi.get(id),
  });

  return (
    <tr className="border-b bg-muted/30">
      <td colSpan={9} className="px-6 py-4">
        {detailQ.isLoading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : detailQ.isError ? (
          <div className="text-xs text-destructive">Failed to load detail.</div>
        ) : detailQ.data ? (
          <ErrorDetailContent detail={detailQ.data} />
        ) : null}
      </td>
    </tr>
  );
}

function ErrorDetailContent({ detail }: { detail: InternalErrorDetail }) {
  const [bodyTooBigForUrl, setBodyTooBigForUrl] = useState(false);

  function buildIssueUrl(): { url: string; oversize: boolean } {
    const title = `[bug] ${detail.exception_class}: ${detail.message.slice(0, 60)}`;
    const body = `## Environment

- Service: ${detail.service}
- Route / task: ${detail.route_or_task ?? "n/a"}
- Request ID: ${detail.request_id ?? "n/a"}
- Occurred: ${detail.timestamp}
- Last seen: ${detail.last_seen_at}
- Recurrence: ${detail.occurrence_count}×

## What happened

(Brief description of what you were doing — please fill in)

## Traceback

\`\`\`
${detail.traceback}
\`\`\`

## Sanitised request context

\`\`\`json
${JSON.stringify(detail.context_json, null, 2)}
\`\`\`

---
*Filed via the in-app error report button. The traceback above has had \`Authorization\` headers and known secret-shaped fields stripped before submission. Please review before posting if your install handles sensitive data.*`;
    const params = new URLSearchParams({
      title,
      body,
      labels: "bug",
    });
    const url = `${GITHUB_NEW_ISSUE_URL}?${params.toString()}`;
    return { url, oversize: url.length > GITHUB_BODY_URL_CAP };
  }

  async function onSubmitBug() {
    const ok = confirm(
      "This will open GitHub with your traceback prefilled. The traceback has been sanitised but please review before posting if your install handles sensitive data.",
    );
    if (!ok) return;
    const { url, oversize } = buildIssueUrl();
    if (oversize) {
      // Body too long for a query param. Copy to clipboard + open
      // a blank issue with just the title.
      const title = `[bug] ${detail.exception_class}: ${detail.message.slice(0, 60)}`;
      const params = new URLSearchParams({ title, labels: "bug" });
      const fallback = `${GITHUB_NEW_ISSUE_URL}?${params.toString()}`;
      await copyToClipboard(extractBodyOnly(url));
      setBodyTooBigForUrl(true);
      window.open(fallback, "_blank", "noopener,noreferrer");
      return;
    }
    window.open(url, "_blank", "noopener,noreferrer");
  }

  return (
    <div className="space-y-3">
      {bodyTooBigForUrl && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          Body was too large for a GitHub URL — copied to your clipboard. Paste
          it into the new issue body.
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onSubmitBug}
          className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
        >
          <GithubMark className="h-3.5 w-3.5" />
          Submit bug
        </button>
        <button
          type="button"
          onClick={() => copyToClipboard(detail.traceback)}
          className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
        >
          <Bug className="h-3.5 w-3.5" />
          Copy traceback
        </button>
        <span className="ml-2 text-[11px] text-muted-foreground">
          Fingerprint:{" "}
          <code className="font-mono">{detail.fingerprint.slice(0, 12)}…</code>
        </span>
      </div>
      <div>
        <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Traceback
        </div>
        <pre className="max-h-72 overflow-auto rounded-md border bg-background p-2 text-[11px] leading-tight">
          {detail.traceback}
        </pre>
      </div>
      <div>
        <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Context
        </div>
        <pre className="max-h-48 overflow-auto rounded-md border bg-background p-2 text-[11px] leading-tight">
          {JSON.stringify(detail.context_json, null, 2)}
        </pre>
      </div>
    </div>
  );
}

function extractBodyOnly(url: string): string {
  // Pull just the body= parameter value, decoded, for clipboard
  // fallback. Anything more sophisticated than this is overkill.
  const u = new URL(url);
  return u.searchParams.get("body") ?? "";
}
