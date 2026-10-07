import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  ClipboardList,
  ChevronLeft,
  ChevronRight,
  Download,
  ShieldCheck,
  ShieldAlert,
  X,
} from "lucide-react";
import { auditApi, type AuditLogEntry } from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { AskAIButton } from "@/components/copilot/AskAIButton";

const PAGE_SIZE = 50;

const ACTION_COLORS: Record<string, string> = {
  create: "bg-green-500/15 text-green-600 dark:text-green-400",
  update: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  delete: "bg-red-500/15 text-red-600 dark:text-red-400",
  reset_password: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400",
  login: "bg-purple-500/15 text-purple-600 dark:text-purple-400",
  logout: "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400",
};

const ACTION_OPTIONS = [
  "create",
  "update",
  "delete",
  "reset_password",
  "login",
  "logout",
];

const RESOURCE_TYPE_OPTIONS = [
  "user",
  "ip_space",
  "ip_block",
  "subnet",
  "ip_address",
  "dns_group",
  "dns_zone",
  "dns_record",
  "dhcp_server_group",
  "dhcp_server",
  "dhcp_scope",
  "dhcp_pool",
  "dhcp_static_assignment",
];

const RESULT_OPTIONS = ["success", "denied", "error"];

function ActionBadge({ action }: { action: string }) {
  const cls =
    ACTION_COLORS[action] ?? "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400";
  return (
    <span
      className={cn(
        "inline-flex rounded px-1.5 py-0.5 text-xs font-medium font-mono",
        cls,
      )}
    >
      {action}
    </span>
  );
}

function ResultBadge({ result }: { result: string }) {
  const ok = result === "success";
  return (
    <span
      className={cn(
        "inline-flex rounded px-1.5 py-0.5 text-xs font-medium",
        ok
          ? "bg-green-500/15 text-green-600 dark:text-green-400"
          : "bg-red-500/15 text-red-600 dark:text-red-400",
      )}
    >
      {result}
    </span>
  );
}

function formatTs(ts: string) {
  try {
    const d = new Date(ts);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

type ColKey = "user" | "action" | "resource" | "summary" | "result" | "ip";

const EMPTY_FILTERS: Record<ColKey, string> = {
  user: "",
  action: "",
  resource: "",
  summary: "",
  result: "",
  ip: "",
};

export function AuditPage() {
  const [page, setPage] = useState(0);
  const [colFilters, setColFilters] =
    useState<Record<ColKey, string>>(EMPTY_FILTERS);

  const hasActiveFilter = Object.values(colFilters).some(Boolean);

  const exportPdfMut = useMutation({
    mutationFn: () => auditApi.exportPdf(),
  });

  const queryParams = {
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
    user_display_name: colFilters.user || undefined,
    action: colFilters.action || undefined,
    resource_type: colFilters.resource || undefined,
    resource_display: colFilters.summary || undefined,
    result: colFilters.result || undefined,
    source_ip: colFilters.ip || undefined,
  };

  const { data, isLoading } = useQuery({
    queryKey: ["audit", queryParams],
    queryFn: () => auditApi.list(queryParams),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];
  const totalPages = Math.ceil(total / PAGE_SIZE);

  function setFilter(col: ColKey, value: string) {
    setColFilters((p) => ({ ...p, [col]: value }));
    setPage(0);
  }

  function clearFilters() {
    setColFilters(EMPTY_FILTERS);
    setPage(0);
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <ClipboardList className="h-6 w-6 text-muted-foreground" />
          <div className="flex-1">
            <h1 className="text-xl font-semibold">Audit Log</h1>
            <p className="text-sm text-muted-foreground">
              All administrative actions recorded by the system
            </p>
          </div>
          <ChainIntegrityBadge />
          <button
            onClick={() => exportPdfMut.mutate()}
            disabled={exportPdfMut.isPending}
            title="Download a compliance / change report PDF (last 30 days)"
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            <Download className="h-3.5 w-3.5" />
            {exportPdfMut.isPending ? "Exporting…" : "Export PDF"}
          </button>
          <span className="text-sm text-muted-foreground">
            {total.toLocaleString()} {total === 1 ? "event" : "events"}
          </span>
        </div>

        {exportPdfMut.isError && (
          <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-600 dark:text-red-400">
            PDF export failed:{" "}
            {(exportPdfMut.error as Error)?.message ?? "unknown error"}
          </div>
        )}

        {/* Table */}
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="border-b bg-muted/40">
                <th className="px-3 py-2 text-left font-medium text-muted-foreground whitespace-nowrap">
                  Timestamp
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                  User
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                  Action
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                  Resource
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                  Summary
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                  Result
                </th>
                <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                  IP
                </th>
                <th className="px-2 py-2 text-right">
                  {hasActiveFilter && (
                    <button
                      onClick={clearFilters}
                      title="Clear all filters"
                      className="rounded p-0.5 text-primary hover:text-destructive"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  )}
                </th>
              </tr>
              <tr className="border-b bg-muted/10 text-xs">
                {/* Timestamp — no filter */}
                <td className="px-2 py-1" />

                {/* User */}
                <td className="px-2 py-1">
                  <input
                    type="text"
                    value={colFilters.user}
                    onChange={(e) => setFilter("user", e.target.value)}
                    placeholder="Filter…"
                    className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                  />
                </td>

                {/* Action — dropdown */}
                <td className="px-2 py-1">
                  <select
                    value={colFilters.action}
                    onChange={(e) => setFilter("action", e.target.value)}
                    className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                  >
                    <option value="">All</option>
                    {ACTION_OPTIONS.map((a) => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                </td>

                {/* Resource — dropdown */}
                <td className="px-2 py-1">
                  <select
                    value={colFilters.resource}
                    onChange={(e) => setFilter("resource", e.target.value)}
                    className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                  >
                    <option value="">All</option>
                    {RESOURCE_TYPE_OPTIONS.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </td>

                {/* Summary */}
                <td className="px-2 py-1">
                  <input
                    type="text"
                    value={colFilters.summary}
                    onChange={(e) => setFilter("summary", e.target.value)}
                    placeholder="Filter…"
                    className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                  />
                </td>

                {/* Result — dropdown */}
                <td className="px-2 py-1">
                  <select
                    value={colFilters.result}
                    onChange={(e) => setFilter("result", e.target.value)}
                    className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                  >
                    <option value="">All</option>
                    {RESULT_OPTIONS.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </td>

                {/* IP */}
                <td className="px-2 py-1">
                  <input
                    type="text"
                    value={colFilters.ip}
                    onChange={(e) => setFilter("ip", e.target.value)}
                    placeholder="Filter…"
                    className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                  />
                </td>

                <td />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {isLoading ? (
                <tr>
                  <td
                    colSpan={8}
                    className="px-3 py-8 text-center text-muted-foreground"
                  >
                    Loading…
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    className="px-3 py-8 text-center text-muted-foreground"
                  >
                    No audit events found
                  </td>
                </tr>
              ) : (
                items.map((entry: AuditLogEntry) => (
                  <tr
                    key={entry.id}
                    className="border-b last:border-0 hover:bg-muted/30"
                  >
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground whitespace-nowrap">
                      {formatTs(entry.timestamp)}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span className="font-medium">
                        {entry.user_display_name}
                      </span>
                      {entry.auth_source !== "local" && (
                        <span className="ml-1.5 text-xs text-muted-foreground">
                          ({entry.auth_source})
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <ActionBadge action={entry.action} />
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span className="text-xs text-muted-foreground">
                        {entry.resource_type}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground max-w-xs truncate">
                      {entry.resource_display}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <ResultBadge result={entry.result} />
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-muted-foreground whitespace-nowrap">
                      {entry.source_ip ?? "—"}
                    </td>
                    <td className="px-2 py-2 text-right">
                      <AskAIButton
                        context={[
                          `Audit event: ${entry.action} on ${entry.resource_type}`,
                          `summary: ${entry.resource_display}`,
                          `result: ${entry.result}`,
                          `user: ${entry.user_display_name}${
                            entry.auth_source !== "local"
                              ? ` (${entry.auth_source})`
                              : ""
                          }`,
                          entry.source_ip
                            ? `source_ip: ${entry.source_ip}`
                            : null,
                          `timestamp: ${entry.timestamp}`,
                          `audit_id: ${entry.id}`,
                        ]
                          .filter(Boolean)
                          .join(", ")}
                        tooltip="Ask AI about this event"
                        prompt="Explain this audit entry in plain English — what happened, who did it, and what changed."
                        iconOnly
                        className="px-1.5 py-1"
                      />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">
              Page {page + 1} of {totalPages}
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="flex h-8 w-8 items-center justify-center rounded-md border text-muted-foreground hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="flex h-8 w-8 items-center justify-center rounded-md border text-muted-foreground hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-40"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ChainIntegrityBadge() {
  // Cap the on-page check at 1000 rows so opening the audit page on a
  // huge deployment doesn't take seconds. The nightly Celery task
  // does the full sweep + writes an alert event, so the badge is
  // primarily here to give operators an at-a-glance "yes, we just
  // checked" signal.
  const { data } = useQuery({
    queryKey: ["audit-integrity-1000"],
    queryFn: () => auditApi.integrity(1000),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  if (!data) {
    return (
      <span className="rounded-full border bg-muted/40 px-2 py-0.5 text-xs text-muted-foreground">
        Checking integrity…
      </span>
    );
  }
  if (data.ok) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300"
        title={`Last ${data.rows_checked.toLocaleString()} rows verified`}
      >
        <ShieldCheck className="h-3 w-3" />
        Chain verified
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/30 dark:text-red-300"
      title={`${data.breaks.length} broken row(s) — first at seq=${data.breaks[0]?.seq}${
        data.breaks[0]
          ? ` (${data.breaks[0].reason}: ${data.breaks[0].action} ${data.breaks[0].resource_type} ${data.breaks[0].resource_id})`
          : ""
      }`}
    >
      <ShieldAlert className="h-3 w-3" />
      Tampering detected ({data.breaks.length})
    </span>
  );
}
