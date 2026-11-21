import { useState } from "react";
import { Download, XCircle } from "lucide-react";
import {
  formatApiError,
  logsApi,
  type DNSQueryExportParams,
  type DNSQueryExportResult,
} from "@/lib/api";

/**
 * View filter for Logs → DNS Queries (#4170): lists the group's CONFIGURED
 * views, so one can be picked before it has had any traffic (the "By view"
 * card only knows views that appeared in the analytics window). A view that is
 * active but no longer configured (set from the card, or deleted since) stays
 * listed, so the select never shows "Any" while a filter is in force.
 */
export function ViewFilter({
  views,
  value,
  onChange,
}: {
  views: string[];
  value: string;
  onChange: (v: string) => void;
}) {
  const options = value && !views.includes(value) ? [...views, value] : views;
  return (
    <label className="flex items-center gap-1.5 text-xs">
      <span className="text-muted-foreground">View</span>
      <select
        aria-label="View"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border bg-background px-2 py-1 text-sm"
      >
        <option value="">Any</option>
        {options.map((v) => (
          <option key={v} value={v}>
            {v}
          </option>
        ))}
      </select>
    </label>
  );
}

/** A visible chip naming the active view filter, however it was set. */
export function ActiveViewChip({
  view,
  onClear,
}: {
  view: string;
  onClear: () => void;
}) {
  if (!view) return null;
  return (
    <span
      data-testid="active-view-chip"
      className="inline-flex items-center gap-1 rounded-full border bg-primary/10 px-2.5 py-0.5 text-xs"
    >
      <span className="text-muted-foreground">View:</span>
      <span className="font-medium">{view}</span>
      <button
        type="button"
        onClick={onClear}
        title="Clear view filter"
        aria-label="Clear view filter"
        className="rounded p-0.5 text-muted-foreground hover:text-foreground"
      >
        <XCircle className="h-3.5 w-3.5" />
      </button>
    </span>
  );
}

/**
 * Export what the current filters select as CSV or JSON Lines (#4171). The
 * server streams the file and caps it; a capped export says so here, because
 * the file itself stays clean CSV / JSONL.
 */
export function ExportControl({
  params,
  disabled,
}: {
  params: DNSQueryExportParams;
  disabled?: boolean;
}) {
  const [busy, setBusy] = useState<"csv" | "jsonl" | null>(null);
  const [result, setResult] = useState<DNSQueryExportResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(format: "csv" | "jsonl") {
    setBusy(format);
    setError(null);
    setResult(null);
    try {
      setResult(await logsApi.exportDnsQueries(params, format));
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setBusy(null);
    }
  }

  const btn =
    "flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent/50 disabled:opacity-50";
  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        className={btn}
        disabled={disabled || busy !== null}
        onClick={() => void run("csv")}
        title="Export the rows the current filters select as CSV"
      >
        <Download className="h-3.5 w-3.5" />
        Export CSV
      </button>
      <button
        type="button"
        className={btn}
        disabled={disabled || busy !== null}
        onClick={() => void run("jsonl")}
        title="Export the rows the current filters select as JSON Lines"
      >
        <Download className="h-3.5 w-3.5" />
        Export JSONL
      </button>
      {result?.truncated && (
        <span role="status" className="text-[11px] text-amber-600">
          Export capped at {result.rowCap.toLocaleString()} rows (newest first)
          — narrow the filter or time window for the rest.
        </span>
      )}
      {error && (
        <span role="alert" className="text-[11px] text-destructive">
          {error}
        </span>
      )}
    </div>
  );
}
