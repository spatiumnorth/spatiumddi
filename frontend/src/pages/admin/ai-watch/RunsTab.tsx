import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { aiWatchApi, type AIWatchRun } from "@/lib/api";
import { pollUnlessRefused } from "@/lib/refusal";
import { Modal } from "@/components/ui/modal";
import { ListReadError } from "@/components/ui/list-read-error";
import { cn } from "@/lib/utils";
import { fmtWhen, skipReason, TRIGGERS } from "./shared";

function stateCls(state: string): string {
  if (state === "ok")
    return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400";
  if (state === "failed") return "bg-red-500/15 text-red-700 dark:text-red-400";
  if (state === "skipped")
    return "bg-amber-500/15 text-amber-700 dark:text-amber-400";
  return "bg-sky-500/15 text-sky-700 dark:text-sky-400";
}

/** What a run did, as one line. A skipped or failed run says why. */
function outcome(r: AIWatchRun): string {
  if (r.state === "skipped") return skipReason(r.skip_reason);
  if (r.state === "failed") return r.error ?? "Failed";
  if (r.state === "running") return "In progress";
  if (r.evidence_count === 0)
    return "Nothing to review: no detector reports a problem";
  const parts = [
    `${r.findings_opened} opened`,
    `${r.findings_updated} updated`,
    `${r.findings_resolved} resolved`,
  ];
  if (r.findings_dropped)
    parts.push(`${r.findings_dropped} dropped (cited no real evidence)`);
  if (r.findings_muted) parts.push(`${r.findings_muted} muted`);
  return parts.join(", ");
}

function costText(r: AIWatchRun): string {
  const tokens = r.tokens_in + r.tokens_out;
  if (r.cost_usd === null) return tokens > 0 ? "unknown" : "—";
  return `$${Number(r.cost_usd).toFixed(4)}`;
}

export function RunsTab() {
  const [openId, setOpenId] = useState<string | null>(null);
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["ai-watch", "runs"],
    queryFn: () => aiWatchApi.listRuns({ limit: 100 }),
    refetchInterval: pollUnlessRefused(30_000),
    retry: false,
  });
  const items = data?.items ?? [];

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Every run, including the ones that did not happen. A run that was
        refused (budget, no provider Copilot Watch may use, maintenance mode) is
        listed as skipped with the reason. Runs are kept for 30 days.
      </p>
      {isLoading && (
        <div className="text-sm text-muted-foreground">Loading…</div>
      )}
      {isError && !data && (
        <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
          <ListReadError error={error} what="the runs" />
        </div>
      )}
      {data && items.length === 0 && (
        <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
          No runs yet. The first one starts within a minute of enabling Copilot
          Watch.
        </div>
      )}
      {items.length > 0 && (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="bg-muted/30 text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-1.5 font-medium">Started</th>
                <th className="px-3 py-1.5 font-medium">Trigger</th>
                <th className="px-3 py-1.5 font-medium">State</th>
                <th className="px-3 py-1.5 font-medium">Outcome</th>
                <th className="px-3 py-1.5 font-medium">Model</th>
                <th className="px-3 py-1.5 text-right font-medium">Tokens</th>
                <th className="px-3 py-1.5 text-right font-medium">Cost</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="border-t align-top">
                  <td className="whitespace-nowrap px-3 py-1.5">
                    <button
                      type="button"
                      className="text-primary hover:underline"
                      onClick={() => setOpenId(r.id)}
                      title="Show how this run reached its result"
                    >
                      {fmtWhen(r.started_at)}
                    </button>
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5">
                    {TRIGGERS[r.trigger] ?? r.trigger}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "rounded px-1.5 py-px text-[10px] font-medium uppercase",
                        stateCls(r.state),
                      )}
                    >
                      {r.state}
                    </span>
                  </td>
                  <td className="break-words px-3 py-1.5 text-xs">
                    {outcome(r)}
                  </td>
                  <td className="px-3 py-1.5 text-xs">
                    {r.model
                      ? `${r.model}${r.provider_name ? ` (${r.provider_name})` : ""}`
                      : "—"}
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 text-right text-xs tabular-nums">
                    {(r.tokens_in + r.tokens_out).toLocaleString()}
                  </td>
                  <td
                    className="whitespace-nowrap px-3 py-1.5 text-right text-xs tabular-nums"
                    title={
                      costText(r) === "unknown"
                        ? "This model is not on the rate sheet, so its cost is unknown. The token budget still counts it."
                        : undefined
                    }
                  >
                    {costText(r)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {openId && <RunModal id={openId} onClose={() => setOpenId(null)} />}
    </div>
  );
}

function entryText(entry: Record<string, unknown>): string {
  const body =
    typeof entry.content === "string"
      ? entry.content
      : JSON.stringify(entry.content ?? entry, null, 2);
  const calls = Array.isArray(entry.tool_calls) ? entry.tool_calls : [];
  return calls.length > 0
    ? `${body}\n\ntool calls: ${JSON.stringify(calls, null, 2)}`
    : body;
}

function RunModal({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["ai-watch", "run", id],
    queryFn: () => aiWatchApi.getRun(id),
    retry: false,
  });
  return (
    <Modal title="Run transcript" onClose={onClose} wide>
      <div className="space-y-2 text-sm">
        <p className="text-xs text-muted-foreground">
          What was sent to the model, what it replied, every tool it called and
          what was not filed. Tool results are data collected from the network
          and are shown as text.
        </p>
        {isLoading && <div className="text-muted-foreground">Loading…</div>}
        {isError && <ListReadError error={error} what="the run" />}
        {data && !data.transcript?.length && (
          <div className="text-muted-foreground">
            {data.state === "skipped"
              ? `This run was skipped: ${skipReason(data.skip_reason)}.`
              : "No transcript was recorded for this run."}
          </div>
        )}
        {data?.transcript?.map((entry, i) => (
          <div key={i} className="rounded-md border">
            <div className="border-b bg-muted/30 px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              {String(entry.role ?? "entry")}
              {entry.name ? ` · ${String(entry.name)}` : ""}
            </div>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words p-2 text-xs">
              {entryText(entry)}
            </pre>
          </div>
        ))}
      </div>
    </Modal>
  );
}
