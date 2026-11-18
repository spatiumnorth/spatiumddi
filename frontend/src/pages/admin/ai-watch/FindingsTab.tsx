import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronDown, ChevronRight, RotateCcw, X } from "lucide-react";
import {
  aiWatchApi,
  formatApiError,
  type AIFinding,
  type AIFindingEvidence,
  type AIFindingVerdict,
} from "@/lib/api";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { pollUnlessRefused } from "@/lib/refusal";
import { Modal } from "@/components/ui/modal";
import { ListReadError } from "@/components/ui/list-read-error";
import { cn } from "@/lib/utils";
import { fmtWhen, severityCls } from "./shared";

const NEEDS_WRITE =
  "Requires write on AI findings (the Findings Analyst role has it)";

const STATE_FILTERS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "active", label: "Open and acknowledged" },
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "dismissed", label: "Dismissed" },
  { value: "resolved", label: "Resolved" },
  { value: "all", label: "All" },
];

const VERDICTS: ReadonlyArray<{ value: AIFindingVerdict; label: string }> = [
  { value: "useful", label: "Useful" },
  { value: "not_useful", label: "Not useful" },
  { value: "wrong", label: "Wrong" },
];

const MUTE_CHOICES: ReadonlyArray<{ value: string; label: string }> = [
  { value: "0", label: "Do not mute: file it again if it comes back" },
  { value: "1", label: "Mute for 1 day" },
  { value: "7", label: "Mute for 7 days" },
  { value: "30", label: "Mute for 30 days" },
  { value: "forever", label: "Mute until I remove the mute" },
];

const btnCls =
  "inline-flex items-center gap-1 rounded-md border bg-background px-2.5 py-1 text-xs hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50";

/** Where an evidence reference leads in the UI, if anywhere. */
function evidenceLink(e: AIFindingEvidence): string | null {
  if (e.type === "alert") return "/admin/alerts";
  if (e.type === "conformity") return "/admin/compliance";
  if (e.type === "audit") return "/admin/audit";
  if (e.subject.startsWith("dns_server:")) return "/dns";
  if (e.subject.startsWith("dhcp_server:")) return "/dhcp";
  return null;
}

const EVIDENCE_LABEL: Record<string, string> = {
  alert: "Alert",
  conformity: "Conformity check",
  server: "Server health",
  agent: "Agent config",
  audit: "Change",
};

export function FindingsTab() {
  const qc = useQueryClient();
  const { can } = usePermissions();
  const mayWrite = can("write", "ai_finding");
  const [state, setState] = useState("active");
  const [severity, setSeverity] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [dismissing, setDismissing] = useState<AIFinding | null>(null);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["ai-watch", "findings", state, severity],
    queryFn: () =>
      aiWatchApi.listFindings({
        state,
        ...(severity ? { severity } : {}),
        limit: 200,
      }),
    refetchInterval: pollUnlessRefused(60_000),
    retry: false,
  });

  const refresh = () => qc.invalidateQueries({ queryKey: ["ai-watch"] });
  const act = useMutation({
    mutationFn: (v: { kind: "ack" | "reopen"; id: string }) =>
      v.kind === "ack" ? aiWatchApi.acknowledge(v.id) : aiWatchApi.reopen(v.id),
    onSuccess: refresh,
  });
  const feedback = useMutation({
    mutationFn: (v: { id: string; verdict: AIFindingVerdict }) =>
      aiWatchApi.feedback(v.id, v.verdict),
    onSuccess: refresh,
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          Show
          <select
            aria-label="Finding state"
            value={state}
            onChange={(e) => setState(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-sm text-foreground"
          >
            {STATE_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          Severity
          <select
            aria-label="Finding severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-sm text-foreground"
          >
            <option value="">Any</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>
        </label>
        {data && (
          <span className="text-xs text-muted-foreground">
            {data.total} finding{data.total === 1 ? "" : "s"}
          </span>
        )}
      </div>

      {(act.isError || feedback.isError) && (
        <div role="alert" className="text-sm text-destructive">
          {formatApiError(act.error ?? feedback.error, "The request failed")}
        </div>
      )}

      {isLoading && (
        <div className="text-sm text-muted-foreground">Loading…</div>
      )}
      {isError && !data && (
        <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
          <ListReadError error={error} what="the findings" />
        </div>
      )}
      {data && items.length === 0 && (
        <div className="rounded-md border bg-muted/20 p-6 text-center text-sm text-muted-foreground">
          {state === "active" && !severity
            ? "No open findings. Copilot Watch files one when the alerts, conformity checks or server health it reviews need explaining; it stays quiet when they do not."
            : "No findings match this filter."}
        </div>
      )}

      <ul className="space-y-2">
        {items.map((f) => {
          const open = openId === f.id;
          return (
            <li key={f.id} className="rounded-md border bg-background">
              <button
                type="button"
                aria-expanded={open}
                onClick={() => setOpenId(open ? null : f.id)}
                className="flex w-full items-start gap-2 px-3 py-2 text-left hover:bg-muted/40"
              >
                {open ? (
                  <ChevronDown className="mt-0.5 h-4 w-4 shrink-0" />
                ) : (
                  <ChevronRight className="mt-0.5 h-4 w-4 shrink-0" />
                )}
                <span
                  className={cn(
                    "mt-0.5 shrink-0 rounded px-1.5 py-px text-[10px] font-medium uppercase",
                    severityCls(f.severity),
                  )}
                >
                  {f.severity}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block break-words text-sm font-medium">
                    {f.title}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {f.kind.replace("_", " ")} · {f.evidence.length} piece
                    {f.evidence.length === 1 ? "" : "s"} of evidence · last seen{" "}
                    {fmtWhen(f.last_seen_at)}
                  </span>
                </span>
                {f.state !== "open" && (
                  <span className="shrink-0 rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
                    {f.state}
                  </span>
                )}
              </button>

              {open && (
                <div className="space-y-3 border-t px-3 py-3 text-sm">
                  <p className="whitespace-pre-wrap break-words">
                    {f.explanation}
                  </p>

                  <div>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Evidence
                    </h3>
                    <ul className="space-y-1">
                      {f.evidence.map((e) => {
                        const to = evidenceLink(e);
                        return (
                          <li
                            key={e.ref}
                            className={cn(
                              "flex flex-wrap items-baseline gap-x-2 text-xs",
                              e.cleared && "text-muted-foreground line-through",
                            )}
                          >
                            <span className="rounded bg-muted px-1 py-px text-[10px]">
                              {EVIDENCE_LABEL[e.type] ?? e.type}
                            </span>
                            {to ? (
                              <Link
                                to={to}
                                className="text-primary hover:underline"
                              >
                                {e.display}
                              </Link>
                            ) : (
                              <span>{e.display}</span>
                            )}
                            {e.detail && (
                              <span className="break-words text-muted-foreground">
                                {e.detail}
                              </span>
                            )}
                            {e.cleared && (
                              <span className="no-underline">(cleared)</span>
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  </div>

                  {f.recommendations.length > 0 && (
                    <div>
                      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                        Recommended next steps
                      </h3>
                      <ul className="list-disc space-y-0.5 pl-5 text-xs">
                        {f.recommendations.map((r, i) => (
                          <li key={i} className="break-words">
                            {r}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <p className="text-xs text-muted-foreground">
                    Written by {f.model || "a model"} from the evidence above
                    ({f.confidence} confidence). First seen{" "}
                    {fmtWhen(f.first_seen_at)}.
                    {f.state_changed_by &&
                      ` ${f.state} by ${f.state_changed_by}${
                        f.state_note ? `: ${f.state_note}` : ""
                      }.`}
                    {f.state === "resolved" &&
                      !f.state_changed_by &&
                      " Closed by Copilot Watch when the evidence cleared."}
                  </p>

                  <div className="flex flex-wrap items-center gap-2">
                    {f.state === "open" && (
                      <button
                        type="button"
                        className={btnCls}
                        onClick={() => act.mutate({ kind: "ack", id: f.id })}
                        disabled={act.isPending}
                        {...permissionGate(mayWrite, NEEDS_WRITE)}
                      >
                        <Check className="h-3.5 w-3.5" />
                        Acknowledge
                      </button>
                    )}
                    {(f.state === "open" || f.state === "acknowledged") && (
                      <button
                        type="button"
                        className={btnCls}
                        onClick={() => setDismissing(f)}
                        {...permissionGate(mayWrite, NEEDS_WRITE)}
                      >
                        <X className="h-3.5 w-3.5" />
                        Dismiss
                      </button>
                    )}
                    {(f.state === "acknowledged" ||
                      f.state === "dismissed") && (
                      <button
                        type="button"
                        className={btnCls}
                        onClick={() =>
                          act.mutate({ kind: "reopen", id: f.id })
                        }
                        disabled={act.isPending}
                        {...permissionGate(mayWrite, NEEDS_WRITE)}
                      >
                        <RotateCcw className="h-3.5 w-3.5" />
                        Reopen
                      </button>
                    )}
                    <span className="ml-auto flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                      Was this finding
                      {VERDICTS.map((v) => (
                        <button
                          key={v.value}
                          type="button"
                          aria-pressed={f.my_verdict === v.value}
                          className={cn(
                            btnCls,
                            f.my_verdict === v.value &&
                              "border-primary bg-primary/10 text-foreground",
                          )}
                          onClick={() =>
                            feedback.mutate({ id: f.id, verdict: v.value })
                          }
                          disabled={feedback.isPending}
                          {...permissionGate(mayWrite, NEEDS_WRITE)}
                        >
                          {v.label}
                        </button>
                      ))}
                    </span>
                  </div>
                </div>
              )}
            </li>
          );
        })}
      </ul>

      {dismissing && (
        <DismissModal
          finding={dismissing}
          onClose={() => setDismissing(null)}
          onDone={() => {
            setDismissing(null);
            refresh();
          }}
        />
      )}
    </div>
  );
}

function DismissModal({
  finding,
  onClose,
  onDone,
}: {
  finding: AIFinding;
  onClose: () => void;
  onDone: () => void;
}) {
  const [note, setNote] = useState("");
  const [mute, setMute] = useState("7");
  const dismiss = useMutation({
    mutationFn: () =>
      aiWatchApi.dismiss(
        finding.id,
        note.trim(),
        mute === "forever" ? null : Number(mute),
      ),
    onSuccess: onDone,
  });
  return (
    <Modal title="Dismiss finding" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p className="break-words font-medium">{finding.title}</p>
        <p className="text-xs text-muted-foreground">
          Dismissing removes the finding from the inbox. It does not change
          the alerts or checks it was built from.
        </p>
        <div>
          <label
            htmlFor="dismiss-note"
            className="mb-1 block text-xs font-medium text-muted-foreground"
          >
            Why (optional, recorded in the audit log)
          </label>
          <textarea
            id="dismiss-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={2}
            maxLength={2000}
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
          />
        </div>
        <div>
          <label
            htmlFor="dismiss-mute"
            className="mb-1 block text-xs font-medium text-muted-foreground"
          >
            If Copilot Watch finds the same thing again
          </label>
          <select
            id="dismiss-mute"
            value={mute}
            onChange={(e) => setMute(e.target.value)}
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
          >
            {MUTE_CHOICES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </div>
        {dismiss.isError && (
          <div role="alert" className="text-sm text-destructive">
            {formatApiError(dismiss.error, "Could not dismiss the finding")}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => dismiss.mutate()}
            disabled={dismiss.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            Dismiss finding
          </button>
        </div>
      </div>
    </Modal>
  );
}
