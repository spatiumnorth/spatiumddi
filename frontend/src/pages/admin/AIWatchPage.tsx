import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, Pause, Play, RefreshCw } from "lucide-react";
import { aiWatchApi, formatApiError } from "@/lib/api";
import { usePermissions } from "@/hooks/usePermissions";
import { cn } from "@/lib/utils";
import { FormError } from "@/components/ui/form-error";
import { FindingsTab } from "./ai-watch/FindingsTab";
import { RunsTab } from "./ai-watch/RunsTab";
import { SettingsTab } from "./ai-watch/SettingsTab";
import { PAUSE_REASONS } from "./ai-watch/shared";

type Tab = "findings" | "runs" | "settings";

/** Copilot Watch (#4405): the findings inbox, the run log and the settings. */
export function AIWatchPage() {
  const qc = useQueryClient();
  const { isSuperadmin } = usePermissions();
  const [tab, setTab] = useState<Tab>("findings");

  const summary = useQuery({
    queryKey: ["ai-watch", "summary"],
    queryFn: aiWatchApi.summary,
    refetchInterval: 30_000,
  });
  const s = summary.data;

  const refresh = () => qc.invalidateQueries({ queryKey: ["ai-watch"] });
  const runNow = useMutation({
    mutationFn: () => aiWatchApi.runNow(),
    onSuccess: refresh,
  });
  const pause = useMutation({
    mutationFn: (paused: boolean) => aiWatchApi.setPaused(paused),
    onSuccess: refresh,
  });

  const status = !s
    ? null
    : !s.enabled
      ? { label: "Off", cls: "bg-muted text-muted-foreground" }
      : s.paused
        ? {
            label: PAUSE_REASONS[s.paused_reason ?? ""] ?? "Paused",
            cls: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
          }
        : {
            label: "Watching",
            cls: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
          };

  const tabs: { id: Tab; label: string }[] = [
    { id: "findings", label: "Findings" },
    { id: "runs", label: "Runs" },
    ...(isSuperadmin ? [{ id: "settings" as Tab, label: "Settings" }] : []),
  ];

  return (
    <div className="mx-auto max-w-6xl space-y-4 p-6">
      <div className="flex flex-wrap items-center gap-3">
        <Eye className="h-5 w-5 text-muted-foreground" />
        <h1 className="text-xl font-semibold">Copilot Watch</h1>
        {status && (
          <span
            className={cn("rounded-full px-2 py-0.5 text-xs", status.cls)}
            data-testid="watch-status"
          >
            {status.label}
          </span>
        )}
        {s && s.open_total > 0 && (
          <span className="text-xs text-muted-foreground">
            {s.open_total} open
          </span>
        )}
        {isSuperadmin && s?.enabled && (
          <div className="ml-auto flex gap-2">
            <button
              type="button"
              onClick={() => runNow.mutate()}
              disabled={runNow.isPending}
              className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Run now
            </button>
            <button
              type="button"
              onClick={() => pause.mutate(!s.paused)}
              disabled={pause.isPending}
              className="inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
            >
              {s.paused ? (
                <>
                  <Play className="h-3.5 w-3.5" /> Resume
                </>
              ) : (
                <>
                  <Pause className="h-3.5 w-3.5" /> Pause
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {s?.paused && s.paused_detail && (
        <p className="text-sm text-muted-foreground">{s.paused_detail}</p>
      )}
      {runNow.isError && <FormError>{formatApiError(runNow.error)}</FormError>}
      {pause.isError && <FormError>{formatApiError(pause.error)}</FormError>}

      <div className="flex gap-1 border-b">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={cn(
              "border-b-2 px-3 py-1.5 text-sm",
              tab === t.id
                ? "border-primary font-medium"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "findings" && <FindingsTab />}
      {tab === "runs" && <RunsTab />}
      {tab === "settings" && isSuperadmin && <SettingsTab />}
    </div>
  );
}
