import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertCircle,
  Container as ContainerIcon,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  ScrollText,
  Square,
} from "lucide-react";

import {
  applianceContainersApi,
  streamApplianceContainerLogs,
  type ApplianceContainer,
  type ContainerAction,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import {
  useApplianceAdminGate,
  useCanReadApplianceLogs,
} from "@/hooks/useApplianceAdmin";

/**
 * Phase 4d (rewritten as Phase 11 wave 4) — Pod management tab.
 *
 * Lists pods in the spatium namespace via the api's mounted
 * ServiceAccount → in-cluster kubeapi, with SpatiumDDI-owned pods
 * (``app.kubernetes.io/part-of=spatiumddi``) pinned first. The
 * "Restart" button hits /containers/{name}/restart which deletes
 * the pod via kubeapi; the owning Deployment / DaemonSet then
 * recreates it on the next reconcile (~1–5 s). "Logs" opens a
 * modal that streams the pod's stdout/stderr via SSE backed by
 * kubeapi's ``follow=true`` pod-log endpoint.
 *
 * Only spatium-owned pods get the restart button by default;
 * cluster-system pods (coredns / local-path-provisioner) are
 * read-only because restarting them on a single-node appliance
 * is an operator footgun.
 */
export function ContainersTab() {
  const qc = useQueryClient();
  const [logsTarget, setLogsTarget] = useState<ApplianceContainer | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["appliance", "containers"],
    queryFn: applianceContainersApi.list,
    refetchInterval: 5_000,
  });

  const action = useMutation({
    mutationFn: ({ name, action }: { name: string; action: ContainerAction }) =>
      applianceContainersApi.action(name, action),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["appliance", "containers"] }),
  });

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold">
            <ContainerIcon className="h-4 w-4 text-muted-foreground" />
            Pods
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">
            All pods in the spatium namespace, listed via the api pod's
            in-cluster ServiceAccount. SpatiumDDI-owned pods are pinned to the
            top. Logs stream live (kubeapi ``follow=true``); Restart deletes the
            pod so the owning Deployment / DaemonSet recreates it.
          </p>
        </div>
        <button
          type="button"
          onClick={() =>
            qc.invalidateQueries({ queryKey: ["appliance", "containers"] })
          }
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-accent"
          title="Refresh now"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {formatApiError(error)}
        </div>
      )}
      {/* A refused Restart / Stop / Start used to say nothing (#1342). */}
      {action.isError && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {formatApiError(action.error, "Pod action failed")}
        </div>
      )}

      {isLoading ? (
        <div className="py-12 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : !data || data.length === 0 ? (
        <div className="rounded-lg border border-dashed bg-muted/30 px-6 py-12 text-center text-sm text-muted-foreground">
          No pods visible. The api's ServiceAccount may not be wired up — check
          the chart's ``api.serviceAccount.enabled`` value.
        </div>
      ) : (
        <div className="space-y-2">
          {data.map((c) => (
            <ContainerCard
              key={c.short_id || c.name}
              container={c}
              onAction={(act) => action.mutate({ name: c.name, action: act })}
              onLogs={() => setLogsTarget(c)}
              busy={action.isPending && action.variables?.name === c.name}
            />
          ))}
        </div>
      )}

      {logsTarget && (
        <LogsStreamModal
          container={logsTarget}
          onClose={() => setLogsTarget(null)}
        />
      )}
    </div>
  );
}

function ContainerCard({
  container,
  onAction,
  onLogs,
  busy,
}: {
  container: ApplianceContainer;
  onAction: (action: ContainerAction) => void;
  onLogs: () => void;
  busy: boolean;
}) {
  // #1342 — a pod's Restart / Stop / Start takes `admin` on `appliance`.
  const applianceGate = useApplianceAdminGate();
  // Pod log text takes `admin` on `appliance`; the button is not drawn
  // for a role that would be refused.
  const canReadLogs = useCanReadApplianceLogs();
  const isRunning = container.state === "running";
  const healthTone =
    container.health === "healthy"
      ? "text-emerald-600 dark:text-emerald-400"
      : container.health === "unhealthy"
        ? "text-destructive"
        : container.health === "starting"
          ? "text-amber-600 dark:text-amber-400"
          : "text-muted-foreground";

  return (
    <div
      className={`rounded-lg border bg-card px-3 py-2 shadow-sm ${
        container.is_spatium ? "" : "opacity-80"
      }`}
    >
      <div className="flex items-center gap-3">
        <StatusDot state={container.state} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className="truncate text-sm font-medium">
              {container.name}
            </span>
            <span className="font-mono text-[10px] text-muted-foreground">
              {container.short_id}
            </span>
            {container.health && (
              <span
                className={`inline-flex items-center gap-0.5 text-[10px] uppercase tracking-wide ${healthTone}`}
              >
                <Activity className="h-2.5 w-2.5" />
                {container.health}
              </span>
            )}
          </div>
          <div className="mt-0.5 flex items-baseline gap-2 text-[11px] text-muted-foreground">
            <span className="truncate font-mono">{container.image}</span>
            <span className="shrink-0">·</span>
            <span className="truncate">{container.status}</span>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {canReadLogs && (
            <button
              type="button"
              onClick={onLogs}
              className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-xs hover:bg-accent"
              title="Stream logs"
            >
              <ScrollText className="h-3 w-3" />
              Logs
            </button>
          )}
          {container.is_spatium && isRunning && (
            <>
              <ActionButton
                icon={RotateCcw}
                label="Restart"
                onClick={() => onAction("restart")}
                disabled={busy}
                {...applianceGate}
              />
              <ActionButton
                icon={Square}
                label="Stop"
                onClick={() => onAction("stop")}
                disabled={busy}
                destructive
                {...applianceGate}
              />
            </>
          )}
          {container.is_spatium && !isRunning && (
            <ActionButton
              icon={Play}
              label="Start"
              onClick={() => onAction("start")}
              disabled={busy}
              {...applianceGate}
            />
          )}
        </div>
      </div>
    </div>
  );
}

function ActionButton({
  icon: Icon,
  label,
  onClick,
  disabled,
  destructive,
  title,
}: {
  icon: typeof Play;
  label: string;
  onClick: () => void;
  disabled?: boolean;
  destructive?: boolean;
  /** Tooltip; the reason while denied (#1342). Defaults to the label. */
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title ?? label}
      className={`inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-xs disabled:cursor-not-allowed disabled:opacity-50 ${
        destructive
          ? "text-destructive hover:bg-destructive/10"
          : "hover:bg-accent"
      }`}
    >
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}

function StatusDot({ state }: { state: string }) {
  const cls =
    state === "running"
      ? "bg-emerald-500"
      : state === "restarting"
        ? "bg-amber-500"
        : state === "exited" || state === "dead"
          ? "bg-destructive"
          : "bg-muted-foreground/50";
  return (
    <span className={`h-2 w-2 shrink-0 rounded-full ${cls}`} title={state} />
  );
}

function LogsStreamModal({
  container,
  onClose,
}: {
  container: ApplianceContainer;
  onClose: () => void;
}) {
  const [lines, setLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    (async () => {
      // The server ends a log stream periodically (it re-validates the
      // session and the token's lifetime); reconnect without re-tailing
      // so lines aren't repeated.
      let tail = 200;
      try {
        while (!ctrl.signal.aborted) {
          for await (const line of streamApplianceContainerLogs(
            container.name,
            ctrl.signal,
            tail,
          )) {
            setLines((prev) => {
              // Cap buffer at 2000 lines so a chatty container doesn't
              // blow up React memory + keep the DOM small.
              const next = [...prev, line];
              if (next.length > 2000) next.splice(0, next.length - 2000);
              return next;
            });
          }
          tail = 0;
          await new Promise((r) => setTimeout(r, 2000));
        }
      } catch (e) {
        if (!ctrl.signal.aborted) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    return () => ctrl.abort();
  }, [container.name]);

  // Auto-scroll to bottom unless the user paused (scrolled up).
  useEffect(() => {
    if (paused) return;
    const el = containerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines, paused]);

  const onScroll = () => {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 50;
    setPaused(!atBottom);
  };

  return (
    <Modal title={`Logs · ${container.name}`} onClose={onClose} wide>
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <Activity className="h-3 w-3 text-emerald-500" />
          Live stream · {lines.length} line{lines.length === 1 ? "" : "s"}
          {paused && (
            <button
              type="button"
              onClick={() => setPaused(false)}
              className="ml-auto inline-flex items-center gap-1 rounded-md border bg-background px-2 py-0.5 text-[11px] hover:bg-accent"
              title="Jump to bottom + resume auto-scroll"
            >
              <Pause className="h-3 w-3" />
              Paused — click to resume
            </button>
          )}
        </div>
        {error && (
          <div className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>{error}</span>
          </div>
        )}
        <div
          ref={containerRef}
          onScroll={onScroll}
          className="h-96 overflow-auto rounded-md border bg-muted/30 px-3 py-2 font-mono text-[11px] leading-tight"
        >
          {lines.length === 0 && !error ? (
            <span className="text-muted-foreground">Waiting for logs…</span>
          ) : (
            lines.map((line, i) => (
              <div key={i} className="whitespace-pre-wrap">
                {line}
              </div>
            ))
          )}
        </div>
      </div>
    </Modal>
  );
}
