/**
 * Capability-aware service lifecycle control (issue #890).
 *
 * The backend answers *what this deployment can do* before anything is
 * attempted, so this renders the actions that exist rather than drawing
 * a button and learning from its 503 that the deployment never had one.
 * Three shapes come out of that:
 *
 *  - no backend        → say which mount is missing, render nothing else
 *  - backend, gated    → show the inventory read-only, with the exact
 *                        toggle to flip (env var / Helm value)
 *  - backend, enabled  → per-row actions, restricted to what the backend
 *                        supports (Kubernetes: restart only)
 *
 * Restarting the API that serves this page is allowed and flagged: the
 * request returns 202 before the daemon is signalled, so the operator
 * sees confirmation rather than a connection reset, and the row goes
 * into a "reconnecting" state instead of reporting failure.
 */

import { pollUnlessRefused } from "@/lib/refusal";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Info, Play, RefreshCw, Square } from "lucide-react";

import { ConfirmModal } from "@/components/ui/confirm-modal";
import {
  serviceControlApi,
  type ServiceAction,
  type ServiceRow,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";

const ACTION_LABEL: Record<ServiceAction, string> = {
  start: "Start",
  stop: "Stop",
  restart: "Restart",
};

const ACTION_ICON: Record<
  ServiceAction,
  typeof Play | typeof Square | typeof RefreshCw
> = {
  start: Play,
  stop: Square,
  restart: RefreshCw,
};

const BACKEND_LABEL: Record<string, string> = {
  "k3s-appliance": "Appliance (k3s)",
  kubernetes: "Kubernetes",
  compose: "Docker Compose",
  none: "None",
};

function stateTone(state: string): string {
  if (state === "running") {
    return "bg-emerald-500/20 text-emerald-700 dark:text-emerald-400";
  }
  if (state === "degraded" || state === "restarting") {
    return "bg-amber-500/20 text-amber-700 dark:text-amber-400";
  }
  if (state === "stopped" || state === "exited" || state === "created") {
    return "bg-muted text-muted-foreground";
  }
  return "bg-rose-500/20 text-rose-700 dark:text-rose-400";
}

function errorDetail(e: unknown, fallback: string): string {
  if (e && typeof e === "object" && "response" in e) {
    const resp = (e as { response?: { data?: { detail?: unknown } } }).response;
    if (resp?.data?.detail) return String(resp.data.detail);
  }
  return fallback;
}

export function ServicesPanel() {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["service-control"],
    queryFn: serviceControlApi.list,
    refetchInterval: pollUnlessRefused(10_000),
  });

  const [pending, setPending] = useState<{
    row: ServiceRow;
    action: ServiceAction;
  } | null>(null);
  const [note, setNote] = useState<{
    tone: "ok" | "error";
    text: string;
  } | null>(null);

  const actMut = useMutation({
    mutationFn: ({ row, action }: { row: ServiceRow; action: ServiceAction }) =>
      serviceControlApi.act(row.id, action),
    onSuccess: (result) => {
      setPending(null);
      setNote({
        tone: "ok",
        text: result.self_targeted
          ? `${ACTION_LABEL[result.action]} accepted for ${result.id} — this is the API serving this page, so it will briefly go away and come back.`
          : `${ACTION_LABEL[result.action]} accepted for ${result.id}.`,
      });
      // A rollout / container restart takes a few seconds to show up;
      // one delayed refetch on top of the 10 s poll makes the state
      // change visible without hammering the endpoint.
      window.setTimeout(
        () => qc.invalidateQueries({ queryKey: ["service-control"] }),
        3000,
      );
    },
    onError: (e: unknown) => {
      setPending(null);
      setNote({ tone: "error", text: errorDetail(e, "Action failed") });
    },
  });

  const cap = query.data?.capability;
  const services = query.data?.services ?? [];

  if (query.isLoading) {
    return (
      <p className="text-xs text-muted-foreground">
        Detecting lifecycle backend…
      </p>
    );
  }

  // A failed request is NOT "this deployment has no backend" — that is
  // exactly the "cannot" vs "down" confusion the capability probe exists
  // to remove, and rendering the no-backend panel here would reintroduce
  // it one layer up. A 403 (this page is reachable without superadmin)
  // and a network failure both land here.
  if (query.isError) {
    return (
      <div className="rounded border border-rose-500/40 bg-rose-500/5 p-4">
        <div className="flex items-center gap-2 text-sm font-medium text-rose-800 dark:text-rose-300">
          <AlertTriangle className="h-4 w-4" />
          Could not read the service inventory
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          {errorDetail(
            query.error,
            "The request failed. Service control is superadmin-only — if you are not a superadmin this is expected.",
          )}
        </p>
      </div>
    );
  }

  if (!cap || cap.backend === "none") {
    return (
      <div className="rounded border border-amber-500/40 bg-amber-500/5 p-4">
        <div className="flex items-center gap-2 text-sm font-medium text-amber-800 dark:text-amber-300">
          <AlertTriangle className="h-4 w-4" />
          No service-control backend on this deployment
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          {cap?.reason ??
            "The API could not determine how this deployment runs its services."}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span className="rounded bg-muted px-2 py-1 font-medium">
          Backend: {BACKEND_LABEL[cap.flavor] ?? cap.flavor}
        </span>
        <span className="text-muted-foreground">
          {cap.enabled
            ? `Actions: ${cap.supported_actions.map((a) => ACTION_LABEL[a]).join(" · ")}`
            : "Control disabled — read-only"}
        </span>
        <span className="text-muted-foreground">Auto-refresh every 10 s</span>
      </div>

      {!cap.enabled && cap.reason && (
        <div className="rounded border border-blue-500/40 bg-blue-500/5 p-3">
          <div className="flex items-center gap-2 text-xs font-medium text-blue-800 dark:text-blue-300">
            <Info className="h-3.5 w-3.5" />
            Service control is off
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{cap.reason}</p>
        </div>
      )}

      {query.data?.error && (
        <div className="rounded border border-rose-500/40 bg-rose-500/5 p-3">
          <div className="flex items-center gap-2 text-xs font-medium text-rose-800 dark:text-rose-300">
            <AlertTriangle className="h-3.5 w-3.5" />
            Backend is live but the inventory could not be read
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {query.data.error}
          </p>
        </div>
      )}

      {note && (
        <div
          className={cn(
            "rounded border p-3 text-xs",
            note.tone === "ok"
              ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-800 dark:text-emerald-300"
              : "border-rose-500/40 bg-rose-500/5 text-rose-800 dark:text-rose-300",
          )}
        >
          {note.text}
        </div>
      )}

      <div className="overflow-x-auto rounded border">
        <table className="w-full min-w-[760px] text-sm">
          <thead className="bg-muted/40 text-xs">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Service</th>
              <th className="px-3 py-2 text-left font-medium">Kind</th>
              <th className="px-3 py-2 text-left font-medium">State</th>
              <th className="px-3 py-2 text-left font-medium">Detail</th>
              <th className="px-3 py-2 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {services.length === 0 && (
              <tr>
                <td
                  colSpan={5}
                  className="px-3 py-4 text-center text-xs text-muted-foreground"
                >
                  No controllable services found.
                </td>
              </tr>
            )}
            {services.map((s) => (
              <tr key={s.id}>
                <td className="px-3 py-1.5">
                  <div className="font-medium">{s.id}</div>
                  <div className="text-[11px] text-muted-foreground">
                    {s.image || s.name}
                  </div>
                </td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground">
                  {s.kind}
                </td>
                <td className="px-3 py-1.5">
                  <span
                    className={cn(
                      "inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium",
                      stateTone(s.state),
                    )}
                  >
                    {s.state}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground">
                  {s.detail || "—"}
                </td>
                <td className="px-3 py-1.5 text-right">
                  <div className="inline-flex items-center gap-1">
                    {s.actions.length === 0 && (
                      <span className="text-[11px] text-muted-foreground">
                        —
                      </span>
                    )}
                    {s.actions.map((action) => {
                      const Icon = ACTION_ICON[action];
                      return (
                        <button
                          key={action}
                          type="button"
                          onClick={() => setPending({ row: s, action })}
                          disabled={actMut.isPending}
                          className="inline-flex items-center gap-1 rounded-md border bg-background px-2 py-1 text-[11px] hover:bg-muted disabled:cursor-not-allowed disabled:opacity-50"
                        >
                          <Icon className="h-3 w-3" />
                          {ACTION_LABEL[action]}
                        </button>
                      );
                    })}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pending && (
        <ConfirmModal
          open
          title={`${ACTION_LABEL[pending.action]} ${pending.row.id}?`}
          message={
            pending.row.kind === "container"
              ? `The container stops and starts. Anything ${pending.row.id} serves is unavailable meanwhile.`
              : `Rollout ${pending.action}: pods are replaced one at a time, so service continues if this workload has more than one replica.`
          }
          confirmLabel={ACTION_LABEL[pending.action]}
          tone="destructive"
          loading={actMut.isPending}
          onClose={() => setPending(null)}
          onConfirm={() => actMut.mutate(pending)}
        />
      )}
    </div>
  );
}
