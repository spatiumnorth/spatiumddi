import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Power,
  ShieldAlert,
  Wrench,
} from "lucide-react";

import { applianceSystemApi, formatApiError } from "@/lib/api";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { useApplianceAdminGate } from "@/hooks/useApplianceAdmin";

/**
 * Phase 4f — Maintenance tab.
 *
 * Two operator actions:
 *  1. Toggle maintenance-mode flag (file-backed; recorded and shown,
 *     nothing reads it yet — #2618).
 *  2. Schedule a host reboot (writes a trigger file; host-side
 *     systemd Path unit waits 10 s, hands the PostgreSQL primary off
 *     when this node holds it (#2974), then runs ``systemctl reboot``).
 *
 * Plus the reboot-pending banner mirrored from the Network tab so
 * operators don't have to flip back and forth.
 */
export function MaintenanceTab() {
  // #1342 — every appliance action takes `admin` on `appliance`.
  const applianceGate = useApplianceAdminGate();
  const qc = useQueryClient();
  const [confirmReboot, setConfirmReboot] = useState(false);

  const info = useQuery({
    queryKey: ["appliance", "system", "info"],
    queryFn: applianceSystemApi.info,
    // #3008 — a reboot started from Fleet or the console can be seconds
    // from request to the node going down; 15 s missed it entirely. The
    // endpoint is a few file stats, and only this open tab polls this fast.
    refetchInterval: (q) =>
      q.state.data?.reboot_scheduled || q.state.data?.reboot_in_progress
        ? 2_000
        : 5_000,
  });

  const toggleMaint = useMutation({
    mutationFn: (enabled: boolean) =>
      applianceSystemApi.setMaintenance(enabled),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["appliance", "system", "info"] }),
  });

  const reboot = useMutation({
    mutationFn: applianceSystemApi.reboot,
    onSuccess: () => {
      setConfirmReboot(false);
      qc.invalidateQueries({ queryKey: ["appliance", "system", "info"] });
    },
  });

  const data = info.data;
  // #3008 — the trigger file is renamed before the primary handoff, so
  // reboot_scheduled reads false while the handoff runs; reboot_in_progress
  // (the host wrapper's lock) covers that until the node goes down.
  const rebootUnderway = !!(data?.reboot_scheduled || data?.reboot_in_progress);

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div>
        <h2 className="flex items-center gap-2 text-base font-semibold">
          <Wrench className="h-4 w-4 text-muted-foreground" />
          Maintenance
        </h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Maintenance mode is a soft flag: it is recorded and shown, and nothing
          drains DNS/DHCP traffic from it yet. Reboot is a real reboot — the api
          schedules it via a host-side service with a 10-second grace.
        </p>
      </div>

      {/* A refused toggle or reboot used to say nothing (#1342). */}
      {(toggleMaint.isError || reboot.isError) && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {formatApiError(
            toggleMaint.error ?? reboot.error,
            "Maintenance action failed",
          )}
        </div>
      )}

      {rebootUnderway && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-xs">
          <Activity className="mt-0.5 h-4 w-4 shrink-0 animate-pulse text-amber-600 dark:text-amber-400" />
          <div className="text-amber-700 dark:text-amber-400">
            <strong>
              Reboot in flight{data?.node ? ` on ${data.node}` : ""}.
            </strong>{" "}
            The host calls <code>systemctl reboot</code> after a short grace (10
            s from this page), and on the node holding the database primary only
            once the primary has moved to another node (up to a few minutes). A
            reboot started from Fleet or the console shows here too. The browser
            may lose connection shortly.
          </div>
        </div>
      )}

      {data?.reboot_pending_from_host && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-xs">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <div className="text-amber-700 dark:text-amber-400">
            Unattended-upgrades installed a kernel or libc update — a reboot is
            needed to actually activate it.
          </div>
        </div>
      )}

      <section className="rounded-lg border bg-card p-4 shadow-sm">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="flex items-center gap-1.5 text-sm font-semibold">
              <ShieldAlert className="h-3.5 w-3.5 text-muted-foreground" />
              Maintenance mode
            </h3>
            <p className="mt-0.5 text-[11px] text-muted-foreground">
              Records that this appliance is under maintenance and shows it
              here. No scheduled task, agent or service reads the flag yet, so
              turning it on does not stop DNS records or DHCP leases being
              issued or renewed, and existing leases keep being served.
            </p>
          </div>
          <button
            type="button"
            onClick={() => toggleMaint.mutate(!data?.maintenance_mode)}
            disabled={toggleMaint.isPending || !data}
            className={`inline-flex shrink-0 items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium ${
              data?.maintenance_mode
                ? "border-amber-500/50 bg-amber-500/10 text-amber-700 hover:bg-amber-500/20 dark:text-amber-400"
                : "bg-background hover:bg-accent"
            } disabled:opacity-50`}
            {...applianceGate}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            {data?.maintenance_mode ? "Disable" : "Enable"}
          </button>
        </div>
      </section>

      <section className="rounded-lg border bg-card p-4 shadow-sm">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="flex items-center gap-1.5 text-sm font-semibold">
              <Power className="h-3.5 w-3.5 text-destructive" />
              Reboot host
            </h3>
            <p className="mt-0.5 text-[11px] text-muted-foreground">
              Reboots the OS (not just the container stack). Useful after an
              unattended-upgrade kernel install. 10-second grace before the host
              actually issues <code>systemctl reboot</code>; on the node holding
              the database primary, the primary moves to another node first (up
              to a few minutes).
            </p>
          </div>
          <button
            type="button"
            onClick={() => setConfirmReboot(true)}
            disabled={rebootUnderway}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-destructive/40 bg-background px-3 py-1.5 text-sm font-medium text-destructive hover:bg-destructive/10 disabled:opacity-50"
            {...applianceGate}
          >
            <Power className="h-3.5 w-3.5" />
            {rebootUnderway ? "Already scheduled" : "Reboot now"}
          </button>
        </div>
      </section>

      <ConfirmModal
        open={confirmReboot}
        title="Reboot appliance?"
        message={
          <span>
            The host will power-cycle in ~10 seconds (up to a few minutes on the
            node holding the database primary, which moves to another node
            first). Existing DHCP leases keep their state (DB-backed); DNS zones
            reload from the served config; the web UI will be unreachable for ~1
            minute.
          </span>
        }
        confirmLabel="Reboot now"
        tone="destructive"
        onClose={() => !reboot.isPending && setConfirmReboot(false)}
        onConfirm={() => reboot.mutate()}
        loading={reboot.isPending}
      />
    </div>
  );
}
