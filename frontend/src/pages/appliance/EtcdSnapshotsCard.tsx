import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  applianceApprovalApi,
  formatApiError,
  type EtcdSnapshotRow,
} from "@/lib/api";
import { isRefused } from "@/lib/refusal";
import { Modal } from "@/components/ui/modal";

// #272 Phase 9b — etcd snapshot inventory + guided restore.
//
// Self-contained card rendered in Fleet → Control plane. The seed
// reports its local ``k3s etcd-snapshot list`` (via the ETCDSnapshotFile
// CRs) on heartbeat; this lists them and offers a guided restore. The
// restore is the MOST destructive control-plane op — a single-node
// cluster-reset that orphans every other member — so it's gated behind a
// typed-hostname confirm on top of the superadmin API gate.

function fmtBytes(n: number | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function EtcdSnapshotsCard() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["appliance", "etcd-snapshots"],
    queryFn: applianceApprovalApi.listEtcdSnapshots,
    staleTime: 20_000,
    // Poll faster while a restore is in flight so the state banner tracks
    // the host runner; idle otherwise.
    refetchInterval: (q) =>
      isRefused(q.state.error)
        ? false
        : q.state.data?.desired_restore_snapshot ||
            q.state.data?.restore_state === "restoring"
          ? 5_000
          : 30_000,
  });

  const [restoreTarget, setRestoreTarget] = useState<EtcdSnapshotRow | null>(
    null,
  );
  const [typed, setTyped] = useState("");

  const restore = useMutation({
    mutationFn: ({ name, hostname }: { name: string; hostname: string }) =>
      applianceApprovalApi.restoreEtcdSnapshot(name, hostname),
    onSuccess: (res) => {
      qc.setQueryData(["appliance", "etcd-snapshots"], res);
      setRestoreTarget(null);
      setTyped("");
    },
  });

  // Hide entirely on a docker / k8s control plane (no appliance seed).
  if (!isLoading && !data?.available) return null;

  const inFlight = !!data?.desired_restore_snapshot;
  const failed = data?.restore_state === "failed";
  const seedHostname = data?.seed_hostname ?? "";

  return (
    <section className="rounded-lg border bg-card p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">
          etcd snapshots — disaster recovery
        </h3>
        {seedHostname && (
          <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
            seed: {seedHostname}
          </span>
        )}
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        Recoverable etcd snapshots from the cluster seed (k3s takes one every
        6&nbsp;h, retains 8). Restoring is{" "}
        <strong className="text-rose-600 dark:text-rose-400">
          destructive
        </strong>{" "}
        — it resets the cluster to a single etcd member from the snapshot, and
        every other control-plane node is orphaned and must be re-paired via{" "}
        <strong>Replace</strong>. Use only for recovery from a bad cluster
        state, never routinely.
      </p>

      {/* In-flight / failed restore banner. */}
      {inFlight && (
        <div className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-700 dark:text-amber-400">
          <strong>Restore in progress</strong> —{" "}
          <span className="font-mono">{data?.desired_restore_snapshot}</span>{" "}
          (state: {data?.restore_state || "pending"}). The seed will reset +
          restart k3s; the Web UI may blip while it converges.
        </div>
      )}
      {failed && !inFlight && (
        <div className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 p-2.5 text-xs text-rose-700 dark:text-rose-400">
          <strong>Last restore failed</strong>
          {data?.restore_reason ? <> — {data.restore_reason}</> : null}. Pick a
          snapshot to retry.
        </div>
      )}

      {isLoading ? (
        <p className="mt-3 text-sm text-muted-foreground">Loading…</p>
      ) : (data?.snapshots.length ?? 0) === 0 ? (
        <p className="mt-3 text-sm text-muted-foreground">
          No snapshots reported yet (the seed reports them on heartbeat; a fresh
          cluster takes its first within ~6&nbsp;h, or run{" "}
          <code>k3s etcd-snapshot save</code> on the seed for one now).
        </p>
      ) : (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[36rem] text-left text-xs">
            <thead className="text-muted-foreground">
              <tr className="border-b">
                <th className="py-1.5 pr-3 font-medium">Snapshot</th>
                <th className="py-1.5 pr-3 font-medium">Node</th>
                <th className="py-1.5 pr-3 font-medium">Size</th>
                <th className="py-1.5 pr-3 font-medium">Created</th>
                <th className="py-1.5" />
              </tr>
            </thead>
            <tbody>
              {data?.snapshots.map((s) => (
                <tr
                  key={`${s.node_name}/${s.name}`}
                  className="border-b last:border-0"
                >
                  <td className="py-1.5 pr-3 font-mono break-all">{s.name}</td>
                  <td className="py-1.5 pr-3">{s.node_name || "—"}</td>
                  <td className="py-1.5 pr-3 tabular-nums">
                    {fmtBytes(s.size)}
                  </td>
                  <td className="py-1.5 pr-3 whitespace-nowrap">
                    {fmtTime(s.created_at)}
                  </td>
                  <td className="py-1.5 text-right">
                    <button
                      type="button"
                      disabled={inFlight}
                      onClick={() => {
                        setRestoreTarget(s);
                        setTyped("");
                      }}
                      className="rounded-md border border-rose-500/40 px-2 py-1 text-rose-600 hover:bg-rose-500/10 disabled:opacity-40 dark:text-rose-400"
                    >
                      Restore…
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Guided restore confirm — typed-hostname gate on the destructive op. */}
      {restoreTarget && (
        <Modal
          title="Restore etcd snapshot?"
          onClose={() => {
            setRestoreTarget(null);
            setTyped("");
          }}
        >
          <div className="space-y-3 text-sm">
            <div className="rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-700 dark:text-rose-400">
              <p className="font-semibold">
                This is a destructive, single-node cluster-reset.
              </p>
              <ul className="mt-1 list-disc space-y-0.5 pl-4">
                <li>
                  The seed resets etcd to a 1-member cluster restored from this
                  snapshot, then restarts k3s.
                </li>
                <li>
                  Every <strong>other</strong> control-plane member is orphaned
                  and must be re-paired afterwards via <strong>Replace</strong>.
                </li>
                <li>The Web UI / API will blip while the seed converges.</li>
              </ul>
            </div>
            <p className="text-xs text-muted-foreground">
              Restoring{" "}
              <span className="font-mono break-all">{restoreTarget.name}</span>{" "}
              (node {restoreTarget.node_name || "—"},{" "}
              {fmtTime(restoreTarget.created_at)}).
            </p>
            <div className="flex flex-col gap-1">
              <span className="text-xs font-medium text-muted-foreground">
                Type the seed hostname{" "}
                <span className="font-mono">{seedHostname}</span> to confirm
              </span>
              <input
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                placeholder={seedHostname}
                className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                autoFocus
              />
            </div>
            {restore.isError && (
              <p className="text-xs text-rose-600">
                {formatApiError(restore.error)}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setRestoreTarget(null);
                  setTyped("");
                }}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={typed.trim() !== seedHostname || restore.isPending}
                onClick={() =>
                  restore.mutate({
                    name: restoreTarget.name,
                    hostname: typed.trim(),
                  })
                }
                className="rounded-md border border-rose-500/50 bg-rose-600 px-3 py-1.5 text-sm text-white hover:bg-rose-700 disabled:opacity-40"
              >
                {restore.isPending ? "Restoring…" : "Restore snapshot"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </section>
  );
}
