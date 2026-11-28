import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  applianceApprovalApi,
  formatApiError,
  type PostgresSynchronousConfig,
} from "@/lib/api";
import { FormError } from "@/components/ui/form-error";
import { ListReadError } from "@/components/ui/list-read-error";
import { usePermissions } from "@/hooks/usePermissions";
import { isRefused } from "@/lib/refusal";

/**
 * #1261 — opt-in synchronous replication for the appliance's PostgreSQL
 * cluster. Off by default: replication is asynchronous and a failover can lose
 * the last few commits. The trade-off is stated next to the control because
 * "required" can stop writes.
 */
export function DatabaseReplicationCard() {
  const qc = useQueryClient();
  const { isSuperadmin, isLoading: permsLoading } = usePermissions();
  const { data, error } = useQuery({
    queryKey: ["appliance", "postgres-synchronous"],
    queryFn: applianceApprovalApi.getPostgresSynchronous,
    enabled: isSuperadmin,
  });

  const [enabled, setEnabled] = useState(false);
  const [method, setMethod] = useState<"any" | "first">("any");
  const [number, setNumber] = useState(1);
  const [durability, setDurability] = useState<"required" | "preferred">(
    "required",
  );
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!data || dirty) return;
    setEnabled(data.enabled);
    setMethod(data.method);
    setNumber(data.number);
    setDurability(data.data_durability);
  }, [data, dirty]);

  const instances = data?.instances ?? 1;
  const canEnable = instances >= 2;

  const save = useMutation({
    mutationFn: (body: PostgresSynchronousConfig) =>
      applianceApprovalApi.setPostgresSynchronous(body),
    onSuccess: (saved) => {
      qc.setQueryData(["appliance", "postgres-synchronous"], saved);
      setDirty(false);
    },
  });

  const touch =
    <T,>(set: (v: T) => void) =>
    (v: T) => {
      set(v);
      setDirty(true);
    };

  if (!isSuperadmin || isRefused(error)) {
    return (
      <section className="rounded-lg border bg-card p-4 shadow-sm">
        <h3 className="text-sm font-semibold">Database replication</h3>
        <p className="mt-2 text-xs text-muted-foreground">
          {permsLoading ? (
            "Loading…"
          ) : isRefused(error) ? (
            <ListReadError error={error} what="the replication settings" />
          ) : (
            "Viewing or changing database replication is restricted to superadmins."
          )}
        </p>
      </section>
    );
  }

  return (
    <section className="space-y-4 rounded-lg border bg-card p-4 shadow-sm">
      <div>
        <h3 className="text-sm font-semibold">Database replication</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          By default PostgreSQL replicates asynchronously: a commit returns
          before a replica has it, so a failover can lose the last few commits.
          Synchronous replication makes each commit wait for replicas to confirm
          it, so a failover loses nothing, at the cost of a replica round-trip
          on every write.
        </p>
      </div>

      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={enabled}
          disabled={!canEnable && !enabled}
          onChange={(e) => touch(setEnabled)(e.target.checked)}
        />
        Enable synchronous replication
      </label>
      {!canEnable && (
        <p className="text-xs text-muted-foreground">
          Needs at least 2 control-plane members; this cluster has {instances}.
        </p>
      )}

      {enabled && (
        <div className="space-y-3 text-sm">
          <label className="block">
            <span className="text-xs text-muted-foreground">
              Replicas that must confirm each commit (1 to {instances - 1})
            </span>
            <input
              type="number"
              min={1}
              max={Math.max(1, instances - 1)}
              value={number}
              onChange={(e) => touch(setNumber)(Number(e.target.value))}
              className="mt-1 w-24 rounded-md border bg-background px-2 py-1"
            />
          </label>
          <label className="block">
            <span className="text-xs text-muted-foreground">Method</span>
            <select
              value={method}
              onChange={(e) =>
                touch(setMethod)(e.target.value as "any" | "first")
              }
              className="mt-1 block rounded-md border bg-background px-2 py-1"
            >
              <option value="any">Any replicas (quorum)</option>
              <option value="first">First in priority order</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-muted-foreground">
              When too few synchronous replicas are available
            </span>
            <select
              value={durability}
              onChange={(e) =>
                touch(setDurability)(e.target.value as "required" | "preferred")
              }
              className="mt-1 block rounded-md border bg-background px-2 py-1"
            >
              <option value="required">
                Required: block writes until they return
              </option>
              <option value="preferred">
                Preferred: fall back to asynchronous
              </option>
            </select>
          </label>
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs">
            <strong>Required</strong> never loses a committed write, but the
            database stops accepting writes while fewer than {number} replica
            {number === 1 ? " is" : "s are"} available, so a node loss in a
            small cluster can halt writes until it is back.{" "}
            <strong>Preferred</strong> keeps writing and degrades to
            asynchronous, so a failure at that moment can lose recent commits.
            If the cluster later shrinks, the number is lowered to fit and
            synchronous replication turns off below 2 members.
          </p>
        </div>
      )}

      <FormError>{save.isError ? formatApiError(save.error) : null}</FormError>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!dirty || save.isPending}
          onClick={() =>
            save.mutate({
              enabled,
              method,
              number,
              data_durability: durability,
            })
          }
          className="rounded-md border bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          {save.isPending ? "Saving…" : "Save"}
        </button>
        {save.isSuccess && !dirty && (
          <span className="text-xs text-emerald-600">✓ Saved</span>
        )}
      </div>
    </section>
  );
}
