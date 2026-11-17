import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, XCircle } from "lucide-react";

import {
  formatApiError,
  timeBoundGrantsApi,
  type TimeBoundGrant,
} from "@/lib/api";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { CreateTimeBoundGrantModal } from "./CreateTimeBoundGrantModal";

// Human-readable "in 3h" / "expired 5m ago" countdown relative to now.
function relativeTo(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  const past = ms < 0;
  const abs = Math.abs(ms);
  const mins = Math.round(abs / 60000);
  let label: string;
  if (mins < 60) label = `${mins}m`;
  else if (mins < 60 * 24) label = `${Math.round(mins / 60)}h`;
  else label = `${Math.round(mins / 1440)}d`;
  return past ? `expired ${label} ago` : `in ${label}`;
}

function StatusChip({ grant }: { grant: TimeBoundGrant }) {
  if (grant.revoked_at) {
    return (
      <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
        revoked
      </span>
    );
  }
  if (grant.is_active) {
    return (
      <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 text-xs text-emerald-600 dark:text-emerald-400">
        active
      </span>
    );
  }
  return (
    <span className="rounded-full bg-amber-500/15 px-2 py-0.5 text-xs text-amber-600 dark:text-amber-400">
      expired
    </span>
  );
}

function GrantsTable({
  grants,
  onRevoke,
}: {
  grants: TimeBoundGrant[];
  onRevoke: (g: TimeBoundGrant) => void;
}) {
  if (grants.length === 0) {
    return (
      <p className="px-1 py-3 text-xs text-muted-foreground">
        No grants in this view.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full min-w-[640px] text-sm">
        <thead>
          <tr className="border-b bg-muted/50 text-xs">
            <th className="px-3 py-2 text-left font-medium">Permission</th>
            <th className="px-3 py-2 text-left font-medium">Scope</th>
            <th className="px-3 py-2 text-left font-medium">Status</th>
            <th className="px-3 py-2 text-left font-medium">Expires</th>
            <th className="px-3 py-2 text-left font-medium">Reason</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {grants.map((g) => (
            <tr key={g.id} className="border-b last:border-0 hover:bg-muted/20">
              <td className="px-3 py-2 font-medium">
                {g.action} <span className="text-muted-foreground">on</span>{" "}
                {g.resource_type}
              </td>
              <td className="px-3 py-2 text-xs text-muted-foreground">
                {g.resource_id ? (
                  <span className="break-all">{g.resource_id}</span>
                ) : (
                  <span className="opacity-60">any instance</span>
                )}
              </td>
              <td className="px-3 py-2">
                <StatusChip grant={g} />
              </td>
              <td className="px-3 py-2 text-xs text-muted-foreground">
                <span title={new Date(g.expires_at).toLocaleString()}>
                  {relativeTo(g.expires_at)}
                </span>
              </td>
              <td className="px-3 py-2 text-xs text-muted-foreground">
                {g.reason || <span className="opacity-40">—</span>}
              </td>
              <td className="px-3 py-2 text-right">
                {!g.revoked_at && g.is_active && (
                  <button
                    onClick={() => onRevoke(g)}
                    className="inline-flex items-center gap-1 rounded p-1 text-muted-foreground hover:text-destructive"
                    title="Revoke now"
                  >
                    <XCircle className="h-3.5 w-3.5" />
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function TimeBoundGrantsPanel({
  groupId,
  groupName,
}: {
  groupId: string;
  groupName: string;
}) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<TimeBoundGrant | null>(null);

  const { data: grants, isLoading } = useQuery({
    queryKey: ["time-bound-grants", groupId],
    queryFn: () => timeBoundGrantsApi.list(groupId, true),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => timeBoundGrantsApi.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["time-bound-grants", groupId] });
      setRevokeTarget(null);
    },
  });

  const { active, history } = useMemo(() => {
    const all = grants ?? [];
    return {
      active: all.filter((g) => g.is_active && !g.revoked_at),
      history: all.filter((g) => !g.is_active || g.revoked_at),
    };
  }, [grants]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">Time-bound grants</h3>
          <p className="text-xs text-muted-foreground">
            Temporary permissions that add to this group's roles and
            auto-expire.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-3.5 w-3.5" />
          Grant temporary access
        </button>
      </div>

      {isLoading ? (
        <p className="px-1 py-3 text-xs text-muted-foreground">Loading…</p>
      ) : (
        <div className="space-y-4">
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground">Active</p>
            <GrantsTable grants={active} onRevoke={setRevokeTarget} />
          </div>
          <div className="space-y-1">
            <p className="text-xs font-medium text-muted-foreground">
              Expired / revoked
            </p>
            <GrantsTable grants={history} onRevoke={setRevokeTarget} />
          </div>
        </div>
      )}

      {showCreate && (
        <CreateTimeBoundGrantModal
          groupId={groupId}
          groupName={groupName}
          onClose={() => setShowCreate(false)}
        />
      )}

      <ConfirmModal
        open={revokeTarget !== null}
        title="Revoke grant"
        tone="destructive"
        confirmLabel="Revoke now"
        loading={revokeMutation.isPending}
        error={
          revokeMutation.error
            ? formatApiError(revokeMutation.error, "Revoke failed")
            : null
        }
        message={
          revokeTarget ? (
            <>
              Revoke{" "}
              <strong className="text-foreground">
                {revokeTarget.action} on {revokeTarget.resource_type}
              </strong>{" "}
              for group <strong className="text-foreground">{groupName}</strong>
              ? The grant row is kept for audit history.
            </>
          ) : (
            ""
          )
        }
        onConfirm={() => revokeTarget && revokeMutation.mutate(revokeTarget.id)}
        onClose={() => {
          setRevokeTarget(null);
          revokeMutation.reset();
        }}
      />
    </div>
  );
}
