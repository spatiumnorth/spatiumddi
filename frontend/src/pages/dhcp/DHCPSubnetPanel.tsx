import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronRight,
  Pencil,
  Plus,
  Server,
  Trash2,
} from "lucide-react";
import { dhcpApi, type DHCPPool, type DHCPScope } from "@/lib/api";
import { zebraBodyCls } from "@/lib/utils";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import {
  APPROVAL_QUEUED_MESSAGE,
  CHANGE_REQUEST_QUERY_KEY,
  handleApprovalQueued,
} from "@/lib/approvalQueue";
import { CreateScopeModal } from "./CreateScopeModal";
import { CreatePoolModal } from "./CreatePoolModal";
import { DeleteConfirmModal } from "./_shared";
import { ScopeServingStrip } from "./WindowsFailoverPanel";

// #1155 — the scope and pool writes, each on the check the server makes:
// the DHCP scope and pool routers map POST / PUT to write and DELETE to
// delete, on ``dhcp_scope`` and ``dhcp_pool``. A control the caller's grants
// will not pass stays in place, disabled, with the reason as its tooltip.
const NEEDS_SCOPE_WRITE = "Requires write permission on DHCP scopes";
const NEEDS_SCOPE_DELETE = "Requires delete permission on DHCP scopes";
const NEEDS_POOL_WRITE = "Requires write permission on DHCP pools";
const NEEDS_POOL_DELETE = "Requires delete permission on DHCP pools";

function PoolRow({ pool, scope }: { pool: DHCPPool; scope: DHCPScope }) {
  const qc = useQueryClient();
  const perms = usePermissions();
  const [edit, setEdit] = useState(false);
  const [del, setDel] = useState(false);
  const mut = useMutation({
    mutationFn: () => dhcpApi.deletePool(scope.id, pool.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-pools", scope.id] });
      setDel(false);
    },
  });
  return (
    <tr className="border-b last:border-0 text-sm">
      <td className="px-3 py-1.5">{pool.name || "—"}</td>
      <td className="px-3 py-1.5 font-mono text-xs">{pool.start_ip}</td>
      <td className="px-3 py-1.5 font-mono text-xs">{pool.end_ip}</td>
      <td className="px-3 py-1.5">
        <span className="rounded-full bg-muted px-2 py-0.5 text-xs">
          {pool.pool_type}
        </span>
      </td>
      <td className="px-3 py-1.5 text-right">
        <button
          onClick={() => setEdit(true)}
          className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
          title="Edit pool"
          {...permissionGate(perms.can("write", "dhcp_pool"), NEEDS_POOL_WRITE)}
        >
          <Pencil className="h-3.5 w-3.5" />
        </button>
        <button
          onClick={() => setDel(true)}
          className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
          title="Delete pool"
          {...permissionGate(
            perms.can("delete", "dhcp_pool"),
            NEEDS_POOL_DELETE,
          )}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </td>
      {edit && (
        <CreatePoolModal
          pool={pool}
          scope={scope}
          onClose={() => setEdit(false)}
        />
      )}
      {del && (
        <DeleteConfirmModal
          title="Delete Pool"
          description={`Delete pool ${pool.start_ip} – ${pool.end_ip}?`}
          onConfirm={() => mut.mutate()}
          onClose={() => setDel(false)}
          isPending={mut.isPending}
        />
      )}
    </tr>
  );
}

function ScopeCard({ scope }: { scope: DHCPScope }) {
  const qc = useQueryClient();
  const perms = usePermissions();
  const canWriteScope = perms.can("write", "dhcp_scope");
  const [showPools, setShowPools] = useState(true);
  const [showAddPool, setShowAddPool] = useState(false);
  const [editScope, setEditScope] = useState(false);
  const [deleteScope, setDeleteScope] = useState(false);
  const [deleteNotice, setDeleteNotice] = useState<string | null>(null);

  const { data: pools = [] } = useQuery({
    queryKey: ["dhcp-pools", scope.id],
    queryFn: () => dhcpApi.listPools(scope.id),
  });

  const toggleEnabled = useMutation({
    mutationFn: (enabled: boolean) =>
      dhcpApi.updateScope(scope.id, { enabled }),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["dhcp-scopes-subnet", scope.subnet_id],
      });
    },
  });

  const delMut = useMutation({
    mutationFn: () => dhcpApi.deleteScope(scope.id),
    onSuccess: (resp) => {
      // Two-person approval (#62): a covered delete returns 202 with a
      // queued change-request instead of deleting. Surface the message,
      // refresh the approval queue, and leave the scope in place.
      if (handleApprovalQueued(resp)) {
        setDeleteNotice(APPROVAL_QUEUED_MESSAGE);
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
        return;
      }
      qc.invalidateQueries({
        queryKey: ["dhcp-scopes-subnet", scope.subnet_id],
      });
      setDeleteScope(false);
    },
  });

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <div className="flex items-center gap-3 min-w-0">
          <Server className="h-4 w-4 text-muted-foreground flex-shrink-0" />
          <div className="min-w-0">
            <p className="text-sm font-semibold truncate">
              {scope.name || `Scope ${scope.id.slice(0, 8)}`}
            </p>
            <p className="text-xs text-muted-foreground">
              Lease {scope.lease_time}s · {pools.length} pool
              {pools.length !== 1 ? "s" : ""}
              {scope.ddns_enabled && " · DDNS"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs cursor-pointer">
            <input
              type="checkbox"
              checked={scope.enabled}
              onChange={(e) => toggleEnabled.mutate(e.target.checked)}
              {...permissionGate(canWriteScope, NEEDS_SCOPE_WRITE)}
            />
            {scope.enabled ? "Enabled" : "Disabled"}
          </label>
          <button
            onClick={() => setEditScope(true)}
            className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-40"
            title="Edit scope"
            {...permissionGate(canWriteScope, NEEDS_SCOPE_WRITE)}
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={() => setDeleteScope(true)}
            className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-40"
            title="Delete scope"
            {...permissionGate(
              perms.can("delete", "dhcp_scope"),
              NEEDS_SCOPE_DELETE,
            )}
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* #1110 — renders nothing when the scope's group has no Windows members. */}
      <ScopeServingStrip scopeId={scope.id} />

      <div>
        <div className="flex items-center justify-between px-4 py-2 border-b bg-muted/30">
          <button
            onClick={() => setShowPools((v) => !v)}
            className="flex items-center gap-1 text-xs font-semibold"
          >
            {showPools ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
            Pools ({pools.length})
          </button>
          <button
            onClick={() => setShowAddPool(true)}
            className="flex items-center gap-1 text-xs text-primary hover:underline disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:no-underline"
            {...permissionGate(
              perms.can("write", "dhcp_pool"),
              NEEDS_POOL_WRITE,
            )}
          >
            <Plus className="h-3 w-3" /> Add Pool
          </button>
        </div>
        {showPools && pools.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px]">
              <thead>
                <tr className="border-b bg-muted/20 text-xs">
                  <th className="px-3 py-1.5 text-left font-medium">Name</th>
                  <th className="px-3 py-1.5 text-left font-medium">Start</th>
                  <th className="px-3 py-1.5 text-left font-medium">End</th>
                  <th className="px-3 py-1.5 text-left font-medium">Type</th>
                  <th className="px-3 py-1.5"></th>
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {pools.map((p) => (
                  <PoolRow key={p.id} pool={p} scope={scope} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showAddPool && (
        <CreatePoolModal scope={scope} onClose={() => setShowAddPool(false)} />
      )}
      {editScope && (
        <CreateScopeModal scope={scope} onClose={() => setEditScope(false)} />
      )}
      {deleteScope && (
        <DeleteConfirmModal
          title="Delete DHCP Scope"
          description={`Delete scope "${scope.name}" and all its pools?`}
          references={[`${pools.length} pool${pools.length !== 1 ? "s" : ""}`]}
          onConfirm={() => delMut.mutate()}
          onClose={() => {
            setDeleteScope(false);
            setDeleteNotice(null);
            delMut.reset();
          }}
          isPending={delMut.isPending}
          notice={deleteNotice}
        />
      )}
    </div>
  );
}

/**
 * Panel shown inside the IPAM SubnetDetail "DHCP" tab. Lists all DHCP scopes
 * defined against the given subnet, lets the user create a new scope, and
 * exposes inline pool management per scope. Static assignments are NOT managed
 * here — they are created from the IPAM "Allocate IP" modal (status
 * `static_dhcp` + scope + MAC) and viewed read-only on the DHCP server group's
 * "Static Assignments" tab.
 */
export function DHCPSubnetPanel({ subnetId }: { subnetId: string }) {
  const [showCreate, setShowCreate] = useState(false);
  const perms = usePermissions();
  const { data: scopes = [], isLoading } = useQuery({
    queryKey: ["dhcp-scopes-subnet", subnetId],
    queryFn: () => dhcpApi.listScopesBySubnet(subnetId),
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold">DHCP Scopes</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Scopes belong to the server group — every Kea server in the group
            serves them (one scope per subnet per group). Windows DHCP servers
            share a scope only through a failover relationship.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          {...permissionGate(
            perms.can("write", "dhcp_scope"),
            NEEDS_SCOPE_WRITE,
          )}
        >
          <Plus className="h-3.5 w-3.5" /> Create Scope
        </button>
      </div>

      {isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}

      {!isLoading && scopes.length === 0 && (
        <div className="rounded-lg border border-dashed p-10 text-center">
          <Server className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
          <p className="text-sm font-medium">No DHCP scopes on this subnet</p>
          <p className="mt-1 text-xs text-muted-foreground">
            Create a scope to start serving leases from a DHCP server.
          </p>
        </div>
      )}

      <div className="space-y-4">
        {scopes.map((s) => (
          <ScopeCard key={s.id} scope={s} />
        ))}
      </div>

      {showCreate && (
        <CreateScopeModal
          subnetId={subnetId}
          onClose={() => setShowCreate(false)}
        />
      )}
    </div>
  );
}
