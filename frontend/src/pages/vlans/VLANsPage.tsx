import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Router as RouterIcon,
  Plus,
  Pencil,
  RefreshCw,
  Trash2,
  Tag,
} from "lucide-react";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import {
  vlansApi,
  ipamApi,
  SUBNET_ROLE_LABELS,
  type Router,
  type VLAN,
  type Subnet,
  type SubnetRole,
  formatApiError,
} from "@/lib/api";
import { ResizablePane } from "@/components/ui/resizable-pane";
import { copyToClipboard } from "@/lib/clipboard";
import { cn, zebraBodyCls } from "@/lib/utils";

/** Small pill rendering for ``Subnet.subnet_role`` (issue #112 phase
 *  2). Voice gets a sky-blue accent so a fleet of voice VLANs is
 *  easy to spot in the VLAN list. Other roles + null get muted /
 *  neutral styling so they don't compete visually. */
function SubnetRoleChip({ role }: { role: SubnetRole | null }) {
  if (!role) return <span className="text-muted-foreground/60">—</span>;
  const cls =
    role === "voice"
      ? "bg-sky-500/10 text-sky-700 dark:text-sky-300"
      : role === "management"
        ? "bg-violet-500/10 text-violet-700 dark:text-violet-300"
        : role === "guest"
          ? "bg-amber-500/10 text-amber-700 dark:text-amber-300"
          : "bg-muted text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex rounded px-1.5 py-0.5 text-[11px] font-medium",
        cls,
      )}
    >
      {SUBNET_ROLE_LABELS[role]}
    </span>
  );
}
import { useTableSort, SortableTh } from "@/lib/useTableSort";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuLabel,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
    </div>
  );
}

type Selection =
  | { kind: "router"; id: string }
  | { kind: "vlan"; id: string; routerId: string }
  | null;

export function VLANsPage() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write on 'vlan'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "vlan"),
    "Requires write permission on VLANs",
  );
  const qc = useQueryClient();
  const [selection, setSelection] = useState<Selection>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [showCreateRouter, setShowCreateRouter] = useState(false);

  const {
    data: routers = [],
    isLoading,
    isFetching,
  } = useQuery({
    queryKey: ["vlans", "routers"],
    queryFn: vlansApi.listRouters,
  });

  // Broad invalidate — ``["vlans"]`` is a prefix for router list,
  // per-router vlan lists, and per-vlan detail queries. Also clears
  // subnet-by-vlan so the VLAN detail pane re-fetches.
  const refreshVlans = () => {
    qc.invalidateQueries({ queryKey: ["vlans"] });
    qc.invalidateQueries({ queryKey: ["subnets-by-vlan"] });
  };

  function toggleExpand(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="flex h-[calc(100vh-3.5rem)]">
      {/* Sidebar */}
      <ResizablePane
        storageKey="vlans"
        defaultWidth={288}
        label="Resize routers tree"
        as="aside"
        className="border-r bg-card overflow-y-auto"
      >
        <div className="flex items-center justify-between px-3 py-2 border-b">
          <h2 className="text-sm font-semibold">Routers</h2>
          <div className="flex items-center gap-1">
            <button
              onClick={refreshVlans}
              disabled={isFetching}
              title="Refresh routers, VLANs, and subnet-by-VLAN data"
              className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-accent-foreground disabled:opacity-50"
            >
              <RefreshCw
                className={cn("h-4 w-4", isFetching && "animate-spin")}
              />
            </button>
            <button
              onClick={() => setShowCreateRouter(true)}
              title="New Router"
              className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-accent-foreground disabled:cursor-not-allowed disabled:opacity-50"
              {...writeGate}
            >
              <Plus className="h-4 w-4" />
            </button>
          </div>
        </div>
        <div className="p-2 space-y-1">
          {isLoading && (
            <p className="text-xs text-muted-foreground italic px-2">
              Loading…
            </p>
          )}
          {!isLoading && routers.length === 0 && (
            <p className="text-xs text-muted-foreground italic px-2 py-4">
              No routers yet. Click + to add one.
            </p>
          )}
          {routers.map((r) => (
            <RouterSidebarItem
              key={r.id}
              router={r}
              expanded={expanded.has(r.id)}
              selection={selection}
              onToggle={() => toggleExpand(r.id)}
              onSelect={setSelection}
            />
          ))}
        </div>
      </ResizablePane>

      {/* Main detail */}
      <main className="flex-1 overflow-y-auto p-6">
        {selection === null && (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
            <RouterIcon className="h-12 w-12 mb-2 opacity-40" />
            <p className="text-sm">Select a router or VLAN to view details.</p>
          </div>
        )}
        {selection?.kind === "router" && (
          <RouterDetail
            routerId={selection.id}
            onSelectVlan={(vlanId, routerId) =>
              setSelection({ kind: "vlan", id: vlanId, routerId })
            }
            onDeleted={() => setSelection(null)}
          />
        )}
        {selection?.kind === "vlan" && (
          <VLANDetail
            vlanId={selection.id}
            routerId={selection.routerId}
            onDeleted={() =>
              setSelection({ kind: "router", id: selection.routerId })
            }
          />
        )}
      </main>

      {showCreateRouter && (
        <CreateRouterModal onClose={() => setShowCreateRouter(false)} />
      )}
    </div>
  );
}

function RouterSidebarItem({
  router,
  expanded,
  selection,
  onToggle,
  onSelect,
}: {
  router: Router;
  expanded: boolean;
  selection: Selection;
  onToggle: () => void;
  onSelect: (s: Selection) => void;
}) {
  const { data: vlans = [] } = useQuery({
    queryKey: ["vlans", router.id],
    queryFn: () => vlansApi.listVlans(router.id),
    enabled: expanded,
  });
  const isActive = selection?.kind === "router" && selection.id === router.id;
  return (
    <div>
      <div
        className={cn(
          "flex items-center gap-1 rounded-md px-1 py-1 text-sm cursor-pointer",
          isActive
            ? "bg-primary/10 text-primary"
            : "hover:bg-accent hover:text-accent-foreground",
        )}
      >
        <button
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          className="flex h-4 w-4 flex-shrink-0 items-center justify-center rounded-sm border border-border bg-background text-[10px] font-bold text-muted-foreground hover:border-primary hover:text-primary"
          title={expanded ? "Collapse" : "Expand"}
        >
          {expanded ? "−" : "+"}
        </button>
        <button
          onClick={() => onSelect({ kind: "router", id: router.id })}
          className="flex flex-1 items-center gap-2 min-w-0"
        >
          <RouterIcon className="h-4 w-4 flex-shrink-0 text-blue-600 dark:text-blue-400" />
          <span className="truncate">{router.name}</span>
          <span className="ml-auto text-[10px] text-muted-foreground">
            {vlans.length || ""}
          </span>
        </button>
      </div>
      {expanded && (
        <div className="ml-5 border-l pl-2 mt-0.5 space-y-0.5">
          {vlans.length === 0 && (
            <p className="text-[11px] text-muted-foreground italic py-1">
              No VLANs
            </p>
          )}
          {vlans.map((v) => {
            const isVSel = selection?.kind === "vlan" && selection.id === v.id;
            return (
              <button
                key={v.id}
                onClick={() =>
                  onSelect({ kind: "vlan", id: v.id, routerId: router.id })
                }
                className={cn(
                  "flex w-full items-center gap-2 rounded-md px-2 py-1 text-xs",
                  isVSel
                    ? "bg-primary/10 text-primary"
                    : "hover:bg-accent hover:text-accent-foreground",
                )}
              >
                <Tag className="h-3 w-3 flex-shrink-0 text-emerald-600 dark:text-emerald-400" />
                <span className="font-mono">{v.vlan_id}</span>
                <span className="truncate text-muted-foreground">{v.name}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function RouterDetail({
  routerId,
  onSelectVlan,
  onDeleted,
}: {
  routerId: string;
  onSelectVlan: (vlanId: string, routerId: string) => void;
  onDeleted: () => void;
}) {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'vlan'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "vlan"),
    "Requires write permission on VLANs",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "vlan"),
    "Requires delete permission on VLANs",
  );
  const qc = useQueryClient();
  const [showEdit, setShowEdit] = useState(false);
  const [showCreateVlan, setShowCreateVlan] = useState(false);
  const [deleteStep, setDeleteStep] = useState<0 | 1 | 2>(0);
  const [deleteChecked, setDeleteChecked] = useState(false);

  const { data: router } = useQuery({
    queryKey: ["vlans", "router", routerId],
    queryFn: () => vlansApi.getRouter(routerId),
  });
  const { data: vlans = [] } = useQuery({
    queryKey: ["vlans", routerId],
    queryFn: () => vlansApi.listVlans(routerId),
  });

  type VlanCol = "tag" | "name" | "description";
  const {
    sorted: sortedVlans,
    sort,
    toggle,
  } = useTableSort<VLAN, VlanCol>(
    vlans,
    { key: "tag", dir: "asc" },
    (row, key) => {
      if (key === "tag") return row.vlan_id;
      if (key === "name") return row.name ?? "";
      if (key === "description") return row.description ?? "";
      return "";
    },
  );

  const [deleteError, setDeleteError] = useState<string | null>(null);
  const deleteMut = useMutation({
    mutationFn: () => vlansApi.deleteRouter(routerId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vlans", "routers"] });
      qc.invalidateQueries({ queryKey: ["vlans", routerId] });
      onDeleted();
    },
    onError: (err: unknown) => {
      setDeleteError(formatApiError(err, "Failed to delete router"));
    },
  });

  if (!router) return <p className="text-sm text-muted-foreground">Loading…</p>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <RouterIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
          <h1 className="text-lg font-semibold">{router.name}</h1>
        </div>
        <div className="flex items-center gap-2">
          <HeaderButton
            icon={Pencil}
            onClick={() => setShowEdit(true)}
            {...writeGate}
          >
            Edit
          </HeaderButton>
          <HeaderButton
            variant="destructive"
            icon={Trash2}
            onClick={() => {
              setDeleteChecked(false);
              setDeleteError(null);
              setDeleteStep(1);
            }}
            {...deleteGate}
          >
            Delete
          </HeaderButton>
          <HeaderButton
            variant="primary"
            icon={Plus}
            onClick={() => setShowCreateVlan(true)}
            {...writeGate}
          >
            New VLAN
          </HeaderButton>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs bg-muted/30 rounded-md p-3">
        <MetaRow label="Location" value={router.location || "—"} />
        <MetaRow label="Management IP" value={router.management_ip ?? "—"} />
        <MetaRow label="Vendor" value={router.vendor ?? "—"} />
        <MetaRow label="Model" value={router.model ?? "—"} />
        <MetaRow label="Description" value={router.description || "—"} span />
        {router.notes && <MetaRow label="Notes" value={router.notes} span />}
      </dl>

      <div className="border rounded-md">
        <div className="flex items-center justify-between border-b px-3 py-2">
          <h3 className="text-sm font-semibold">
            VLANs{" "}
            <span className="text-muted-foreground">({vlans.length})</span>
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-xs">
            <thead className="text-muted-foreground bg-muted/30">
              <tr>
                <SortableTh
                  sortKey="tag"
                  sort={sort}
                  onSort={toggle}
                  className="w-16 px-3 py-1.5"
                >
                  Tag
                </SortableTh>
                <SortableTh
                  sortKey="name"
                  sort={sort}
                  onSort={toggle}
                  className="px-3 py-1.5"
                >
                  Name
                </SortableTh>
                <SortableTh
                  sortKey="description"
                  sort={sort}
                  onSort={toggle}
                  className="px-3 py-1.5"
                >
                  Description
                </SortableTh>
                <th className="text-right px-3 py-1.5 w-24 font-medium">
                  Subnets
                </th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {vlans.length === 0 && (
                <tr>
                  <td
                    colSpan={4}
                    className="px-3 py-3 text-center text-muted-foreground italic"
                  >
                    No VLANs yet.
                  </td>
                </tr>
              )}
              {sortedVlans.map((v) => (
                <VLANRow
                  key={v.id}
                  vlan={v}
                  onClick={() => onSelectVlan(v.id, routerId)}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showEdit && (
        <EditRouterModal router={router} onClose={() => setShowEdit(false)} />
      )}
      {showCreateVlan && (
        <CreateVLANModal
          routerId={routerId}
          onClose={() => setShowCreateVlan(false)}
        />
      )}
      {deleteStep === 1 && (
        <Modal title="Delete Router" onClose={() => setDeleteStep(0)}>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Delete <strong className="text-foreground">{router.name}</strong>?
              All {vlans.length} VLAN
              {vlans.length === 1 ? "" : "s"} under this router will be removed.
              Deletion is blocked if any subnet still references a VLAN on this
              router — reassign those subnets first.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteStep(0)}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => setDeleteStep(2)}
                className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90"
              >
                Continue
              </button>
            </div>
          </div>
        </Modal>
      )}
      {deleteStep === 2 && (
        <Modal
          title="Confirm Permanent Deletion"
          onClose={() => {
            setDeleteStep(0);
            setDeleteError(null);
          }}
        >
          <div className="space-y-4">
            <p className="text-sm font-medium text-destructive">
              This action cannot be undone.
            </p>
            <p className="text-sm text-muted-foreground">
              <strong className="text-foreground">{router.name}</strong> and all{" "}
              {vlans.length} VLAN{vlans.length === 1 ? "" : "s"} it contains
              will be permanently deleted.
            </p>
            <label className="flex cursor-pointer items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={deleteChecked}
                onChange={(e) => setDeleteChecked(e.target.checked)}
              />
              I understand this will permanently delete{" "}
              <strong>{router.name}</strong> and all its VLANs.
            </label>
            {deleteError && (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                {deleteError}
              </div>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => {
                  setDeleteStep(0);
                  setDeleteError(null);
                }}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  setDeleteError(null);
                  deleteMut.mutate();
                }}
                disabled={!deleteChecked || deleteMut.isPending}
                className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                {deleteMut.isPending ? "Deleting…" : "Delete permanently"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function VLANRow({ vlan, onClick }: { vlan: VLAN; onClick: () => void }) {
  const { data: subnets = [] } = useQuery({
    queryKey: ["subnets-by-vlan", vlan.id],
    queryFn: () => ipamApi.listSubnets({ vlan_ref_id: vlan.id }),
  });
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <tr
          onClick={onClick}
          className="border-t cursor-pointer hover:bg-muted/40"
        >
          <td className="px-3 py-1.5 font-mono">{vlan.vlan_id}</td>
          <td className="px-3 py-1.5">{vlan.name}</td>
          <td className="px-3 py-1.5 text-muted-foreground">
            {vlan.description || "—"}
          </td>
          <td className="px-3 py-1.5 text-right">{subnets.length}</td>
        </tr>
      </ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuLabel>
          VLAN {vlan.vlan_id} — {vlan.name}
        </ContextMenuLabel>
        <ContextMenuSeparator />
        <ContextMenuItem onSelect={onClick}>Open…</ContextMenuItem>
        <ContextMenuItem onSelect={() => copyToClipboard(String(vlan.vlan_id))}>
          Copy VLAN ID
        </ContextMenuItem>
        <ContextMenuItem onSelect={() => copyToClipboard(vlan.name)}>
          Copy Name
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

function VLANDetail({
  vlanId,
  routerId,
  onDeleted,
}: {
  vlanId: string;
  routerId: string;
  onDeleted: () => void;
}) {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'vlan'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "vlan"),
    "Requires write permission on VLANs",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "vlan"),
    "Requires delete permission on VLANs",
  );
  const qc = useQueryClient();
  const [showEdit, setShowEdit] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const { data: vlan } = useQuery({
    queryKey: ["vlans", "vlan", vlanId],
    queryFn: () => vlansApi.getVlan(vlanId),
  });
  const { data: router } = useQuery({
    queryKey: ["vlans", "router", routerId],
    queryFn: () => vlansApi.getRouter(routerId),
  });
  const { data: subnets = [] } = useQuery({
    queryKey: ["subnets-by-vlan", vlanId],
    queryFn: () => ipamApi.listSubnets({ vlan_ref_id: vlanId }),
  });

  const [deleteError, setDeleteError] = useState<string | null>(null);
  const deleteMut = useMutation({
    mutationFn: () => vlansApi.deleteVlan(vlanId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vlans", routerId] });
      qc.invalidateQueries({ queryKey: ["subnets-by-vlan", vlanId] });
      onDeleted();
    },
    onError: (err: unknown) => {
      setDeleteError(formatApiError(err, "Failed to delete VLAN"));
    },
  });

  if (!vlan) return <p className="text-sm text-muted-foreground">Loading…</p>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Tag className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          <h1 className="text-lg font-semibold">
            VLAN <span className="font-mono">{vlan.vlan_id}</span> ·{" "}
            <span className="text-muted-foreground font-normal">
              {vlan.name}
            </span>
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <HeaderButton
            icon={Pencil}
            onClick={() => setShowEdit(true)}
            {...writeGate}
          >
            Edit
          </HeaderButton>
          <HeaderButton
            variant="destructive"
            icon={Trash2}
            onClick={() => setConfirmDelete(true)}
            {...deleteGate}
          >
            Delete
          </HeaderButton>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs bg-muted/30 rounded-md p-3">
        <MetaRow label="Router" value={router?.name ?? "—"} />
        <MetaRow label="Tag" value={String(vlan.vlan_id)} />
        <MetaRow label="Description" value={vlan.description || "—"} span />
      </dl>

      <div className="border rounded-md">
        <div className="border-b px-3 py-2">
          <h3 className="text-sm font-semibold">
            Subnets{" "}
            <span className="text-muted-foreground">({subnets.length})</span>
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-xs">
            <thead className="text-muted-foreground bg-muted/30">
              <tr>
                <th className="text-left px-3 py-1.5">Network</th>
                <th className="text-left px-3 py-1.5">Name</th>
                <th className="text-left px-3 py-1.5">Role</th>
                <th className="text-left px-3 py-1.5">Status</th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {subnets.length === 0 && (
                <tr>
                  <td
                    colSpan={4}
                    className="px-3 py-3 text-center text-muted-foreground italic"
                  >
                    No subnets reference this VLAN.
                  </td>
                </tr>
              )}
              {subnets.map((s: Subnet) => (
                <tr key={s.id} className="border-t">
                  <td className="px-3 py-1.5 font-mono">{s.network}</td>
                  <td className="px-3 py-1.5">{s.name || "—"}</td>
                  <td className="px-3 py-1.5">
                    <SubnetRoleChip role={s.subnet_role ?? null} />
                  </td>
                  <td className="px-3 py-1.5 text-muted-foreground">
                    {s.status}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showEdit && (
        <EditVLANModal
          vlan={vlan}
          routerId={routerId}
          onClose={() => setShowEdit(false)}
        />
      )}
      {confirmDelete && (
        <Modal
          title="Delete VLAN"
          onClose={() => {
            setConfirmDelete(false);
            setDeleteError(null);
          }}
        >
          <div className="space-y-3">
            {subnets.length > 0 ? (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
                <p className="font-medium">
                  Cannot delete: {subnets.length} subnet
                  {subnets.length === 1 ? "" : "s"} still reference this VLAN.
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Reassign or clear the VLAN on the subnets below first, then
                  try again.
                </p>
                <ul className="mt-2 max-h-32 list-disc overflow-auto pl-5 text-xs">
                  {subnets.map((s) => (
                    <li key={s.id} className="font-mono">
                      {s.network}
                      {s.name && (
                        <span className="text-muted-foreground">
                          {" "}
                          — {s.name}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-sm">
                Delete VLAN <strong>{vlan.vlan_id}</strong> ({vlan.name})? No
                subnets currently reference it.
              </p>
            )}
            {deleteError && (
              <p className="text-sm text-destructive">{deleteError}</p>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={() => {
                  setConfirmDelete(false);
                  setDeleteError(null);
                }}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                {subnets.length > 0 ? "Close" : "Cancel"}
              </button>
              {subnets.length === 0 && (
                <button
                  onClick={() => deleteMut.mutate()}
                  disabled={deleteMut.isPending}
                  className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
                >
                  {deleteMut.isPending ? "Deleting…" : "Delete"}
                </button>
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function MetaRow({
  label,
  value,
  span,
}: {
  label: string;
  value: string;
  span?: boolean;
}) {
  return (
    <div className={cn(span ? "col-span-2" : "")}>
      <dt className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground/70">
        {label}
      </dt>
      <dd className="text-foreground">{value}</dd>
    </div>
  );
}

// ── Modals ──────────────────────────────────────────────────────────────────

function CreateRouterModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  return (
    <RouterFormModal
      title="New Router"
      initial={{}}
      onClose={onClose}
      onSubmit={async (data) => {
        await vlansApi.createRouter(data);
        qc.invalidateQueries({ queryKey: ["vlans", "routers"] });
        onClose();
      }}
    />
  );
}

function EditRouterModal({
  router,
  onClose,
}: {
  router: Router;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  return (
    <RouterFormModal
      title={`Edit ${router.name}`}
      initial={router}
      onClose={onClose}
      onSubmit={async (data) => {
        await vlansApi.updateRouter(router.id, data);
        qc.invalidateQueries({ queryKey: ["vlans", "routers"] });
        qc.invalidateQueries({ queryKey: ["vlans", "router", router.id] });
        onClose();
      }}
    />
  );
}

function RouterFormModal({
  title,
  initial,
  onClose,
  onSubmit,
}: {
  title: string;
  initial: Partial<Router>;
  onClose: () => void;
  onSubmit: (data: Partial<Router>) => Promise<void>;
}) {
  const [name, setName] = useState(initial.name ?? "");
  const [description, setDescription] = useState(initial.description ?? "");
  const [location, setLocation] = useState(initial.location ?? "");
  const [managementIp, setManagementIp] = useState(initial.management_ip ?? "");
  const [vendor, setVendor] = useState(initial.vendor ?? "");
  const [model, setModel] = useState(initial.model ?? "");
  const [notes, setNotes] = useState(initial.notes ?? "");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit() {
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit({
        name: name.trim(),
        description,
        location,
        management_ip: managementIp || null,
        vendor: vendor || null,
        model: model || null,
        notes,
      });
    } catch (e: unknown) {
      setError(formatApiError(e, "Failed to save"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="space-y-3">
        <Field label="Name *">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Location">
            <input
              className={inputCls}
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              placeholder="Site / Rack"
            />
          </Field>
          <Field label="Management IP">
            <input
              className={inputCls}
              value={managementIp}
              onChange={(e) => setManagementIp(e.target.value)}
              placeholder="10.0.0.1"
            />
          </Field>
          <Field label="Vendor">
            <input
              className={inputCls}
              value={vendor}
              onChange={(e) => setVendor(e.target.value)}
            />
          </Field>
          <Field label="Model">
            <input
              className={inputCls}
              value={model}
              onChange={(e) => setModel(e.target.value)}
            />
          </Field>
        </div>
        <Field label="Notes">
          <textarea
            className={cn(inputCls, "min-h-[80px]")}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </Field>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {submitting ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function CreateVLANModal({
  routerId,
  onClose,
}: {
  routerId: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  return (
    <VLANFormModal
      title="New VLAN"
      initial={{}}
      onClose={onClose}
      onSubmit={async (data) => {
        await vlansApi.createVlan(routerId, {
          vlan_id: Number(data.vlan_id),
          name: data.name ?? "",
          description: data.description,
        });
        qc.invalidateQueries({ queryKey: ["vlans", routerId] });
        onClose();
      }}
    />
  );
}

function EditVLANModal({
  vlan,
  routerId,
  onClose,
}: {
  vlan: VLAN;
  routerId: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  return (
    <VLANFormModal
      title={`Edit VLAN ${vlan.vlan_id}`}
      initial={vlan}
      onClose={onClose}
      onSubmit={async (data) => {
        await vlansApi.updateVlan(vlan.id, {
          vlan_id: Number(data.vlan_id),
          name: data.name,
          description: data.description,
        });
        qc.invalidateQueries({ queryKey: ["vlans", routerId] });
        qc.invalidateQueries({ queryKey: ["vlans", "vlan", vlan.id] });
        onClose();
      }}
    />
  );
}

function VLANFormModal({
  title,
  initial,
  onClose,
  onSubmit,
}: {
  title: string;
  initial: Partial<VLAN>;
  onClose: () => void;
  onSubmit: (data: {
    vlan_id: number | string;
    name: string;
    description?: string;
  }) => Promise<void>;
}) {
  const [tag, setTag] = useState(initial.vlan_id?.toString() ?? "");
  const [name, setName] = useState(initial.name ?? "");
  const [description, setDescription] = useState(initial.description ?? "");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit() {
    const n = parseInt(tag, 10);
    if (Number.isNaN(n) || n < 1 || n > 4094) {
      setError("VLAN tag must be between 1 and 4094");
      return;
    }
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit({ vlan_id: n, name: name.trim(), description });
    } catch (e: unknown) {
      setError(formatApiError(e, "Failed to save"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-3">
        <Field label="VLAN Tag * (1–4094)">
          <input
            className={inputCls}
            type="number"
            value={tag}
            onChange={(e) => setTag(e.target.value)}
            autoFocus
          />
        </Field>
        <Field label="Name *">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {submitting ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
