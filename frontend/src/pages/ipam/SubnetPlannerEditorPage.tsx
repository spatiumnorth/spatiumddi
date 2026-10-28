import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  DndContext,
  type DragEndEvent,
  PointerSensor,
  closestCenter,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import {
  AlertTriangle,
  Box,
  CheckCircle2,
  GripVertical,
  Layers,
  Loader2,
  Plus,
  RefreshCw,
  Save,
  Trash2,
  Workflow,
} from "lucide-react";
import {
  ipamApi,
  dnsApi,
  dhcpApi,
  type PlanNode,
  type PlanValidationConflict,
} from "@/lib/api";
import { newNodeId } from "@/lib/uuid";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { useModuleOn } from "@/hooks/useModuleOn";
import { Modal } from "@/components/ui/modal";

/**
 * Subnet planner editor — left = tree, right = node properties + actions.
 * Drag-and-drop reparents nodes (drop on another node = becomes its child).
 * After every drop or edit, validation runs server-side and conflicts
 * surface as red badges next to offending nodes + a banner above the tree.
 */
export function SubnetPlannerEditorPage() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  // #1341 — the plans router asks write on 'ip_block' (save, reopen), and
  // apply also asks write on 'subnet' since it creates subnets (plans.py).
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "ip_block"),
    "Requires write permission on IP blocks",
  );
  const applyGate = permissionGate(
    perms.can("write", "ip_block") && perms.can("write", "subnet"),
    "Requires write permission on IP blocks and subnets",
  );

  const { data: plan, isLoading } = useQuery({
    queryKey: ["subnet-plan", id],
    queryFn: () => ipamApi.getSubnetPlan(id),
  });
  const { data: spaces = [] } = useQuery({
    queryKey: ["ipam", "spaces"],
    queryFn: () => ipamApi.listSpaces(),
    staleTime: 5 * 60 * 1000,
  });
  const spaceName = spaces.find((s) => s.id === plan?.space_id)?.name;

  const [tree, setTree] = useState<PlanNode | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [conflicts, setConflicts] = useState<PlanValidationConflict[]>([]);
  const [dirty, setDirty] = useState(false);
  const lastSyncedTreeRef = useRef<string>("");

  // Hydrate local state once the plan loads.
  useEffect(() => {
    if (plan?.tree && lastSyncedTreeRef.current !== JSON.stringify(plan.tree)) {
      setTree(plan.tree);
      lastSyncedTreeRef.current = JSON.stringify(plan.tree);
      setSelectedId(plan.tree.id);
      setDirty(false);
    }
  }, [plan]);

  const validateMut = useMutation({
    mutationFn: (t: PlanNode) =>
      ipamApi.validateSubnetPlanTree({
        name: plan?.name ?? "tmp",
        space_id: plan?.space_id ?? "",
        tree: t,
      }),
    onSuccess: (r) => setConflicts(r.conflicts),
  });

  // Re-validate whenever the tree changes (debounced inline by React's batch).
  useEffect(() => {
    if (!tree || !plan) return;
    const t = setTimeout(() => validateMut.mutate(tree), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tree, plan?.space_id]);

  const saveMut = useMutation({
    mutationFn: () => {
      if (!tree) throw new Error("No tree");
      return ipamApi.updateSubnetPlan(id, { tree });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subnet-plan", id] });
      setDirty(false);
    },
  });

  const [showApplyConfirm, setShowApplyConfirm] = useState(false);
  const reopenMut = useMutation({
    mutationFn: () => ipamApi.reopenSubnetPlan(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subnet-plan", id] });
      qc.invalidateQueries({ queryKey: ["subnet-plans"] });
    },
  });

  const applyMut = useMutation({
    mutationFn: () => ipamApi.applySubnetPlan(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subnet-plan", id] });
      qc.invalidateQueries({ queryKey: ["subnet-plans"] });
    },
  });

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
  );

  function handleDragEnd(e: DragEndEvent) {
    if (!tree) return;
    const dragId = String(e.active.id);
    const dropId = e.over ? String(e.over.id) : null;
    if (!dropId || dragId === dropId) return;
    // Don't allow dropping a node onto its own descendant.
    if (isDescendant(tree, dragId, dropId)) return;
    // Subnets can't have children — refuse drops onto a subnet target.
    const dropTarget = findNode(tree, dropId);
    if (dropTarget?.kind === "subnet") return;
    const next = reparentNode(tree, dragId, dropId);
    if (next) {
      setTree(next);
      setDirty(true);
    }
  }

  const conflictByNodeId = useMemo(() => {
    const m = new Map<string, PlanValidationConflict[]>();
    for (const c of conflicts) {
      if (!m.has(c.node_id)) m.set(c.node_id, []);
      m.get(c.node_id)!.push(c);
    }
    return m;
  }, [conflicts]);

  if (isLoading || !plan) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (!tree) {
    return (
      <div className="p-6 text-sm text-destructive">
        This plan has no tree yet.
      </div>
    );
  }

  const applied = !!plan.applied_at;
  const selected = selectedId ? findNode(tree, selectedId) : null;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <button
              type="button"
              onClick={() => navigate("/ipam/plans")}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              ← All plans
            </button>
            <div className="mt-1 flex items-center gap-2">
              <Workflow className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">{plan.name}</h1>
              {spaceName && (
                <span className="rounded border bg-muted/30 px-1.5 py-0.5 text-xs text-muted-foreground">
                  Space: {spaceName}
                </span>
              )}
              {applied && (
                <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-xs text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" />
                  Applied {new Date(plan.applied_at!).toLocaleString()}{" "}
                  (read-only)
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {applied && (
              <button
                type="button"
                onClick={() => reopenMut.mutate()}
                disabled={reopenMut.isPending}
                title="Re-open this plan as a draft. Only succeeds if every block / subnet it created has been deleted from IPAM."
                className="inline-flex items-center gap-1 rounded border px-3 py-1.5 text-sm hover:bg-muted/50 disabled:opacity-50"
                {...writeGate}
              >
                {reopenMut.isPending ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                Reopen
              </button>
            )}
            <button
              type="button"
              disabled={!dirty || saveMut.isPending || applied}
              onClick={() => saveMut.mutate()}
              className="inline-flex items-center gap-1 rounded border px-3 py-1.5 text-sm hover:bg-muted/50 disabled:opacity-50"
              {...writeGate}
            >
              {saveMut.isPending ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Save className="h-3.5 w-3.5" />
              )}
              Save
            </button>
            <button
              type="button"
              disabled={
                applied || conflicts.length > 0 || applyMut.isPending || dirty
              }
              onClick={() => {
                // A refusal from an earlier attempt belongs to that attempt.
                applyMut.reset();
                setShowApplyConfirm(true);
              }}
              className="inline-flex items-center gap-1 rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              title={
                dirty
                  ? "Save before applying"
                  : conflicts.length > 0
                    ? "Resolve conflicts before applying"
                    : ""
              }
              {...applyGate}
            >
              {applyMut.isPending && (
                <Loader2 className="h-3 w-3 animate-spin" />
              )}
              Apply
            </button>
          </div>
        </div>
        {applyMut.isError && !showApplyConfirm && (
          <ApplyErrorBanner error={applyMut.error as unknown} />
        )}
        {reopenMut.isError && (
          <ApplyErrorBanner error={reopenMut.error as unknown} />
        )}
        {conflicts.length > 0 && (
          <div className="mt-3 flex items-start gap-2 rounded border border-destructive/40 bg-destructive/5 px-3 py-2">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-destructive" />
            <div className="text-xs">
              <div className="font-medium text-destructive">
                {conflicts.length} conflict{conflicts.length === 1 ? "" : "s"}
              </div>
              <ul className="mt-0.5 space-y-0.5 text-destructive/80">
                {conflicts.slice(0, 5).map((c, i) => (
                  <li key={i}>{c.message}</li>
                ))}
                {conflicts.length > 5 && (
                  <li>… +{conflicts.length - 5} more</li>
                )}
              </ul>
            </div>
          </div>
        )}
      </div>

      <div className="flex flex-1 overflow-hidden">
        <DndContext
          sensors={sensors}
          collisionDetection={closestCenter}
          onDragEnd={handleDragEnd}
        >
          <div className="flex-1 overflow-auto border-r p-4">
            {!applied && (
              <div className="mb-3 rounded border border-dashed bg-muted/20 px-3 py-2 text-[11px] text-muted-foreground">
                <strong className="font-medium text-foreground">
                  How to use:
                </strong>{" "}
                On any block row, click <em>+ Subnet</em> or <em>+ Block</em> to
                nest a child of that kind. Click a node to edit it on the right
                (CIDR, name, kind, optional DNS / DHCP / gateway). Drag the grip
                handle to reparent (drops onto subnets are refused — subnets
                can't have children). Save, then Apply to materialise everything
                in IPAM in one transaction.
              </div>
            )}
            <TreeNodeRow
              node={tree}
              depth={0}
              selectedId={selectedId}
              onSelect={setSelectedId}
              conflictByNodeId={conflictByNodeId}
              isRoot
              readOnly={applied}
              onMutate={(updater) => {
                const next = updater(tree);
                setTree(next);
                setDirty(true);
              }}
            />
            {!applied && tree.children.length === 0 && (
              <p className="mt-3 pl-8 text-[11px] text-muted-foreground">
                Tip: pick the kind explicitly per node — blocks can hold more
                blocks or subnets, subnets are leaves. The root must be a block
                (subnets need a block parent).
              </p>
            )}
          </div>
        </DndContext>
        <div className="w-[360px] overflow-auto p-4">
          {selected ? (
            <PropertiesPanel
              node={selected}
              isRoot={selected.id === tree.id}
              readOnly={applied}
              onChange={(patch) => {
                setTree((t) => (t ? mutateNode(t, selected.id, patch) : t));
                setDirty(true);
              }}
            />
          ) : (
            <p className="text-xs text-muted-foreground">
              Select a node to edit its properties.
            </p>
          )}
        </div>
      </div>
      {showApplyConfirm && tree && (
        <ApplyConfirmModal
          tree={tree}
          spaceName={spaceName}
          onCancel={() => setShowApplyConfirm(false)}
          onConfirm={() => {
            // Stay open while the call runs: a refusal shows here, where
            // this confirm said it would (#2984); success closes it.
            applyMut.mutate(undefined, {
              onSuccess: () => setShowApplyConfirm(false),
            });
          }}
          isPending={applyMut.isPending}
          error={applyMut.isError ? (applyMut.error as unknown) : null}
        />
      )}
    </div>
  );
}

export function ApplyConfirmModal({
  tree,
  spaceName,
  onCancel,
  onConfirm,
  isPending,
  error,
}: {
  tree: PlanNode;
  spaceName: string | undefined;
  onCancel: () => void;
  onConfirm: () => void;
  isPending: boolean;
  error?: unknown;
}) {
  const counts = useMemo(() => countNodes(tree), [tree]);
  return (
    <Modal title="Apply this plan?" onClose={onCancel} wide>
      <div className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          This will create the following in IPAM
          {spaceName ? ` under space "${spaceName}"` : ""} in a single
          transaction. Once applied, the plan flips read-only and the
          materialised rows become the source of truth (you can edit them
          directly in IPAM, or delete them and Reopen this plan).
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div className="rounded border bg-violet-500/5 px-3 py-2">
            <div className="flex items-center gap-1.5 text-xs font-medium text-violet-700 dark:text-violet-400">
              <Layers className="h-3.5 w-3.5" /> Blocks
            </div>
            <div className="mt-1 text-2xl font-semibold">{counts.blocks}</div>
            {tree.existing_block_id && (
              <div className="text-[11px] text-muted-foreground">
                (root reuses existing block — not counted)
              </div>
            )}
          </div>
          <div className="rounded border bg-blue-500/5 px-3 py-2">
            <div className="flex items-center gap-1.5 text-xs font-medium text-blue-700 dark:text-blue-400">
              <Box className="h-3.5 w-3.5" /> Subnets
            </div>
            <div className="mt-1 text-2xl font-semibold">{counts.subnets}</div>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          If anything fails (overlap, missing parent, drifted state) the whole
          transaction rolls back and you'll see the conflicts here.
        </p>
        {error != null && <ApplyErrorBanner error={error} />}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isPending}
            className="inline-flex items-center gap-1 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {isPending && <Loader2 className="h-3 w-3 animate-spin" />}
            Yes, apply now
          </button>
        </div>
      </div>
    </Modal>
  );
}

function countNodes(tree: PlanNode): { blocks: number; subnets: number } {
  let blocks = 0;
  let subnets = 0;
  function walk(n: PlanNode) {
    if (n.kind === "block") blocks++;
    else subnets++;
    for (const c of n.children) walk(c);
  }
  walk(tree);
  if (tree.existing_block_id) blocks--;
  return { blocks, subnets };
}

// ── Tree row ────────────────────────────────────────────────────────────

function TreeNodeRow({
  node,
  depth,
  selectedId,
  onSelect,
  conflictByNodeId,
  isRoot,
  readOnly,
  onMutate,
}: {
  node: PlanNode;
  depth: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
  conflictByNodeId: Map<string, PlanValidationConflict[]>;
  isRoot: boolean;
  readOnly: boolean;
  onMutate: (updater: (root: PlanNode) => PlanNode) => void;
}) {
  const isSelected = selectedId === node.id;
  const hasConflicts = conflictByNodeId.has(node.id);

  const drag = useDraggable({ id: node.id, disabled: isRoot || readOnly });
  const drop = useDroppable({ id: node.id, disabled: readOnly });

  const dragStyle = drag.transform
    ? {
        transform: `translate3d(${drag.transform.x}px, ${drag.transform.y}px, 0)`,
        opacity: 0.6,
      }
    : undefined;

  function addChild(kind: "block" | "subnet") {
    onMutate((root) =>
      mutateNode(root, node.id, {
        children: [
          ...node.children,
          {
            id: newNodeId(),
            network: suggestChildCidr(node, node.children),
            name: "",
            description: "",
            kind,
            children: [],
          },
        ],
      }),
    );
  }

  function removeNode() {
    onMutate((root) => deleteNode(root, node.id) ?? root);
  }

  return (
    <div ref={drop.setNodeRef}>
      <div
        ref={drag.setNodeRef}
        style={dragStyle}
        className={`group flex items-center gap-2 rounded border px-2 py-1.5 ${
          isSelected ? "border-primary bg-primary/5" : "border-transparent"
        } ${drop.isOver ? "border-emerald-500 bg-emerald-500/10" : ""} ${
          hasConflicts ? "ring-1 ring-destructive/40" : ""
        }`}
        onClick={(e) => {
          e.stopPropagation();
          onSelect(node.id);
        }}
      >
        <div style={{ width: depth * 16 }} />
        {!isRoot && !readOnly && (
          <button
            {...drag.listeners}
            {...drag.attributes}
            type="button"
            className="cursor-grab text-muted-foreground/40 hover:text-muted-foreground active:cursor-grabbing"
            aria-label="Drag node"
          >
            <GripVertical className="h-3.5 w-3.5" />
          </button>
        )}
        {node.kind === "block" ? (
          <Layers
            className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400"
            aria-label="Block"
          />
        ) : (
          <Box
            className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400"
            aria-label="Subnet"
          />
        )}
        <span className="font-mono text-sm">{node.network}</span>
        {node.name && (
          <span className="truncate text-xs text-muted-foreground">
            {node.name}
          </span>
        )}
        <span className="ml-auto flex items-center gap-1">
          {!readOnly && node.kind === "block" && (
            <>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  addChild("subnet");
                }}
                className="inline-flex items-center gap-0.5 rounded border bg-background px-1.5 py-0.5 text-[11px] text-blue-700 hover:bg-blue-500/10 dark:text-blue-400"
                title="Add a child Subnet (leaf)"
              >
                <Plus className="h-3 w-3" /> Subnet
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  addChild("block");
                }}
                className="inline-flex items-center gap-0.5 rounded border bg-background px-1.5 py-0.5 text-[11px] text-violet-700 hover:bg-violet-500/10 dark:text-violet-400"
                title="Add a child Block (can hold further subnets)"
              >
                <Plus className="h-3 w-3" /> Block
              </button>
            </>
          )}
          {!readOnly && (
            <>
              {!isRoot && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    removeNode();
                  }}
                  className="rounded border bg-background p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                  aria-label="Delete node"
                  title="Delete node + its children"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              )}
            </>
          )}
        </span>
      </div>
      {node.children.map((c) => (
        <TreeNodeRow
          key={c.id}
          node={c}
          depth={depth + 1}
          selectedId={selectedId}
          onSelect={onSelect}
          conflictByNodeId={conflictByNodeId}
          isRoot={false}
          readOnly={readOnly}
          onMutate={onMutate}
        />
      ))}
    </div>
  );
}

// ── Properties panel ────────────────────────────────────────────────────

// eslint-disable-next-line react-refresh/only-export-components -- exported for its test
export function PropertiesPanel({
  node,
  isRoot,
  readOnly,
  onChange,
}: {
  node: PlanNode;
  isRoot: boolean;
  readOnly: boolean;
  onChange: (patch: Partial<PlanNode>) => void;
}) {
  // Canonical group keys (#367) — match the rest of the app so create/edit
  // invalidations refresh these pickers without a full reload.
  // #2135 — DNS server groups only exist while core.dns is on.
  const dnsOn = useModuleOn("core.dns");
  const { data: dnsGroups = [] } = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    staleTime: 5 * 60 * 1000,
    enabled: dnsOn,
  });
  // #2130 — DHCP server groups only exist while core.dhcp is on.
  const dhcpOn = useModuleOn("core.dhcp");
  const { data: dhcpGroups = [] } = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: () => dhcpApi.listGroups(),
    staleTime: 5 * 60 * 1000,
    enabled: dhcpOn,
  });

  const isSubnet = node.kind === "subnet";
  const cannotChangeKind =
    isRoot || (node.kind === "block" && node.children.length > 0);

  return (
    <div className="space-y-3">
      <h2 className="text-sm font-semibold">Node properties</h2>

      <Field label="Kind">
        <div className="inline-flex overflow-hidden rounded border text-xs">
          <button
            type="button"
            disabled={readOnly || cannotChangeKind}
            onClick={() => onChange({ kind: "block" })}
            className={
              node.kind === "block"
                ? "bg-violet-600 px-2 py-1 text-white"
                : "px-2 py-1 text-muted-foreground hover:bg-muted/50 disabled:opacity-50"
            }
          >
            <Layers className="mr-1 inline h-3 w-3" /> Block
          </button>
          <button
            type="button"
            disabled={readOnly || cannotChangeKind}
            onClick={() => onChange({ kind: "subnet" })}
            className={
              node.kind === "subnet"
                ? "bg-blue-600 px-2 py-1 text-white"
                : "px-2 py-1 text-muted-foreground hover:bg-muted/50 disabled:opacity-50"
            }
          >
            <Box className="mr-1 inline h-3 w-3" /> Subnet
          </button>
        </div>
        {isRoot && (
          <p className="mt-1 text-[11px] text-muted-foreground">
            Root must be a block — subnets need a block parent.
          </p>
        )}
        {!isRoot && node.kind === "block" && node.children.length > 0 && (
          <p className="mt-1 text-[11px] text-muted-foreground">
            Has children — delete or move them before converting to subnet.
          </p>
        )}
      </Field>

      <Field label="CIDR">
        <input
          type="text"
          value={node.network}
          onChange={(e) => onChange({ network: e.target.value })}
          disabled={readOnly || (isRoot && !!node.existing_block_id)}
          className="w-full rounded border bg-background px-2 py-1 font-mono text-sm disabled:opacity-50"
        />
        {isRoot && node.existing_block_id && (
          <p className="mt-1 text-[11px] text-muted-foreground">
            Locked — root is anchored to an existing block.
          </p>
        )}
      </Field>
      <Field label="Name">
        <input
          type="text"
          value={node.name}
          onChange={(e) => onChange({ name: e.target.value })}
          disabled={readOnly}
          className="w-full rounded border bg-background px-2 py-1 text-sm disabled:opacity-50"
        />
      </Field>
      <Field label="Description">
        <textarea
          value={node.description}
          onChange={(e) => onChange({ description: e.target.value })}
          disabled={readOnly}
          rows={2}
          className="w-full rounded border bg-background px-2 py-1 text-sm disabled:opacity-50"
        />
      </Field>

      <div className="pt-2">
        <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          Resources (optional — blank = inherit)
        </p>
        {dnsOn && (
          <Field label="DNS server group">
            <select
              value={node.dns_group_id ?? ""}
              onChange={(e) =>
                onChange({ dns_group_id: e.target.value || null })
              }
              disabled={readOnly}
              className="w-full rounded border bg-background px-2 py-1 text-sm disabled:opacity-50"
            >
              <option value="">— inherit —</option>
              {dnsGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </Field>
        )}
        {dhcpOn && (
          <Field label="DHCP server group">
            <select
              value={node.dhcp_server_group_id ?? ""}
              onChange={(e) =>
                onChange({ dhcp_server_group_id: e.target.value || null })
              }
              disabled={readOnly}
              className="w-full rounded border bg-background px-2 py-1 text-sm disabled:opacity-50"
            >
              <option value="">— inherit —</option>
              {dhcpGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </Field>
        )}
        {isSubnet && (
          <Field label="Gateway IP">
            <input
              type="text"
              value={node.gateway ?? ""}
              onChange={(e) => onChange({ gateway: e.target.value || null })}
              disabled={readOnly}
              placeholder="e.g. 10.0.0.1"
              className="w-full rounded border bg-background px-2 py-1 font-mono text-sm disabled:opacity-50"
            />
          </Field>
        )}
        {isSubnet ? null : (
          <p className="text-[11px] text-muted-foreground">
            Gateway IP appears when this node is a subnet.
          </p>
        )}
      </div>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-1 block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
    </div>
  );
}

// ── Apply error banner ──────────────────────────────────────────────────

function ApplyErrorBanner({ error }: { error: unknown }) {
  const detail = (error as { response?: { data?: { detail?: unknown } } })
    ?.response?.data?.detail;
  let conflicts: PlanValidationConflict[] = [];
  let survivors: { kind: string; network: string }[] = [];
  let message = "Operation failed.";
  if (typeof detail === "string") {
    message = detail;
  } else if (detail && typeof detail === "object") {
    const d = detail as {
      message?: string;
      conflicts?: PlanValidationConflict[];
      survivors?: { kind: string; network: string }[];
    };
    if (d.message) message = d.message;
    if (Array.isArray(d.conflicts)) conflicts = d.conflicts;
    if (Array.isArray(d.survivors)) survivors = d.survivors;
  }
  return (
    <div className="mt-3 flex items-start gap-2 rounded border border-destructive/40 bg-destructive/5 px-3 py-2">
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-destructive" />
      <div className="text-xs">
        <div className="font-medium text-destructive">{message}</div>
        {conflicts.length > 0 && (
          <ul className="mt-1 space-y-0.5 text-destructive/80">
            {conflicts.slice(0, 8).map((c, i) => (
              <li key={i}>{c.message}</li>
            ))}
            {conflicts.length > 8 && <li>…and {conflicts.length - 8} more</li>}
          </ul>
        )}
        {survivors.length > 0 && (
          <ul className="mt-1 space-y-0.5 text-destructive/80">
            {survivors.slice(0, 8).map((s, i) => (
              <li key={i}>
                {s.kind} <span className="font-mono">{s.network}</span> still
                exists
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── Tree ops ────────────────────────────────────────────────────────────

function findNode(root: PlanNode, id: string): PlanNode | null {
  if (root.id === id) return root;
  for (const c of root.children) {
    const r = findNode(c, id);
    if (r) return r;
  }
  return null;
}

function isDescendant(
  root: PlanNode,
  ancestorId: string,
  candidateId: string,
): boolean {
  const ancestor = findNode(root, ancestorId);
  if (!ancestor) return false;
  return findNode(ancestor, candidateId) !== null;
}

function mutateNode(
  root: PlanNode,
  id: string,
  patch: Partial<PlanNode>,
): PlanNode {
  if (root.id === id) return { ...root, ...patch };
  return {
    ...root,
    children: root.children.map((c) => mutateNode(c, id, patch)),
  };
}

function deleteNode(root: PlanNode, id: string): PlanNode | null {
  if (root.id === id) return null;
  return {
    ...root,
    children: root.children
      .map((c) => deleteNode(c, id))
      .filter((c): c is PlanNode => c !== null),
  };
}

function reparentNode(
  root: PlanNode,
  dragId: string,
  dropId: string,
): PlanNode | null {
  const dragged = findNode(root, dragId);
  if (!dragged) return null;
  // Detach
  const detached = deleteNode(root, dragId);
  if (!detached) return null;
  // Attach as last child of drop target
  return mutateNode(detached, dropId, {
    children: [...(findNode(detached, dropId)?.children ?? []), dragged],
  });
}

function suggestChildCidr(parent: PlanNode, existing: PlanNode[]): string {
  // Choose a target prefix that's smaller than the parent (default +8, capped
  // so the parent can fit the result). Then walk aligned slots of that size
  // inside the parent and return the first one that doesn't overlap any
  // existing sibling. If everything's taken at +8, step the slot size down by
  // one bit (= halve it) and retry, up to /30.
  const isV6 = parent.network.includes(":");
  if (isV6) {
    // No bigint helpers in this file yet — for v6 we just stamp parent's base
    // with a guessed prefix and let the operator edit. Validation will flag
    // any clash.
    const slash = parent.network.indexOf("/");
    const prefix = parseInt(parent.network.slice(slash + 1), 10);
    const childPrefix = Math.min(prefix + 16, 127);
    return `${parent.network.slice(0, slash)}/${childPrefix}`;
  }
  const parsed = parseCidrV4(parent.network);
  if (!parsed) return parent.network;
  const existingRanges = existing
    .map((c) => parseCidrV4(c.network))
    .filter((c): c is V4 => c !== null);

  for (let target = parsed.prefix + 8; target <= 30; target++) {
    if (target <= parsed.prefix) continue;
    const slotSize = 2 ** (32 - target);
    const start = parsed.base;
    const end = start + 2 ** (32 - parsed.prefix);
    for (let addr = start; addr < end; addr += slotSize) {
      const candidate: V4 = { base: addr, prefix: target };
      if (!existingRanges.some((e) => v4Overlaps(candidate, e))) {
        return `${intToIp(addr)}/${target}`;
      }
    }
  }
  // No room at any size — return the parent's base as a placeholder.
  return parent.network;
}

interface V4 {
  base: number;
  prefix: number;
}

function parseCidrV4(cidr: string): V4 | null {
  const [ip, prefixStr] = cidr.split("/");
  if (!ip || !prefixStr) return null;
  const prefix = parseInt(prefixStr, 10);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return { base: (n & mask) >>> 0, prefix };
}

function v4Overlaps(a: V4, b: V4): boolean {
  const aSize = 2 ** (32 - a.prefix);
  const bSize = 2 ** (32 - b.prefix);
  return a.base < b.base + bSize && b.base < a.base + aSize;
}

function intToIp(n: number): string {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join(".");
}
