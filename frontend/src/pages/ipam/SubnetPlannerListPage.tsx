import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, Plus, Trash2, Workflow } from "lucide-react";
import {
  ipamApi,
  type IPBlock,
  type IPSpace,
  type SubnetPlanRead,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { newNodeId } from "@/lib/uuid";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

/**
 * Index of saved subnet plans. New plans bootstrap with a root node and a
 * choice between "anchored to existing block" or "new top-level CIDR".
 */
export function SubnetPlannerListPage() {
  // #1341 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'ip_block'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "ip_block"),
    "Requires write permission on IP blocks",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "ip_block"),
    "Requires delete permission on IP blocks",
  );
  const [showNew, setShowNew] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<SubnetPlanRead | null>(
    null,
  );
  const qc = useQueryClient();

  const { data = [], isLoading } = useQuery({
    queryKey: ["subnet-plans"],
    queryFn: () => ipamApi.listSubnetPlans(),
  });
  const { data: spaces = [] } = useQuery({
    queryKey: ["ipam", "spaces"],
    queryFn: () => ipamApi.listSpaces(),
    staleTime: 5 * 60 * 1000,
  });
  const spaceNameById = new Map(spaces.map((s) => [s.id, s.name]));

  const deleteMut = useMutation({
    mutationFn: (id: string) => ipamApi.deleteSubnetPlan(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subnet-plans"] });
      setPendingDelete(null);
    },
  });

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Workflow className="h-5 w-5 text-muted-foreground" />
              <h1 className="text-lg font-semibold">Subnet planner</h1>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
              Design multi-level CIDR hierarchies before committing them. Each
              plan captures a tree of nested blocks + subnets; "Apply"
              transactionally creates everything in IPAM. Plans persist after
              apply as an audit trail.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowNew(true)}
            className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            {...writeGate}
          >
            <Plus className="h-4 w-4" /> New plan
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {isLoading ? (
          <p className="inline-flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" /> Loading plans…
          </p>
        ) : data.length === 0 ? (
          <div className="rounded-lg border border-dashed p-12 text-center">
            <Workflow className="mx-auto h-8 w-8 text-muted-foreground/40" />
            <p className="mt-3 text-sm text-muted-foreground">
              No plans yet. Create one to design a CIDR hierarchy.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border bg-card">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/30 text-xs">
                  <th className="px-3 py-2 text-left">Name</th>
                  <th className="px-3 py-2 text-left">Space</th>
                  <th className="px-3 py-2 text-left">Status</th>
                  <th className="px-3 py-2 text-left">Modified</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {data.map((p) => (
                  <tr
                    key={p.id}
                    className="border-b last:border-0 hover:bg-muted/20"
                  >
                    <td className="px-3 py-2">
                      <Link
                        to={`/ipam/plans/${p.id}`}
                        className="font-medium text-primary hover:underline"
                      >
                        {p.name}
                      </Link>
                      {p.description && (
                        <div className="text-xs text-muted-foreground">
                          {p.description}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {spaceNameById.get(p.space_id) ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      {p.applied_at ? (
                        <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-xs text-emerald-700 dark:text-emerald-400">
                          <CheckCircle2 className="h-3 w-3" />
                          Applied
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                          Draft
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {new Date(p.modified_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <button
                        type="button"
                        onClick={() => setPendingDelete(p)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                        aria-label="Delete plan"
                        {...deleteGate}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showNew && <NewPlanModal onClose={() => setShowNew(false)} />}
      {pendingDelete && (
        <Modal
          title={`Delete plan "${pendingDelete.name}"?`}
          onClose={() => setPendingDelete(null)}
        >
          <p className="mb-4 text-xs text-muted-foreground">
            This deletes only the plan record — any IPAM blocks / subnets that
            were already applied stay in place.
          </p>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setPendingDelete(null)}
              className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => deleteMut.mutate(pendingDelete.id)}
              disabled={deleteMut.isPending}
              className="rounded bg-destructive px-3 py-1.5 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
            >
              {deleteMut.isPending ? "Deleting…" : "Delete"}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function NewPlanModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [spaceId, setSpaceId] = useState("");
  const [rootMode, setRootMode] = useState<"existing" | "new">("new");
  const [rootBlockId, setRootBlockId] = useState("");
  const [rootCidr, setRootCidr] = useState("");

  const { data: spaces = [] } = useQuery({
    queryKey: ["ipam", "spaces"],
    queryFn: () => ipamApi.listSpaces(),
  });
  const { data: blocks = [] } = useQuery<IPBlock[]>({
    queryKey: ["ipam", "blocks", spaceId],
    queryFn: () => ipamApi.listBlocks(spaceId),
    enabled: !!spaceId,
  });

  const createMut = useMutation({
    mutationFn: () => {
      let rootNet = rootCidr;
      let existingBlockId: string | null = null;
      if (rootMode === "existing") {
        const block = blocks.find((b) => b.id === rootBlockId);
        if (!block) throw new Error("Pick an existing block");
        rootNet = block.network;
        existingBlockId = block.id;
      }
      return ipamApi.createSubnetPlan({
        name,
        description,
        space_id: spaceId,
        tree: {
          id: newNodeId(),
          network: rootNet,
          name: name || "Root",
          description: "",
          existing_block_id: existingBlockId,
          kind: "block",
          children: [],
        },
      });
    },
    onSuccess: (plan) => {
      qc.invalidateQueries({ queryKey: ["subnet-plans"] });
      window.location.href = `/ipam/plans/${plan.id}`;
    },
  });

  const space = spaces.find((s: IPSpace) => s.id === spaceId);
  const submitDisabled =
    !name ||
    !space ||
    (rootMode === "existing" ? !rootBlockId : !/\/\d+$/.test(rootCidr));

  return (
    <Modal title="New subnet plan" onClose={onClose} wide>
      <div className="space-y-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full rounded border bg-background px-2 py-1.5 text-sm"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Description
          </label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="w-full rounded border bg-background px-2 py-1.5 text-sm"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            IP Space
          </label>
          <select
            value={spaceId}
            onChange={(e) => setSpaceId(e.target.value)}
            className="w-full rounded border bg-background px-2 py-1.5 text-sm"
          >
            <option value="">— pick a space —</option>
            {spaces.map((s: IPSpace) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Root
          </label>
          <div className="mb-2 inline-flex overflow-hidden rounded border text-xs">
            <button
              type="button"
              onClick={() => setRootMode("new")}
              className={
                rootMode === "new"
                  ? "bg-primary px-2 py-1 text-primary-foreground"
                  : "px-2 py-1 text-muted-foreground hover:bg-muted/50"
              }
            >
              New top-level CIDR
            </button>
            <button
              type="button"
              onClick={() => setRootMode("existing")}
              className={
                rootMode === "existing"
                  ? "bg-primary px-2 py-1 text-primary-foreground"
                  : "px-2 py-1 text-muted-foreground hover:bg-muted/50"
              }
            >
              Anchor to existing block
            </button>
          </div>
          {rootMode === "new" ? (
            <input
              type="text"
              value={rootCidr}
              onChange={(e) => setRootCidr(e.target.value)}
              placeholder="10.0.0.0/16"
              className="w-full rounded border bg-background px-2 py-1.5 font-mono text-sm"
            />
          ) : (
            <select
              value={rootBlockId}
              onChange={(e) => setRootBlockId(e.target.value)}
              disabled={!spaceId}
              className="w-full rounded border bg-background px-2 py-1.5 text-sm disabled:opacity-50"
            >
              <option value="">— pick a block —</option>
              {blocks.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.network} {b.name ? `(${b.name})` : ""}
                </option>
              ))}
            </select>
          )}
        </div>
        {createMut.isError && (
          <p className="text-xs text-destructive">
            {formatApiError(createMut.error)}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-sm hover:bg-muted/50"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={submitDisabled || createMut.isPending}
            onClick={() => createMut.mutate()}
            className="inline-flex items-center gap-1 rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground disabled:opacity-50"
          >
            {createMut.isPending && (
              <Loader2 className="h-3 w-3 animate-spin" />
            )}
            Create
          </button>
        </div>
      </div>
    </Modal>
  );
}
