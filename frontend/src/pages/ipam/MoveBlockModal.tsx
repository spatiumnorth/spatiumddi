/**
 * MoveBlockModal — relocate an IPBlock (and everything under it) into a
 * different IPSpace. Two-stage flow mirroring ResizeBlockModal:
 *
 *   1. Pick target space (combo, search). Optionally pick a target parent
 *      block within that space (filtered to blocks in the target space).
 *   2. Click "Preview" → server returns the blast radius (subnet count, IP
 *      count, integration blockers, supernet-reparent chain).
 *   3. If integration blockers are present, the commit button is HIDDEN
 *      (not disabled). Operator must detach the integration first.
 *   4. Type the moved block's CIDR to confirm. Commit posts the rewrite.
 *
 * The descendant cascade + advisory lock + overlap re-check happen
 * server-side — see ``app/services/ipam/block_move.py``. This modal is
 * just a thin client.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowRight, CheckCircle2, X } from "lucide-react";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";
import {
  formatApiError,
  ipamApi,
  type BlockMoveCommitResponse,
  type BlockMovePreviewResponse,
  type IPBlock,
  type IPSpace,
} from "@/lib/api";

const INPUT_CLS =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-60";

export function MoveBlockModal({
  block,
  onClose,
  onCommitted,
}: {
  block: IPBlock;
  onClose: () => void;
  onCommitted: (result: BlockMoveCommitResponse) => void;
}) {
  const qc = useQueryClient();
  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);

  const [targetSpaceId, setTargetSpaceId] = useState<string>("");
  const [targetParentId, setTargetParentId] = useState<string | "">("");
  const [confirmCidr, setConfirmCidr] = useState("");
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [commitError, setCommitError] = useState<string | null>(null);

  const { data: spaces = [] } = useQuery({
    queryKey: ["spaces"],
    queryFn: ipamApi.listSpaces,
  });
  // Filter target spaces — operator can't move a block into the space
  // it's already in (would be a no-op, server 422s anyway).
  const eligibleSpaces = useMemo(
    () => spaces.filter((s) => s.id !== block.space_id),
    [spaces, block.space_id],
  );

  // Blocks in the target space — used to populate the optional parent
  // picker. Skip the moved block itself.
  const { data: targetBlocks = [] } = useQuery({
    queryKey: ["blocks", targetSpaceId],
    queryFn: () => ipamApi.listBlocks(targetSpaceId),
    enabled: !!targetSpaceId,
  });
  const eligibleParents = useMemo(
    () => targetBlocks.filter((b) => b.id !== block.id),
    [targetBlocks, block.id],
  );

  const previewMut = useMutation({
    mutationFn: () =>
      ipamApi.moveBlockPreview(block.id, {
        target_space_id: targetSpaceId,
        target_parent_id: targetParentId || null,
      }),
    onSuccess: () => setPreviewError(null),
    onError: (err: unknown) => setPreviewError(formatApiError(err)),
  });
  const preview = previewMut.data as BlockMovePreviewResponse | undefined;

  const commitMut = useMutation({
    mutationFn: () =>
      ipamApi.moveBlockCommit(block.id, {
        target_space_id: targetSpaceId,
        target_parent_id: targetParentId || null,
        confirmation_cidr: confirmCidr,
      }),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["blocks"] });
      qc.invalidateQueries({ queryKey: ["spaces"] });
      qc.invalidateQueries({ queryKey: ["subnets"] });
      onCommitted(result);
    },
    onError: (err: unknown) => setCommitError(formatApiError(err)),
  });

  const hasBlockers = !!preview && preview.integration_blockers.length > 0;
  const cidrConfirmed = confirmCidr.trim() === block.network;
  const canCommit =
    !!preview && !hasBlockers && cidrConfirmed && !commitMut.isPending;

  // Reset preview if the operator changes target — the prior preview
  // is stale. They have to click Preview again.
  function onTargetChange(spaceId: string) {
    setTargetSpaceId(spaceId);
    setTargetParentId("");
    setConfirmCidr("");
    previewMut.reset();
    setPreviewError(null);
    setCommitError(null);
  }

  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        style={dialogStyle}
        className="relative max-h-[90vh] w-full max-w-2xl overflow-hidden rounded-lg border bg-card shadow-xl focus:outline-none"
      >
        <div
          {...dragHandleProps}
          className="flex cursor-move items-center justify-between border-b bg-card px-4 py-3"
        >
          <div className="flex items-center gap-2">
            <ArrowRight className="h-4 w-4 text-muted-foreground" />
            <h2 {...titleProps} className="text-sm font-semibold">
              Move block {block.network}
            </h2>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div
          className="space-y-4 overflow-auto px-5 py-4 text-sm"
          style={{ maxHeight: "calc(90vh - 8rem)" }}
        >
          <div className="rounded-md border bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
            Move this block <strong>and every descendant</strong> (child blocks,
            subnets, IP addresses) into a different IP space. The cascade
            happens in a single transaction. IP addresses keep their subnet
            binding — only the enclosing space changes.
          </div>

          {/* Target space picker */}
          <Field
            label="Target IP space"
            hint="Pick the destination space. Source-equal-target isn't allowed."
          >
            <select
              value={targetSpaceId}
              onChange={(e) => onTargetChange(e.target.value)}
              className={INPUT_CLS}
            >
              <option value="">—</option>
              {eligibleSpaces.map((s: IPSpace) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </Field>

          {/* Optional parent picker */}
          {targetSpaceId && (
            <Field
              label="Target parent block (optional)"
              hint="Leave empty to land at the top level of the target space. Picking a parent requires the moved block to be a strict subset of it."
            >
              <select
                value={targetParentId}
                onChange={(e) => {
                  setTargetParentId(e.target.value);
                  previewMut.reset();
                  setConfirmCidr("");
                }}
                className={INPUT_CLS}
              >
                <option value="">— top level —</option>
                {eligibleParents.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.network}
                    {b.name ? ` — ${b.name}` : ""}
                  </option>
                ))}
              </select>
            </Field>
          )}

          {/* Preview button */}
          <div>
            <button
              type="button"
              onClick={() => {
                previewMut.mutate();
                setConfirmCidr("");
              }}
              disabled={!targetSpaceId || previewMut.isPending}
              className="rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted disabled:opacity-50"
            >
              {previewMut.isPending ? "Calculating…" : "Preview move"}
            </button>
            {previewError && (
              <p className="mt-2 rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                {previewError}
              </p>
            )}
          </div>

          {/* Preview output */}
          {preview && (
            <div className="space-y-3 rounded-md border bg-muted/20 px-3 py-3 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                <span>
                  Will move {1 + preview.descendant_blocks_count} block
                  {preview.descendant_blocks_count === 0 ? "" : "s"},{" "}
                  {preview.descendant_subnets_count} subnet
                  {preview.descendant_subnets_count === 1 ? "" : "s"},{" "}
                  {preview.descendant_ip_addresses_total} IP address
                  {preview.descendant_ip_addresses_total === 1 ? "" : "es"}.
                </span>
              </div>
              {preview.reparent_chain_block_ids.length > 0 && (
                <p className="text-muted-foreground">
                  Will pull {preview.reparent_chain_block_ids.length} sibling
                  block
                  {preview.reparent_chain_block_ids.length === 1
                    ? ""
                    : "s"}{" "}
                  under the moved block as a supernet.
                </p>
              )}
              {preview.warnings.length > 0 && (
                <ul className="space-y-1">
                  {preview.warnings.map((w, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-1.5 text-amber-700 dark:text-amber-400"
                    >
                      <AlertTriangle className="mt-0.5 h-3 w-3 flex-shrink-0" />
                      <span>{w}</span>
                    </li>
                  ))}
                </ul>
              )}
              {hasBlockers && (
                <div className="space-y-1 rounded-md border border-destructive/40 bg-destructive/5 px-2 py-2">
                  <p className="font-semibold text-destructive">
                    Move refused — {preview.integration_blockers.length}{" "}
                    descendant
                    {preview.integration_blockers.length === 1 ? "" : "s"} owned
                    by an integration reconciler. Detach the integration first.
                  </p>
                  <ul className="space-y-0.5 font-mono text-[11px]">
                    {preview.integration_blockers.slice(0, 10).map((b) => (
                      <li key={b.resource_id}>
                        {b.kind} {b.network}{" "}
                        <span className="text-muted-foreground">
                          ({b.integration})
                        </span>
                      </li>
                    ))}
                    {preview.integration_blockers.length > 10 && (
                      <li className="text-muted-foreground">
                        … and {preview.integration_blockers.length - 10} more.
                      </li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Confirmation gate — only render when preview is clean */}
          {preview && !hasBlockers && (
            <Field
              label="Type the block's CIDR to confirm"
              hint={`Paste or type "${block.network}" to enable Move.`}
            >
              <input
                type="text"
                value={confirmCidr}
                onChange={(e) => {
                  setConfirmCidr(e.target.value);
                  setCommitError(null);
                }}
                placeholder={block.network}
                className={cn(
                  INPUT_CLS,
                  "font-mono",
                  cidrConfirmed && "border-emerald-500/40",
                )}
              />
            </Field>
          )}

          {commitError && (
            <p className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {commitError}
            </p>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t bg-card px-5 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => commitMut.mutate()}
            disabled={!canCommit}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {commitMut.isPending ? "Moving…" : "Move"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1 text-xs">
      <span className="font-medium text-muted-foreground">{label}</span>
      {children}
      {hint && (
        <span className="block text-[11px] text-muted-foreground/80">
          {hint}
        </span>
      )}
    </label>
  );
}
