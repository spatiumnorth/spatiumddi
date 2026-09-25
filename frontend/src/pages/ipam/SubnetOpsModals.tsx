/**
 * FindFreeModal + SplitSubnetModal + MergeSubnetModal — operator
 * surfaces for the three subnet/space operational features (Items 1, 2,
 * 3 in the 2026.04.26 IPAM ops landing).
 *
 * Design follows the ResizeModals pattern:
 * - Preview is a pure read; it shows the blast radius / candidate list
 *   before any mutation.
 * - Commit endpoints take a typed-CIDR confirmation gate (split, merge).
 * - All three modals reuse the shared `useModalDialog` helper so they
 *   behave like every other heavy modal in the IPAM surface.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Search,
  X,
} from "lucide-react";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";
import {
  formatApiError,
  ipamApi,
  type FindFreeCandidate,
  type FindFreeRequest,
  type IPSpace,
  type MergeSubnetPreviewResponse,
  type ResizeConflict,
  type SplitSubnetPreviewResponse,
  type Subnet,
} from "@/lib/api";

// ── Shared bits ───────────────────────────────────────────────────────────

function ConflictList({ conflicts }: { conflicts: ResizeConflict[] }) {
  if (conflicts.length === 0) return null;
  return (
    <div className="rounded border border-red-300 bg-red-50 p-3 dark:border-red-900 dark:bg-red-900/20">
      <div className="mb-1 flex items-center gap-2 text-sm font-medium text-red-900 dark:text-red-200">
        <AlertCircle className="h-4 w-4" />
        {conflicts.length} conflict{conflicts.length === 1 ? "" : "s"} — commit
        disabled
      </div>
      <ul className="list-disc pl-5 text-xs text-red-800 dark:text-red-300">
        {conflicts.map((c, i) => (
          <li key={i}>
            <span className="font-mono">{c.type}</span>: {c.detail}
          </li>
        ))}
      </ul>
    </div>
  );
}

function WarningList({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="rounded border border-amber-300 bg-amber-50 p-3 dark:border-amber-900 dark:bg-amber-900/20">
      <div className="mb-1 flex items-center gap-2 text-sm font-medium text-amber-900 dark:text-amber-200">
        <AlertTriangle className="h-4 w-4" />
        Warnings
      </div>
      <ul className="list-disc pl-5 text-xs text-amber-900 dark:text-amber-200">
        {warnings.map((w, i) => (
          <li key={i}>{w}</li>
        ))}
      </ul>
    </div>
  );
}

function ModalShell({
  title,
  onClose,
  children,
  footer,
  width = "760px",
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer: React.ReactNode;
  width?: string;
}) {
  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);
  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        className="flex max-h-[90vh] w-full max-w-[95vw] flex-col rounded-lg bg-background shadow-xl focus:outline-none"
        style={{ ...dialogStyle, maxWidth: `min(95vw, ${width})` }}
      >
        <div
          {...dragHandleProps}
          className={cn(
            "flex items-center justify-between border-b p-4",
            dragHandleProps.className,
          )}
        >
          <h2 {...titleProps} className="text-base font-semibold">
            {title}
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">{children}</div>
        <div className="flex flex-wrap justify-end gap-2 border-t p-3">
          {footer}
        </div>
      </div>
    </div>
  );
}

// ── FindFreeModal ─────────────────────────────────────────────────────────
//
// Top-of-tree "find me an unused CIDR in this space" finder. Posts the
// request, renders one row per candidate, with a "Use this" button that
// calls onPickCidr (the parent wires this into the create-subnet modal).

export function FindFreeModal({
  space,
  onClose,
  onPickCidr,
  defaultBlockId,
}: {
  space: IPSpace;
  onClose: () => void;
  /** Called with `(cidr, parentBlockId)` when the operator picks a candidate. */
  onPickCidr?: (cidr: string, parentBlockId: string) => void;
  /** When set, the search is pre-scoped to this block. */
  defaultBlockId?: string;
}) {
  const [prefixLength, setPrefixLength] = useState(24);
  const [addressFamily, setAddressFamily] = useState<4 | 6>(4);
  const [count, setCount] = useState(5);
  const [submitted, setSubmitted] = useState<FindFreeRequest | null>(null);

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["find-free", space.id, submitted],
    queryFn: () => ipamApi.findFreeSpace(space.id, submitted!),
    enabled: !!submitted,
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted({
      prefix_length: prefixLength,
      address_family: addressFamily,
      count,
      ...(defaultBlockId ? { parent_block_id: defaultBlockId } : {}),
    });
  };

  return (
    <ModalShell
      title={`Find free space in ${space.name}`}
      onClose={onClose}
      footer={
        <button
          type="button"
          onClick={onClose}
          className="rounded border px-3 py-1.5 text-sm hover:bg-accent"
        >
          Close
        </button>
      }
    >
      <form
        onSubmit={onSubmit}
        className="grid grid-cols-1 gap-3 rounded border bg-muted/30 p-3 sm:grid-cols-4"
      >
        <div className="space-y-1">
          <label className="text-xs font-medium">Prefix length</label>
          <input
            type="number"
            min={addressFamily === 4 ? 8 : 8}
            max={addressFamily === 4 ? 30 : 126}
            value={prefixLength}
            onChange={(e) => setPrefixLength(Number(e.target.value) || 0)}
            className="w-full rounded border bg-background px-2 py-1 text-sm font-mono"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium">Family</label>
          <select
            value={addressFamily}
            onChange={(e) => setAddressFamily(Number(e.target.value) as 4 | 6)}
            className="w-full rounded border bg-background px-2 py-1 text-sm"
          >
            <option value={4}>IPv4</option>
            <option value={6}>IPv6</option>
          </select>
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium">Max candidates</label>
          <input
            type="number"
            min={1}
            max={100}
            value={count}
            onChange={(e) => setCount(Number(e.target.value) || 1)}
            className="w-full rounded border bg-background px-2 py-1 text-sm font-mono"
          />
        </div>
        <div className="flex items-end">
          <button
            type="submit"
            className="inline-flex w-full items-center justify-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            <Search className="h-4 w-4" /> Find
          </button>
        </div>
      </form>

      {!submitted && (
        <p className="text-xs text-muted-foreground">
          Pick a prefix length and run the search to find unused CIDRs in this
          space.
        </p>
      )}
      {submitted && isLoading && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 className="h-3 w-3 animate-spin" /> Scanning blocks…
        </div>
      )}
      {submitted && isError && (
        <div className="rounded border border-red-300 bg-red-50 p-3 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-200">
          {formatApiError(error)}
        </div>
      )}
      {data && (
        <>
          {typeof data.summary?.warning === "string" && (
            <div className="rounded border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-200">
              {String(data.summary.warning)}
            </div>
          )}
          {data.candidates.length === 0 && !data.summary?.warning && (
            <p className="text-xs text-muted-foreground">
              No free CIDRs of /{prefixLength} found in this space.
            </p>
          )}
          {data.candidates.length > 0 && (
            <div className="overflow-hidden rounded border">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs">
                  <tr>
                    <th className="px-2 py-2 text-left">Candidate CIDR</th>
                    <th className="px-2 py-2 text-left">Inside block</th>
                    <th className="px-2 py-2 text-left">Free addresses</th>
                    <th className="px-2 py-2 text-right" />
                  </tr>
                </thead>
                <tbody>
                  {data.candidates.map((c: FindFreeCandidate) => (
                    <tr
                      key={`${c.cidr}-${c.parent_block_id}`}
                      className="border-t"
                    >
                      <td className="px-2 py-1.5 font-mono">{c.cidr}</td>
                      <td className="px-2 py-1.5 font-mono text-xs text-muted-foreground">
                        {c.parent_block_cidr}
                      </td>
                      <td className="px-2 py-1.5 text-xs">
                        {c.free_addresses ?? "—"}
                      </td>
                      <td className="px-2 py-1.5 text-right">
                        {onPickCidr && (
                          <button
                            type="button"
                            onClick={() => {
                              onPickCidr(c.cidr, c.parent_block_id);
                              onClose();
                            }}
                            className="rounded border px-2 py-0.5 text-xs hover:bg-accent"
                          >
                            Create subnet here
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </ModalShell>
  );
}

// ── SplitSubnetModal ──────────────────────────────────────────────────────

export function SplitSubnetModal({
  subnet,
  onClose,
  onCommitted,
}: {
  subnet: Subnet;
  onClose: () => void;
  onCommitted?: () => void;
}) {
  const qc = useQueryClient();
  const currentPrefix = useMemo(
    () => Number(subnet.network.split("/")[1] ?? 32),
    [subnet.network],
  );
  const [newPrefix, setNewPrefix] = useState(
    Math.min(currentPrefix + 1, subnet.network.includes(":") ? 126 : 30),
  );
  const [preview, setPreview] = useState<SplitSubnetPreviewResponse | null>(
    null,
  );
  const [confirmText, setConfirmText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const previewMut = useMutation({
    mutationFn: () =>
      ipamApi.splitSubnetPreview(subnet.id, { new_prefix_length: newPrefix }),
    onSuccess: (d) => {
      setPreview(d);
      setError(null);
    },
    onError: (e) => setError(formatApiError(e)),
  });

  const commitMut = useMutation({
    mutationFn: () =>
      ipamApi.splitSubnetCommit(subnet.id, {
        new_prefix_length: newPrefix,
        confirm_cidr: subnet.network,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subnets"] });
      qc.invalidateQueries({ queryKey: ["subnet", subnet.id] });
      onCommitted?.();
      onClose();
    },
    onError: (e) => setError(formatApiError(e)),
  });

  const blocked = !!preview && preview.conflicts.length > 0;
  const canCommit =
    !!preview &&
    !blocked &&
    confirmText.trim() === subnet.network.trim() &&
    !commitMut.isPending;

  return (
    <ModalShell
      title={`Split subnet ${subnet.network}`}
      onClose={onClose}
      footer={
        <>
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => previewMut.mutate()}
            disabled={previewMut.isPending}
            className="rounded border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            {previewMut.isPending ? "Previewing…" : "Preview"}
          </button>
          {!blocked && (
            <button
              type="button"
              onClick={() => commitMut.mutate()}
              disabled={!canCommit}
              className="rounded bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {commitMut.isPending ? "Committing…" : "Confirm split"}
            </button>
          )}
        </>
      }
    >
      <p className="text-xs text-muted-foreground">
        Split <span className="font-mono">{subnet.network}</span> (currently /
        {currentPrefix}) into 2<sup>(new − current)</sup> child subnets.
        IPAddress rows migrate to whichever child contains them.
      </p>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-xs font-medium">New child prefix length</label>
          <input
            type="number"
            min={currentPrefix + 1}
            max={subnet.network.includes(":") ? 126 : 30}
            value={newPrefix}
            onChange={(e) => {
              setNewPrefix(Number(e.target.value) || currentPrefix + 1);
              setPreview(null);
            }}
            className="w-full rounded border bg-background px-2 py-1 text-sm font-mono"
          />
        </div>
        <div className="space-y-1 text-xs text-muted-foreground">
          <p>
            Children: 2<sup>{newPrefix - currentPrefix}</sup> ={" "}
            {2 ** (newPrefix - currentPrefix)}
          </p>
        </div>
      </div>

      {error && (
        <div className="rounded border border-red-300 bg-red-50 p-3 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-200">
          {error}
        </div>
      )}

      {preview && (
        <>
          <ConflictList conflicts={preview.conflicts} />
          <WarningList warnings={preview.warnings} />
          {preview.children.length > 0 && (
            <div className="overflow-hidden rounded border">
              <table className="w-full text-sm">
                <thead className="bg-muted/40 text-xs">
                  <tr>
                    <th className="px-2 py-2 text-left">Child CIDR</th>
                    <th className="px-2 py-2 text-right">IPs</th>
                    <th className="px-2 py-2 text-right">DNS</th>
                    <th className="px-2 py-2 text-right">DHCP scope</th>
                    <th className="px-2 py-2 text-right">Pools / Statics</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.children.map((c) => (
                    <tr key={c.cidr} className="border-t">
                      <td className="px-2 py-1.5 font-mono">{c.cidr}</td>
                      <td className="px-2 py-1.5 text-right">
                        {c.allocations_count}
                      </td>
                      <td className="px-2 py-1.5 text-right">
                        {c.dns_record_count}
                      </td>
                      <td className="px-2 py-1.5 text-right text-xs">
                        {c.dhcp_scope_id ? (
                          <CheckCircle2 className="inline h-3 w-3 text-emerald-500" />
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="px-2 py-1.5 text-right text-xs">
                        {c.dhcp_pool_count} / {c.dhcp_static_count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {!blocked && (
            <div className="space-y-1">
              <label className="text-xs font-medium">
                Type the parent CIDR to confirm:{" "}
                <span className="font-mono">{subnet.network}</span>
              </label>
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder={subnet.network}
                spellCheck={false}
                autoComplete="off"
                className="w-full rounded border bg-background px-2 py-1 text-sm font-mono focus:ring-inset"
              />
            </div>
          )}
        </>
      )}
    </ModalShell>
  );
}

// ── MergeSubnetModal ──────────────────────────────────────────────────────

export function MergeSubnetModal({
  subnet,
  candidateSiblings,
  onClose,
  onCommitted,
}: {
  subnet: Subnet;
  /** Subnet rows in the same parent block (excluding `subnet`). */
  candidateSiblings: Subnet[];
  onClose: () => void;
  onCommitted?: () => void;
}) {
  const qc = useQueryClient();
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<MergeSubnetPreviewResponse | null>(
    null,
  );
  const [confirmText, setConfirmText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const sortedSiblings = useMemo(
    () =>
      [...candidateSiblings].sort((a, b) => a.network.localeCompare(b.network)),
    [candidateSiblings],
  );

  const togglePicked = (id: string) => {
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setPreview(null);
  };

  const previewMut = useMutation({
    mutationFn: () =>
      ipamApi.mergeSubnetPreview(subnet.id, {
        sibling_subnet_ids: Array.from(picked),
      }),
    onSuccess: (d) => {
      setPreview(d);
      setError(null);
    },
    onError: (e) => setError(formatApiError(e)),
  });

  const commitMut = useMutation({
    mutationFn: () =>
      ipamApi.mergeSubnetCommit(subnet.id, {
        sibling_subnet_ids: Array.from(picked),
        confirm_cidr: preview?.merged_cidr ?? "",
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subnets"] });
      onCommitted?.();
      onClose();
    },
    onError: (e) => setError(formatApiError(e)),
  });

  const blocked =
    !!preview && (preview.conflicts.length > 0 || !preview.merged_cidr);
  const canCommit =
    !!preview &&
    !blocked &&
    !!preview.merged_cidr &&
    confirmText.trim() === preview.merged_cidr.trim() &&
    !commitMut.isPending;

  return (
    <ModalShell
      title={`Merge subnet ${subnet.network}`}
      onClose={onClose}
      footer={
        <>
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => previewMut.mutate()}
            disabled={picked.size === 0 || previewMut.isPending}
            className="rounded border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            {previewMut.isPending ? "Previewing…" : "Preview merge"}
          </button>
          {!blocked && preview && (
            <button
              type="button"
              onClick={() => commitMut.mutate()}
              disabled={!canCommit}
              className="rounded bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {commitMut.isPending ? "Merging…" : "Confirm merge"}
            </button>
          )}
        </>
      }
    >
      <p className="text-xs text-muted-foreground">
        Merge <span className="font-mono">{subnet.network}</span> with one or
        more contiguous siblings under the same parent block.
      </p>

      {sortedSiblings.length === 0 ? (
        <p className="rounded border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
          No sibling subnets under this parent block. Move siblings under the
          same parent first.
        </p>
      ) : (
        <div className="overflow-hidden rounded border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs">
              <tr>
                <th className="w-8 px-2 py-2" />
                <th className="px-2 py-2 text-left">Sibling subnet</th>
                <th className="px-2 py-2 text-left">Name</th>
              </tr>
            </thead>
            <tbody>
              {sortedSiblings.map((s) => (
                <tr key={s.id} className="border-t">
                  <td className="px-2 py-1.5">
                    <input
                      type="checkbox"
                      checked={picked.has(s.id)}
                      onChange={() => togglePicked(s.id)}
                    />
                  </td>
                  <td className="px-2 py-1.5 font-mono">{s.network}</td>
                  <td className="px-2 py-1.5 text-xs">{s.name || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {error && (
        <div className="rounded border border-red-300 bg-red-50 p-3 text-xs text-red-800 dark:border-red-900 dark:bg-red-900/20 dark:text-red-200">
          {error}
        </div>
      )}

      {preview && (
        <>
          <div className="rounded border bg-muted/30 p-3 text-xs">
            <div>
              <span className="text-muted-foreground">Merged CIDR: </span>
              <span className="font-mono">{preview.merged_cidr ?? "—"}</span>
            </div>
            <div className="mt-1 text-muted-foreground">
              {preview.source_subnets.length} source subnets (target +{" "}
              {preview.source_subnets.length - 1} sibling
              {preview.source_subnets.length === 2 ? "" : "s"})
            </div>
            {preview.surviving_dhcp_scope_id && (
              <div className="mt-1 text-emerald-700 dark:text-emerald-300">
                DHCP scope will be re-bound to the merged subnet.
              </div>
            )}
          </div>
          <ConflictList conflicts={preview.conflicts} />
          <WarningList warnings={preview.warnings} />

          {!blocked && preview.merged_cidr && (
            <div className="space-y-1">
              <label className="text-xs font-medium">
                Type the merged CIDR to confirm:{" "}
                <span className="font-mono">{preview.merged_cidr}</span>
              </label>
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder={preview.merged_cidr}
                spellCheck={false}
                autoComplete="off"
                className="w-full rounded border bg-background px-2 py-1 text-sm font-mono focus:ring-inset"
              />
            </div>
          )}
        </>
      )}
    </ModalShell>
  );
}

// ── MergeSubnetSiblingPicker ──────────────────────────────────────────────
//
// Convenience wrapper that loads the candidate-sibling list (subnets
// in the same parent block, excluding the target itself) before
// rendering the merge modal. The router endpoint accepts arbitrary
// sibling IDs, but the UI restricts the pick list to subnets the
// merge service won't immediately reject.

export function MergeSubnetSiblingPicker({
  subnet,
  onClose,
  onCommitted,
}: {
  subnet: Subnet;
  onClose: () => void;
  onCommitted?: () => void;
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["merge-siblings", subnet.block_id],
    queryFn: () =>
      ipamApi.listSubnets({
        space_id: subnet.space_id,
        block_id: subnet.block_id ?? undefined,
      }),
    enabled: !!subnet.block_id,
  });

  if (isLoading) {
    return (
      <ModalShell
        title={`Merge subnet ${subnet.network}`}
        onClose={onClose}
        footer={null}
      >
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 className="h-3 w-3 animate-spin" /> Loading siblings…
        </div>
      </ModalShell>
    );
  }
  if (isError || !data) {
    return (
      <ModalShell
        title={`Merge subnet ${subnet.network}`}
        onClose={onClose}
        footer={
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Close
          </button>
        }
      >
        <p className="text-xs text-red-700">
          Failed to load sibling subnets — try again later.
        </p>
      </ModalShell>
    );
  }
  const siblings = data.filter((s) => s.id !== subnet.id);
  return (
    <MergeSubnetModal
      subnet={subnet}
      candidateSiblings={siblings}
      onClose={onClose}
      onCommitted={onCommitted}
    />
  );
}
