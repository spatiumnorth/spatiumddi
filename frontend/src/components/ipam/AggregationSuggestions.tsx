import { useCallback, useMemo, useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellOff, Combine, Lightbulb, RotateCcw, X } from "lucide-react";
import { ipamApi, type AggregationSuggestion } from "@/lib/api";
import { cn } from "@/lib/utils";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { useSessionState } from "@/lib/useSessionState";
import { useDismissableMenu } from "@/hooks/useDismissableMenu";

/**
 * Passive badge button + popover that surfaces contiguous sibling subnets
 * which would pack into a clean supernet.
 *
 * Replaces the older inline banner that crowded the IPAM page on every
 * load — operators correctly found that too aggressive for a "by the
 * way…" hint. The badge stays compact in the header, popover opens on
 * click, snoozed/dismissed candidates are filtered server-side.
 *
 * Per-session expand/collapse (so an operator working through the list
 * doesn't have to re-click on every nav) is keyed on the block id —
 * different blocks remember their own popover state.
 */
// The snooze map is platform-wide — it changes the badge for every
// operator — so the API requires write on IP blocks for all three actions.
const NEEDS_BLOCK_WRITE = "Requires write permission on IP blocks";

export function AggregationCandidatesBadge({ blockId }: { blockId: string }) {
  const qc = useQueryClient();
  const canEdit = usePermissions().can("write", "ip_block");
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  const [open, setOpen] = useSessionState(
    `ipam-aggregation-popover-${blockId}`,
    false,
  );
  const [includeSnoozed, setIncludeSnoozed] = useSessionState(
    `ipam-aggregation-show-snoozed-${blockId}`,
    false,
  );

  const { data = [] } = useQuery({
    queryKey: ["block-aggregation-suggestions", blockId, includeSnoozed],
    queryFn: () =>
      ipamApi.blockAggregationSuggestions(blockId, {
        include_snoozed: includeSnoozed,
      }),
    staleTime: 60 * 1000,
  });

  const invalidate = () =>
    qc.invalidateQueries({
      queryKey: ["block-aggregation-suggestions", blockId],
    });

  const snoozeMut = useMutation({
    mutationFn: (key: string) => ipamApi.snoozeAggregationCandidate(key, 30),
    onSuccess: invalidate,
  });
  const dismissMut = useMutation({
    mutationFn: (key: string) => ipamApi.dismissAggregationCandidate(key),
    onSuccess: invalidate,
  });
  const clearMut = useMutation({
    mutationFn: (key: string) => ipamApi.clearAggregationSnooze(key),
    onSuccess: invalidate,
  });

  // Esc, an outside press and focus leaving close the popover, and Esc
  // returns focus to the badge (#3159).
  const closePopover = useCallback(() => setOpen(false), [setOpen]);
  const { onBlur } = useDismissableMenu({
    open,
    onClose: closePopover,
    containerRef: wrapperRef,
    triggerRef,
  });

  const activeCount = useMemo(
    () => data.filter((s) => s.snoozed_until === null).length,
    [data],
  );
  const snoozedCount = data.length - activeCount;

  // Render nothing when there's no signal worth surfacing — neither
  // open candidates nor snoozed ones the operator might want to revisit.
  if (activeCount === 0 && snoozedCount === 0) return null;

  return (
    <div className="relative" ref={wrapperRef} onBlur={onBlur}>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        title={
          activeCount > 0
            ? "Sibling subnets that would pack into a clean supernet"
            : "All current candidates are snoozed — click to review"
        }
        className={cn(
          "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors",
          activeCount > 0
            ? "border-amber-300 bg-amber-50 text-amber-800 hover:bg-amber-100 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300 dark:hover:bg-amber-950/60"
            : "border-dashed text-muted-foreground hover:bg-accent",
        )}
      >
        <Lightbulb className="h-3.5 w-3.5" />
        {activeCount > 0
          ? `${activeCount} aggregation suggestion${activeCount === 1 ? "" : "s"}`
          : `${snoozedCount} snoozed`}
      </button>

      {open && (
        <div className="absolute right-0 top-full z-30 mt-1 w-[440px] max-w-[90vw] rounded-md border bg-popover shadow-lg">
          <div className="flex items-center justify-between border-b px-3 py-2">
            <div className="flex items-center gap-2">
              <Combine className="h-3.5 w-3.5 text-amber-600 dark:text-amber-500" />
              <span className="text-xs font-semibold uppercase tracking-wider">
                Aggregation candidates
              </span>
            </div>
            <button
              aria-label="Close"
              title="Close"
              type="button"
              onClick={() => setOpen(false)}
              className="rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="max-h-[420px] divide-y overflow-auto">
            {data.length === 0 ? (
              <p className="px-3 py-6 text-center text-xs text-muted-foreground">
                {includeSnoozed
                  ? "No candidates."
                  : "No active candidates. Snoozed entries reappear after their timer."}
              </p>
            ) : (
              data.map((s) => (
                <CandidateRow
                  key={s.candidate_key}
                  candidate={s}
                  canEdit={canEdit}
                  onSnooze={() => snoozeMut.mutate(s.candidate_key)}
                  onDismiss={() => dismissMut.mutate(s.candidate_key)}
                  onClear={() => clearMut.mutate(s.candidate_key)}
                />
              ))
            )}
          </div>

          {snoozedCount > 0 || includeSnoozed ? (
            <div className="border-t px-3 py-2">
              <button
                type="button"
                onClick={() => setIncludeSnoozed(!includeSnoozed)}
                className="text-[11px] text-muted-foreground hover:text-foreground"
              >
                {includeSnoozed
                  ? "Hide snoozed candidates"
                  : `Show ${snoozedCount} snoozed`}
              </button>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}

function CandidateRow({
  candidate,
  canEdit,
  onSnooze,
  onDismiss,
  onClear,
}: {
  candidate: AggregationSuggestion;
  canEdit: boolean;
  onSnooze: () => void;
  onDismiss: () => void;
  onClear: () => void;
}) {
  const isSnoozed = candidate.snoozed_until !== null;
  const isPermanent = candidate.snoozed_until === "permanent";
  const gate = permissionGate(canEdit, NEEDS_BLOCK_WRITE);
  const btn =
    "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50";

  let snoozeLabel: string | null = null;
  if (isPermanent) {
    snoozeLabel = "Dismissed";
  } else if (candidate.snoozed_until) {
    try {
      const until = new Date(candidate.snoozed_until);
      snoozeLabel = `Snoozed until ${until.toLocaleDateString()}`;
    } catch {
      snoozeLabel = "Snoozed";
    }
  }

  return (
    <div className={cn("px-3 py-2.5 text-xs", isSnoozed && "opacity-60")}>
      <div className="font-mono text-sm font-medium">{candidate.supernet}</div>
      <div className="mt-0.5 break-words text-[11px] text-muted-foreground">
        ← {candidate.subnet_networks.join(", ")}
      </div>
      {snoozeLabel ? (
        <div className="mt-1 text-[10px] uppercase tracking-wide text-muted-foreground">
          {snoozeLabel}
        </div>
      ) : null}
      <div className="mt-2 flex items-center gap-1.5">
        {isSnoozed ? (
          <button type="button" onClick={onClear} className={btn} {...gate}>
            <RotateCcw className="h-3 w-3" />
            Re-enable
          </button>
        ) : (
          <>
            <button
              type="button"
              onClick={onSnooze}
              className={btn}
              title="Hide for 30 days"
              {...gate}
            >
              <BellOff className="h-3 w-3" />
              Snooze 30 days
            </button>
            <button
              type="button"
              onClick={onDismiss}
              className={cn(btn, "text-muted-foreground hover:text-foreground")}
              title="Don't suggest this candidate again"
              {...gate}
            >
              Don't suggest again
            </button>
          </>
        )}
      </div>
    </div>
  );
}
