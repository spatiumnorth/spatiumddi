import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Loader2, Plus, X } from "lucide-react";
import { Modal } from "@/components/ui/modal";
import { formatCount } from "@/lib/format-count";
import {
  ipamApi,
  type IPBlock,
  type PlanAllocationResponse,
  type PlanRequestItem,
  formatApiError,
} from "@/lib/api";
import { FormError } from "@/components/ui/form-error";

interface RowDraft {
  count: string;
  prefix_len: string;
}

function isV6(block: IPBlock): boolean {
  return block.network.includes(":");
}

/**
 * Address planner — operator enters one or more sized requests
 * (e.g. "4 × /24, 2 × /26") and the backend returns a packed
 * allocation preview using the smallest-fitting-free heuristic.
 *
 * No writes happen here; this is purely a visualisation tool. The
 * operator copies the suggested CIDRs back into the existing
 * Create Subnet flow if they want to commit them.
 */
export function PlanAllocationModal({
  block,
  onClose,
}: {
  block: IPBlock;
  onClose: () => void;
}) {
  const v6 = isV6(block);
  const blockPrefix = parseInt(block.network.split("/")[1] ?? "0", 10);
  const minPrefix = blockPrefix + 1;
  const maxPrefix = v6 ? 128 : 32;

  const [rows, setRows] = useState<RowDraft[]>([
    {
      count: "4",
      prefix_len: String(Math.min(blockPrefix + 8, maxPrefix)),
    },
  ]);
  const [result, setResult] = useState<PlanAllocationResponse | null>(null);

  const planMut = useMutation({
    mutationFn: () => {
      const items: PlanRequestItem[] = rows
        .map((r) => ({
          count: parseInt(r.count, 10),
          prefix_len: parseInt(r.prefix_len, 10),
        }))
        .filter(
          (r) =>
            Number.isFinite(r.count) &&
            r.count >= 1 &&
            Number.isFinite(r.prefix_len) &&
            r.prefix_len >= minPrefix &&
            r.prefix_len <= maxPrefix,
        );
      return ipamApi.planBlockAllocation(block.id, items);
    },
    onSuccess: (data) => setResult(data),
  });

  const validationError = useMemo(() => {
    for (const r of rows) {
      const c = parseInt(r.count, 10);
      const p = parseInt(r.prefix_len, 10);
      if (!Number.isFinite(c) || c < 1) return "Each row needs count ≥ 1";
      if (!Number.isFinite(p) || p < minPrefix || p > maxPrefix)
        return `Prefix length must be ${minPrefix}–${maxPrefix}`;
    }
    return null;
  }, [rows, minPrefix, maxPrefix]);

  function updateRow(i: number, patch: Partial<RowDraft>) {
    setRows((prev) =>
      prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)),
    );
  }

  function addRow() {
    setRows((prev) => [
      ...prev,
      { count: "1", prefix_len: String(Math.min(blockPrefix + 8, maxPrefix)) },
    ]);
  }

  function removeRow(i: number) {
    setRows((prev) => prev.filter((_, idx) => idx !== i));
  }

  return (
    <Modal title={`Plan allocation — ${block.network}`} onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-xs text-muted-foreground">
          Pack requested subnet sizes into this block's free space using a
          largest-first best-fit heuristic. Preview only — nothing is written.
        </p>

        <div className="rounded-md border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b bg-muted/30">
                <th className="px-2 py-1.5 text-left">Count</th>
                <th className="px-2 py-1.5 text-left">Prefix /N</th>
                <th className="px-2 py-1.5"></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className="border-b last:border-0">
                  <td className="px-2 py-1.5">
                    <input
                      type="number"
                      min={1}
                      max={1024}
                      value={r.count}
                      onChange={(e) => updateRow(i, { count: e.target.value })}
                      className="w-20 rounded border bg-background px-2 py-1 text-xs"
                    />
                  </td>
                  <td className="px-2 py-1.5">
                    <input
                      type="number"
                      min={minPrefix}
                      max={maxPrefix}
                      value={r.prefix_len}
                      onChange={(e) =>
                        updateRow(i, { prefix_len: e.target.value })
                      }
                      className="w-20 rounded border bg-background px-2 py-1 text-xs"
                    />
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    {rows.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeRow(i)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive"
                        aria-label="Remove row"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="border-t p-2">
            <button
              type="button"
              onClick={addRow}
              className="inline-flex items-center gap-1 rounded border bg-muted/30 px-2 py-1 text-xs hover:bg-muted/60"
            >
              <Plus className="h-3 w-3" /> Add row
            </button>
          </div>
        </div>

        {validationError && (
          <p className="text-xs text-destructive">{validationError}</p>
        )}
        {planMut.isError && (
          <FormError className="text-xs text-destructive">
            {formatApiError(planMut.error)}
          </FormError>
        )}

        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
          >
            Close
          </button>
          <button
            type="button"
            disabled={!!validationError || planMut.isPending}
            onClick={() => planMut.mutate()}
            className="inline-flex items-center gap-1 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground disabled:opacity-50"
          >
            {planMut.isPending && <Loader2 className="h-3 w-3 animate-spin" />}
            Compute plan
          </button>
        </div>

        {result && (
          <div className="space-y-3 border-t pt-3">
            <div>
              <h3 className="mb-1.5 text-xs font-semibold">
                Suggested allocations ({result.allocations.length})
              </h3>
              {result.allocations.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No subnets could be packed — block has no matching free space.
                </p>
              ) : (
                <div className="overflow-x-auto rounded border">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b bg-muted/30">
                        <th className="px-2 py-1 text-left">Network</th>
                        <th className="px-2 py-1 text-left">Range</th>
                        <th className="px-2 py-1 text-right">Size</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.allocations.map((a) => (
                        <tr key={a.network} className="border-b last:border-0">
                          <td className="px-2 py-1 font-mono">{a.network}</td>
                          <td className="px-2 py-1 font-mono text-muted-foreground">
                            {a.first} – {a.last}
                          </td>
                          <td className="px-2 py-1 text-right">
                            {formatCount(a.size_exact, a.size)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {result.unfulfilled.length > 0 && (
              <div>
                <h3 className="mb-1.5 text-xs font-semibold text-amber-600 dark:text-amber-500">
                  Couldn't fit
                </h3>
                <ul className="text-xs">
                  {result.unfulfilled.map((u, i) => (
                    <li key={i} className="text-muted-foreground">
                      Requested {u.requested} × /{u.prefix_len}, only{" "}
                      {u.allocated} fit
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <h3 className="mb-1.5 text-xs font-semibold">
                Remaining free after plan ({result.remaining_free.length})
              </h3>
              {result.remaining_free.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  Block fully consumed by the plan.
                </p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {result.remaining_free.slice(0, 30).map((f) => (
                    <span
                      key={f.network}
                      className="rounded border bg-muted/30 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground"
                    >
                      {f.network}
                    </span>
                  ))}
                  {result.remaining_free.length > 30 && (
                    <span className="text-[11px] text-muted-foreground">
                      +{result.remaining_free.length - 30} more
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}
