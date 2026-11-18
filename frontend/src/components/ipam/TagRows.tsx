import { useId } from "react";
import { useQuery } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";
import { tagsApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { TagRow } from "./tag-rows";

/**
 * Key/value tag rows shared by the IPAM single create / edit dialogs
 * (via :func:`TagsField`) and the bulk-edit dialogs (#4107).
 *
 * Keys and values are suggested from ``/tags/keys`` and ``/tags/values``,
 * which only return tags on rows the caller may read — so the datalists
 * keep tags consistent without a central catalog and leak nothing.
 */

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ring";

function ValueInput({
  tagKey,
  listId,
  ...rest
}: {
  tagKey: string;
  listId: string;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  const key = tagKey.trim();
  const { data } = useQuery({
    queryKey: ["tag-values", key, ""],
    queryFn: () => tagsApi.listValues(key, undefined, 50),
    enabled: key !== "",
    staleTime: 30_000,
  });
  return (
    <>
      <input list={listId} {...rest} />
      <datalist id={listId}>
        {(data?.values ?? []).map((v) => (
          <option key={v} value={v} />
        ))}
      </datalist>
    </>
  );
}

export function TagRows({
  rows,
  onChange,
  showRemove = false,
  inherited,
  disabled = false,
}: {
  rows: TagRow[];
  onChange: (next: TagRow[]) => void;
  /** Bulk edit: show the per-row "remove" toggle. */
  showRemove?: boolean;
  /** Tags inherited from a parent block / space, shown as value
   *  placeholders and as read-only chips for keys not set locally. */
  inherited?: Record<string, { value: unknown; from: string }>;
  disabled?: boolean;
}) {
  const uid = useId();
  const keysListId = `${uid}-keys`;
  const { data: keyData } = useQuery({
    queryKey: ["tag-keys", ""],
    queryFn: () => tagsApi.listKeys(undefined, 50),
    staleTime: 30_000,
  });
  const set = (i: number, patch: Partial<TagRow>) =>
    onChange(rows.map((r, j) => (i === j ? { ...r, ...patch } : r)));
  const localKeys = new Set(rows.map((r) => r.k.trim()));
  const seen = new Set<string>();
  const inheritedOnly = Object.entries(inherited ?? {}).filter(
    ([k]) => !localKeys.has(k),
  );

  return (
    <div className="space-y-2">
      <datalist id={keysListId}>
        {(keyData?.keys ?? []).map((k) => (
          <option key={k} value={k} />
        ))}
      </datalist>
      {rows.map((row, i) => {
        const k = row.k.trim();
        const dup = k !== "" && !row.remove && seen.has(k);
        if (k !== "" && !row.remove) seen.add(k);
        const inh = inherited?.[k];
        return (
          <div key={i} className="space-y-0.5">
            <div className="flex items-center gap-2">
              <input
                className={cn(inputCls, "flex-1")}
                list={keysListId}
                value={row.k}
                disabled={disabled}
                onChange={(e) => set(i, { k: e.target.value })}
                placeholder="key"
                aria-label={`Tag key ${i + 1}`}
              />
              <ValueInput
                tagKey={row.k}
                listId={`${uid}-v${i}`}
                className={cn(inputCls, "flex-1", row.remove && "opacity-40")}
                value={row.v}
                disabled={disabled || row.remove}
                onChange={(e) => set(i, { v: e.target.value })}
                placeholder={
                  row.remove
                    ? "(will remove key)"
                    : inh
                      ? `${String(inh.value)} (from ${inh.from})`
                      : "value"
                }
                aria-label={`Tag value ${i + 1}`}
              />
              {showRemove && (
                <label
                  className="flex flex-shrink-0 items-center gap-1 text-[11px] text-muted-foreground"
                  title="If checked, this key is removed from all selected IPs."
                >
                  <input
                    type="checkbox"
                    checked={row.remove}
                    onChange={(e) => set(i, { remove: e.target.checked })}
                  />
                  remove
                </label>
              )}
              <button
                type="button"
                disabled={disabled}
                onClick={() => onChange(rows.filter((_, j) => j !== i))}
                className="rounded p-1 text-muted-foreground hover:text-destructive"
                title={showRemove ? "Discard row" : "Remove tag"}
                aria-label={`Remove tag row ${i + 1}`}
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
            {dup && (
              <p className="text-[11px] text-destructive">
                Duplicate key — the last row wins.
              </p>
            )}
          </div>
        );
      })}
      {inheritedOnly.length > 0 && (
        <div className="flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
          {inheritedOnly.map(([k, h]) => (
            <span
              key={k}
              className="rounded border border-dashed px-1.5 py-0.5"
              title={`Inherited from ${h.from}; add a row with this key to override`}
            >
              {k}: {String(h.value)} <em>(from {h.from})</em>
            </span>
          ))}
        </div>
      )}
      <button
        type="button"
        disabled={disabled}
        onClick={() => onChange([...rows, { k: "", v: "", remove: false }])}
        className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
      >
        <Plus className="h-3 w-3" /> Add tag
      </button>
    </div>
  );
}

/**
 * Controlled single-record tag editor: takes and returns a tags object.
 * The caller keeps ``rows`` (so blank / half-typed rows survive a
 * re-render) and derives the object with :func:`tagRowsToRecord`.
 */
export function TagsField({
  rows,
  onChange,
  inherited,
  disabled,
}: {
  rows: TagRow[];
  onChange: (next: TagRow[]) => void;
  inherited?: Record<string, { value: unknown; from: string }>;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div className="space-y-1" role="group" aria-labelledby={id}>
      <span id={id} className="block text-sm font-medium">
        Tags
      </span>
      <TagRows
        rows={rows}
        onChange={onChange}
        inherited={inherited}
        disabled={disabled}
      />
    </div>
  );
}
