// Saved searches / saved views header dropdown (issue #77).
//
// A reusable, page-agnostic control: a page hands it a stable ``page``
// key, its current filter/sort/column state as an opaque ``payload``,
// and an ``onApply`` callback. The menu stores presets per-user via
// ``savedViewsApi`` and restores them by calling ``onApply``. Wiring a
// new page in is two props + a tiny apply function — no shared state
// machinery.
//
// Gated by the ``ui.saved_views`` feature module: hidden entirely when
// an operator turns it off.
import { useCallback, useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bookmark, ChevronDown, Star, Trash2 } from "lucide-react";

import { savedViewsApi, type SavedView } from "@/lib/api";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { useDismissableMenu } from "@/hooks/useDismissableMenu";

export function SavedViewsMenu<P extends Record<string, unknown>>({
  page,
  currentPayload,
  onApply,
}: {
  page: string;
  /** The page's current filter/sort/column state — stored verbatim. */
  currentPayload: P;
  /** Restore a previously-saved payload back onto the page. */
  onApply: (payload: P) => void;
}) {
  const { enabled, ready } = useFeatureModules();
  const moduleOn = enabled("ui.saved_views");

  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [toDelete, setToDelete] = useState<SavedView | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const appliedDefault = useRef(false);

  const viewsQ = useQuery({
    queryKey: ["saved-views", page],
    queryFn: () => savedViewsApi.list(page),
    // Fetch once the module is known-enabled (not gated on ``open``) so the
    // default view can auto-apply on mount. Gated on ``ready`` to avoid a
    // 404 before the module set resolves.
    enabled: ready && moduleOn,
    staleTime: 30_000,
  });

  // Auto-apply the operator's default view once per mount (#77 is_default).
  // The ref guard means clearing/changing filters during a visit sticks;
  // the default only re-applies on a fresh mount / navigation back.
  useEffect(() => {
    if (appliedDefault.current || !viewsQ.isSuccess) return;
    appliedDefault.current = true;
    const def = viewsQ.data.find((v) => v.is_default);
    if (def) onApply(def.payload as P);
  }, [viewsQ.isSuccess, viewsQ.data, onApply]);

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["saved-views", page] });

  const save = useMutation({
    mutationFn: () =>
      savedViewsApi.create({
        page,
        name: name.trim(),
        payload: currentPayload,
      }),
    onSuccess: () => {
      setName("");
      invalidate();
    },
  });

  const setDefault = useMutation({
    mutationFn: (v: SavedView) =>
      savedViewsApi.update(v.id, { is_default: !v.is_default }),
    onSuccess: invalidate,
  });

  const remove = useMutation({
    mutationFn: (id: string) => savedViewsApi.remove(id),
    onSuccess: () => {
      setToDelete(null);
      invalidate();
    },
  });

  // Esc / outside press / focus leaving close the panel (#3159).
  const closePanel = useCallback(() => setOpen(false), []);
  const { onBlur } = useDismissableMenu({
    open,
    onClose: closePanel,
    containerRef: ref,
    triggerRef,
  });

  // Hidden when the operator disabled the module. Stay optimistic while
  // the module set is still loading so the control doesn't blink in.
  if (ready && !moduleOn) return null;

  const views = viewsQ.data ?? [];
  const trimmed = name.trim();
  const nameClashes = views.some(
    (v) => v.name.toLowerCase() === trimmed.toLowerCase(),
  );

  return (
    <div ref={ref} className="relative" onBlur={onBlur}>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        title="Saved views — store and recall this page's filters"
        className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
      >
        <Bookmark className="h-3.5 w-3.5" />
        Views
        <ChevronDown className="h-3.5 w-3.5" />
      </button>
      {open && (
        <div className="absolute right-0 z-20 mt-1 w-72 overflow-hidden rounded-md border bg-popover shadow-md">
          <div className="max-h-64 overflow-y-auto">
            {viewsQ.isLoading && (
              <p className="px-3 py-2 text-sm text-muted-foreground">
                Loading…
              </p>
            )}
            {!viewsQ.isLoading && views.length === 0 && (
              <p className="px-3 py-2 text-sm text-muted-foreground">
                No saved views yet. Set your filters, then save below.
              </p>
            )}
            {views.map((v) => (
              <div
                key={v.id}
                className="flex items-center gap-1 px-1 hover:bg-muted"
              >
                <button
                  type="button"
                  onClick={() => {
                    onApply(v.payload as P);
                    setOpen(false);
                  }}
                  className="flex-1 truncate px-2 py-2 text-left text-sm"
                  title={`Apply "${v.name}"`}
                >
                  {v.name}
                </button>
                <button
                  type="button"
                  onClick={() => setDefault.mutate(v)}
                  title={v.is_default ? "Default view" : "Set as default"}
                  className="rounded p-1 hover:bg-background"
                >
                  <Star
                    className={
                      v.is_default
                        ? "h-3.5 w-3.5 fill-amber-400 text-amber-500"
                        : "h-3.5 w-3.5 text-muted-foreground"
                    }
                  />
                </button>
                <button
                  type="button"
                  onClick={() => {
                    // Close first, so the confirm dialog owns Esc.
                    setOpen(false);
                    setToDelete(v);
                  }}
                  title="Delete view"
                  className="rounded p-1 text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
          <div className="border-t p-2">
            <div className="flex items-center gap-1">
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Save current view as…"
                className="w-full rounded-md border bg-background px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && trimmed && !nameClashes)
                    save.mutate();
                }}
              />
              <button
                type="button"
                disabled={!trimmed || nameClashes || save.isPending}
                onClick={() => save.mutate()}
                className="shrink-0 rounded-md bg-primary px-2.5 py-1 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                Save
              </button>
            </div>
            {nameClashes && trimmed && (
              <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">
                A view with this name already exists.
              </p>
            )}
            {save.isError && (
              <p className="mt-1 text-xs text-destructive">
                Couldn't save — try a different name.
              </p>
            )}
          </div>
        </div>
      )}

      <ConfirmModal
        open={toDelete !== null}
        title="Delete saved view"
        message={`Delete the saved view "${toDelete?.name ?? ""}"?`}
        confirmLabel="Delete"
        tone="destructive"
        onConfirm={() => {
          if (toDelete) remove.mutate(toDelete.id);
        }}
        onClose={() => setToDelete(null)}
      />
    </div>
  );
}
