import { useEffect, useRef, useState } from "react";
import type { QueryClient } from "@tanstack/react-query";

/**
 * Read an edit dialog's row fresh when the dialog opens (#3075 / #3076 / #3077).
 *
 * Edit dialogs seed their form once, from a row the page holds out of a cached
 * list or a click-time snapshot. When another surface changed the object since
 * (and the list has not refetched yet), the dialog shows the old value and an
 * untouched Save writes it back. `load` fetches the row now; the dialog should
 * render only once `ready` is true, with the returned `row`. A failed load
 * falls back to the row the caller already had, so the dialog never gets
 * stuck closed.
 *
 * Pair with `changedFields` so the Save sends only what the operator changed.
 */
export function useFreshRow<T>(
  row: T | undefined,
  load: () => Promise<T | undefined>,
): { row: T | undefined; ready: boolean } {
  const [state, setState] = useState<{ row: T | undefined; ready: boolean }>({
    row,
    ready: row === undefined,
  });
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    if (row === undefined) return;
    let live = true;
    Promise.resolve()
      .then(() => loadRef.current())
      .then((fresh) => live && setState({ row: fresh ?? row, ready: true }))
      .catch(() => live && setState({ row, ready: true }));
    return () => {
      live = false;
    };
    // Once per open: the dialog is mounted for one row id.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return state;
}

/**
 * The entries of `after` that differ from `before`: a Save's PATCH-style body.
 * Compared by JSON so arrays and nulls behave; an empty result means the Save
 * has nothing to send.
 */
export function changedFields<A extends Record<string, unknown>>(
  before: Record<string, unknown>,
  after: A,
): Partial<A> {
  const out: Partial<A> = {};
  for (const k of Object.keys(after) as (keyof A & string)[]) {
    if (JSON.stringify(before[k] ?? null) !== JSON.stringify(after[k] ?? null))
      out[k] = after[k];
  }
  return out;
}

/**
 * Refetch the cached list(s) under `queryKey` and return the row with `id`,
 * looking through plain arrays and `{items}` pages. Resolves undefined when no
 * such row is cached (the caller then keeps the row it had).
 */
export async function refetchRow<T extends { id: string }>(
  qc: QueryClient,
  queryKey: readonly unknown[],
  id: string,
): Promise<T | undefined> {
  await qc.refetchQueries({ queryKey });
  for (const [, data] of qc.getQueriesData<unknown>({ queryKey })) {
    const rows = Array.isArray(data)
      ? data
      : ((data as { items?: unknown[] } | undefined)?.items ?? []);
    const hit = (rows as T[]).find((r) => r && r.id === id);
    if (hit) return hit;
  }
  return undefined;
}
