import { useEffect, useRef, useState } from "react";
import type { QueryClient } from "@tanstack/react-query";

export type FreshRow<T> = {
  /** The row read when the dialog opened; undefined in create mode. */
  row: T | undefined;
  /** True once the dialog may render its form. */
  ready: boolean;
  /** Set when the fresh read failed; the form must not render. */
  error: unknown;
  /** Read again after a failure. */
  retry: () => void;
};

/**
 * Read an edit dialog's row fresh when the dialog opens (#3075 / #3076 / #3077).
 *
 * Edit dialogs seed their form once, from a row the page holds out of a cached
 * list or a click-time snapshot. When another surface changed the object since
 * (and the list has not refetched yet), the dialog shows the old value and an
 * untouched Save writes it back. `load` fetches the row now; the dialog should
 * render its form only once `ready` is true, with the returned `row`.
 *
 * A failed read (or a load that finds no row) is reported in `error` and the
 * form is NOT rendered: falling back to the cached row would seed the form
 * with exactly the stale values this exists to avoid, silently, on any
 * network blip. The caller shows `FreshRowError` (retry or cancel) instead.
 *
 * Pair with `changedFields` so the Save sends only what the operator changed.
 */
export function useFreshRow<T>(
  row: T | undefined,
  load: () => Promise<T | undefined>,
): FreshRow<T> {
  const creating = row === undefined;
  const [state, setState] = useState<{
    row: T | undefined;
    ready: boolean;
    error: unknown;
  }>({ row: undefined, ready: creating, error: null });
  const [attempt, setAttempt] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    if (creating) return;
    let live = true;
    Promise.resolve()
      .then(() => loadRef.current())
      .then((fresh) => {
        if (fresh === undefined)
          throw new Error("it was not found, and may have been deleted");
        if (live) setState({ row: fresh, ready: true, error: null });
      })
      .catch((error: unknown) => {
        if (live) setState({ row: undefined, ready: false, error });
      });
    return () => {
      live = false;
    };
    // Once per open (and per retry): the dialog is mounted for one row id.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt]);
  return {
    row: state.row,
    ready: state.ready,
    error: state.error,
    retry: () => {
      setState({ row: undefined, ready: false, error: null });
      setAttempt((n) => n + 1);
    },
  };
}

/**
 * The entries of `after` that differ from `before`: a Save's PATCH-style body.
 * Compared by JSON so arrays and nulls behave (undefined and null count as the
 * same; "" is not null, so a cleared text field is sent). An empty result
 * means the Save has nothing to send.
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
 * Refetch the cached list(s) under each of `queryKeys` and return the row with
 * `id`, looking through plain arrays and `{items}` pages. Rejects when a
 * refetch fails, so the caller never seeds from the stale cache, and resolves
 * undefined when no refetched list holds the row.
 */
export async function refetchRow<T extends { id: string }>(
  qc: QueryClient,
  queryKeys: readonly (readonly unknown[])[],
  id: string,
): Promise<T | undefined> {
  await Promise.all(
    queryKeys.map((queryKey) =>
      qc.refetchQueries({ queryKey }, { throwOnError: true }),
    ),
  );
  for (const queryKey of queryKeys) {
    for (const [, data] of qc.getQueriesData<unknown>({ queryKey })) {
      const rows = Array.isArray(data)
        ? data
        : ((data as { items?: unknown[] } | undefined)?.items ?? []);
      const hit = (rows as T[]).find((r) => r && r.id === id);
      if (hit) return hit;
    }
  }
  return undefined;
}
