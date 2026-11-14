export interface TagRow {
  k: string;
  v: string;
  /** Bulk edit only: delete this key instead of setting it. */
  remove: boolean;
  /** The stored value, kept so an untouched non-string value (a number,
   *  a boolean) is written back as it was and not as its text. */
  orig?: unknown;
}

/** A record's tags as editable rows, in key order. */
export function tagRowsFromRecord(
  tags: Record<string, unknown> | null | undefined,
): TagRow[] {
  return Object.entries(tags ?? {}).map(([k, v]) => ({
    k,
    v: v === null || v === undefined ? "" : String(v),
    remove: false,
    orig: v,
  }));
}

/** The record the rows describe: blank keys dropped, keys trimmed, a later
 *  duplicate overriding an earlier one. */
export function tagRowsToRecord(rows: TagRow[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const row of rows) {
    const k = row.k.trim();
    if (!k || row.remove) continue;
    out[k] =
      row.orig !== undefined && String(row.orig ?? "") === row.v
        ? row.orig
        : row.v;
  }
  return out;
}
