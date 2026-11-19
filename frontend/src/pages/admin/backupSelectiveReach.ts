import type { BackupSection } from "@/lib/api";

/**
 * What a selective restore of ``selected`` replaces beyond the ticked
 * sections: the union of each ticked section's ``also_restores`` (computed
 * server-side from the restore's own FK-cascade closure), minus the sections
 * that are themselves ticked or always-on (#4333).
 */
export function reachOutsideSelection(
  catalog: BackupSection[],
  selected: string[],
): { key: string; label: string; tables: string[] }[] {
  const inside = new Set(selected);
  for (const s of catalog) if (!s.selectable) inside.add(s.key);
  const merged = new Map<
    string,
    { key: string; label: string; tables: Set<string> }
  >();
  for (const s of catalog) {
    if (!inside.has(s.key)) continue;
    for (const r of s.also_restores ?? []) {
      if (inside.has(r.key)) continue;
      const cur = merged.get(r.key) ?? {
        key: r.key,
        label: r.label,
        tables: new Set<string>(),
      };
      r.tables.forEach((t) => cur.tables.add(t));
      merged.set(r.key, cur);
    }
  }
  return [...merged.values()].map((m) => ({
    key: m.key,
    label: m.label,
    tables: [...m.tables].sort(),
  }));
}
