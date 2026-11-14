import type { LockFields } from "@/lib/api";

// Lock helpers shared by the padlock components and the pages (#3361).

export function lockTitle(r: LockFields): string | null {
  if (!r.lock_level) return null;
  const who = r.locked_by ? ` by ${r.locked_by}` : "";
  const why = r.lock_reason ? `: ${r.lock_reason}` : "";
  const what =
    r.lock_level === "edit"
      ? "Edit-locked (operative fields frozen, cannot be deleted)"
      : "Delete-locked (cannot be deleted)";
  return `${what}${who}${why}`;
}

export function isDeleteBlockedByLock(r: LockFields): boolean {
  return !!r.lock_level;
}
