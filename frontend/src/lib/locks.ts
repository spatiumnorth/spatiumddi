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

/** A delete control's gate once the object's lock is taken into account
 *  (#3361): any lock, at either level, disables it and puts the reason in its
 *  title; otherwise ``gate`` (the ``permissionGate`` answer) stands. */
export function deleteLockGate(
  r: LockFields | null | undefined,
  gate: { disabled?: boolean; title?: string } = {},
): { disabled?: boolean; title?: string } {
  if (r && isDeleteBlockedByLock(r)) {
    return { disabled: true, title: lockTitle(r) ?? gate.title };
  }
  return gate;
}

/** An edit control's title on an edit-locked object: still enabled, because
 *  annotations (description, tags, custom fields, owner) stay editable, but
 *  the title says what is frozen and why. Nothing on a delete-locked or
 *  unlocked object. */
export function editLockHint(r: LockFields | null | undefined): {
  title?: string;
} {
  if (!r || r.lock_level !== "edit") return {};
  return {
    title: `${lockTitle(r)}. Only description, tags and custom fields can be changed.`,
  };
}

/** The padlock filter every list that has filters offers (#3361). */
export type LockedFilter = "all" | "locked" | "unlocked";

export function matchesLockedFilter(
  r: LockFields,
  filter: LockedFilter,
): boolean {
  if (!filter || filter === "all") return true;
  return filter === "locked" ? !!r.lock_level : !r.lock_level;
}
