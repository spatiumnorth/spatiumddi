import { describe, expect, it } from "vitest";

import { deleteLockGate, editLockHint, matchesLockedFilter } from "./locks";

const edit = {
  lock_level: "edit",
  locked_by: "alice",
  lock_reason: "freeze",
} as const;
const del = {
  lock_level: "delete",
  locked_by: "bob",
  lock_reason: "hold",
} as const;

describe("deleteLockGate (#3361)", () => {
  it("disables delete at either level, with the reason in the title", () => {
    for (const r of [edit, del]) {
      const g = deleteLockGate(r, {});
      expect(g.disabled).toBe(true);
      expect(g.title).toContain(r.lock_reason);
      expect(g.title).toContain(r.locked_by);
    }
  });

  it("leaves the permission gate alone on an unlocked object", () => {
    const perm = { disabled: true, title: "Requires delete permission" };
    expect(deleteLockGate({ lock_level: null }, perm)).toBe(perm);
    expect(deleteLockGate(undefined, {})).toEqual({});
  });
});

describe("editLockHint (#3361)", () => {
  it("only an edit lock hints, and says annotations stay editable", () => {
    expect(editLockHint(edit).title).toContain("freeze");
    expect(editLockHint(edit).title).toContain("description");
    expect(editLockHint(del)).toEqual({});
    expect(editLockHint({ lock_level: null })).toEqual({});
  });
});

describe("matchesLockedFilter (#3361)", () => {
  it("splits locked from unlocked and passes everything on all", () => {
    expect(matchesLockedFilter(edit, "locked")).toBe(true);
    expect(matchesLockedFilter(edit, "unlocked")).toBe(false);
    expect(matchesLockedFilter({}, "locked")).toBe(false);
    expect(matchesLockedFilter({}, "unlocked")).toBe(true);
    expect(matchesLockedFilter(edit, "all")).toBe(true);
    // The empty string a filter object holds for "all" is not a filter.
    expect(matchesLockedFilter({}, "" as never)).toBe(true);
  });
});
