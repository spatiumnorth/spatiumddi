import { describe, expect, it } from "vitest";
import { scopeDeleteCopy } from "./dhcp-scope-delete";

describe("scopeDeleteCopy (#2706)", () => {
  it("says a superadmin restores from Trash, not that the user can", () => {
    const { description } = scopeDeleteCopy("s", 1, 1);
    expect(description).toContain("A superadmin can restore");
    expect(description).not.toMatch(/are restorable/);
  });
});
