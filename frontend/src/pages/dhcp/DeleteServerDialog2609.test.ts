import { describe, expect, it } from "vitest";
import { deleteServerDescription } from "./serverDeleteCopy";

describe("Delete DHCP Server copy (#2609)", () => {
  it("says scopes stay with the group and what the last server means", () => {
    const said = deleteServerDescription("kea1");
    expect(said).toMatch(/stay with the group/);
    expect(said).toMatch(/last server/);
  });
  it("does not claim scopes are unassigned", () => {
    expect(deleteServerDescription("kea1")).not.toMatch(/unassigned/);
  });
});
