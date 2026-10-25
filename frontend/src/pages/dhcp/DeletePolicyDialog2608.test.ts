import { describe, expect, it } from "vitest";
import { deletePolicyDescription } from "./devicePolicyCopy";

describe("Delete device policy copy (#2608)", () => {
  it("says a pool-referenced class blocks the delete", () => {
    const said = deletePolicyDescription("p1", "spatium-device-p1");
    expect(said).toMatch(/cannot be deleted/);
    expect(said).toMatch(/spatium-device-p1/);
  });
  it("no longer claims pools lose the class", () => {
    expect(deletePolicyDescription("p1", "c")).not.toMatch(
      /no longer match any class/,
    );
  });
});
