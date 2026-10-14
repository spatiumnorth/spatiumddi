import { describe, expect, it } from "vitest";
import { activityTone } from "./activity-tone";

describe("activityTone", () => {
  it("reads a failed sign-in (result=failure) as a failure, not a login", () => {
    expect(activityTone("login", "failure")).toEqual({
      tone: "bad",
      label: "FAIL",
    });
  });
  it("keeps the existing mappings", () => {
    expect(activityTone("update", "failed")).toEqual({
      tone: "bad",
      label: "FAIL",
    });
    expect(activityTone("update", "denied")).toEqual({
      tone: "warn",
      label: "DENY",
    });
    expect(activityTone("create", "success").tone).toBe("good");
    expect(activityTone("delete", "success").tone).toBe("bad");
    expect(activityTone("login", "success")).toEqual({
      tone: "info",
      label: "LOGIN",
    });
  });
});
