import { describe, expect, it } from "vitest";
import { withoutEmptyValues } from "./withoutEmptyValues";

describe("withoutEmptyValues (#4558)", () => {
  it("drops empty strings and null, keeps false, 0 and text", () => {
    expect(
      withoutEmptyValues({
        a: "",
        b: null,
        c: false,
        d: 0,
        e: "x",
        f: undefined,
      }),
    ).toEqual({ c: false, d: 0, e: "x" });
  });
});
