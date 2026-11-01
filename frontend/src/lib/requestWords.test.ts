import { describe, expect, it } from "vitest";
import { plainSubmitError, plainText } from "./requestWords";

describe("plainText", () => {
  it("drops bold and code marks", () => {
    expect(plainText("Create **A** `x` and `y`")).toBe("Create A x and y");
  });
});

describe("plainSubmitError", () => {
  const label = (f: string) => ({ ttl: "TTL (seconds)" })[f] ?? f;
  it("rewrites numeric bounds and types", () => {
    expect(
      plainSubmitError(
        "Invalid request payload — ttl: Input should be greater than or equal to 60",
        label,
      ),
    ).toBe("TTL (seconds) must be at least 60.");
  });
  it("leaves other errors alone", () => {
    expect(plainSubmitError("Unknown request kind 'x'", label)).toBe(
      "Unknown request kind 'x'",
    );
  });
});
