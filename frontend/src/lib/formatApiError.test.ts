/**
 * formatApiError / formatDialogError on the object and 422 shapes (#3040,
 * #3041). The object arm is shared by every error-render site, so these pin
 * what the `errors` list changed and what it left alone.
 */

import { describe, expect, it } from "vitest";
import { formatApiError, formatDialogError } from "@/lib/api";

function refusal(detail: unknown) {
  return { message: "Request failed", response: { data: { detail } } };
}

describe("formatApiError, an object detail", () => {
  it("says a list of string errors in words (#3040)", () => {
    expect(
      formatApiError(
        refusal({ reason: "password_policy", errors: ["one", "two"] }),
      ),
    ).toBe("one; two");
  });

  it("prefers message over errors (the DNS sheet import's 422)", () => {
    expect(
      formatApiError(
        refusal({
          message: "2 row(s) have errors; nothing was imported.",
          errors: [{ row: 3, reason: "bad" }],
        }),
      ),
    ).toBe("2 row(s) have errors; nothing was imported.");
  });

  it("keeps the JSON when errors holds no strings, rather than saying nothing", () => {
    const detail = { errors: [{ row: 3, reason: "bad" }] };
    expect(formatApiError(refusal(detail))).toBe(JSON.stringify(detail));
    const empty = { reason: "x", errors: [] };
    expect(formatApiError(refusal(empty))).toBe(JSON.stringify(empty));
  });
});

describe("formatDialogError, pydantic's prefix", () => {
  it("drops the leading 'Value error, ' of each 422 entry", () => {
    expect(
      formatDialogError(
        refusal([
          {
            loc: ["body", "name"],
            msg: "Value error, Role name cannot be empty",
          },
          { loc: ["body"], msg: "Value error, two" },
        ]),
      ),
    ).toBe("name: Role name cannot be empty; two");
  });

  it("leaves the same words alone inside a real message", () => {
    const text = "Upstream said: Value error, x; Value error, y";
    expect(formatDialogError(refusal(text))).toBe(text);
    expect(formatDialogError(refusal({ message: text }))).toBe(text);
    expect(
      formatDialogError(refusal([{ loc: ["body", "n"], msg: `Bad: ${text}` }])),
    ).toBe(`n: Bad: ${text}`);
  });

  it("formatApiError keeps the prefix, as its callers' tests expect", () => {
    expect(
      formatApiError(refusal([{ loc: ["body", "n"], msg: "Value error, x" }])),
    ).toBe("n: Value error, x");
  });
});
