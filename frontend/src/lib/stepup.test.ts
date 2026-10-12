import { describe, expect, it } from "vitest";

import { isStepUpRequired, stepUpBody } from "./stepup";

const answer = (status: number, headers: Record<string, unknown> = {}) => ({
  response: { status, headers },
});

describe("isStepUpRequired (#1412)", () => {
  it("is true only for a 403 carrying the header", () => {
    expect(isStepUpRequired(answer(403, { "x-stepup-required": "true" }))).toBe(
      true,
    );
  });

  it("is false for any other 403, so a real refusal is shown as an error", () => {
    expect(isStepUpRequired(answer(403))).toBe(false);
    expect(
      isStepUpRequired(answer(403, { "x-stepup-required": "false" })),
    ).toBe(false);
  });

  it("is false for other statuses and for errors with no response", () => {
    expect(isStepUpRequired(answer(429, { "x-stepup-required": "true" }))).toBe(
      false,
    );
    expect(isStepUpRequired(new Error("network"))).toBe(false);
    expect(isStepUpRequired(undefined)).toBe(false);
  });
});

describe("stepUpBody", () => {
  it("sends null for an empty field rather than an empty string", () => {
    expect(stepUpBody("pw", "")).toEqual({
      stepup_password: "pw",
      stepup_totp_code: null,
    });
  });
});
