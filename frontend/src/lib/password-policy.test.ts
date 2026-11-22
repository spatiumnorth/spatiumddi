/**
 * The Change Password screen's rule evaluation and error parsing (#1004).
 *
 * The screen told the operator a password was acceptable and the server then
 * refused it: the rule list and the submit gate were computed separately, and
 * a 422 whose `detail` is an array fell through to a message blaming the
 * CURRENT password for a fault in the new one — on the one screen a fresh
 * install cannot navigate away from.
 *
 * Pure logic, no DOM. The component wiring is pinned separately in
 * `pages/ChangePasswordPage.test.tsx`, because "the evaluator is right" and
 * "the button is wired to it" are different claims and it was the second one
 * that failed.
 */

import { describe, expect, it } from "vitest";
import type { PasswordPolicy } from "@/lib/api";
import { evaluatePolicy, parsePasswordError } from "./password-policy";

/** The shipped defaults, which are also the reproduction in the issue. */
const DEFAULT_POLICY: PasswordPolicy = {
  min_length: 12,
  require_uppercase: true,
  require_lowercase: true,
  require_digit: true,
  require_symbol: false,
  history_count: 5,
  max_age_days: 0,
};

const policy = (over: Partial<PasswordPolicy> = {}): PasswordPolicy => ({
  ...DEFAULT_POLICY,
  ...over,
});

describe("evaluatePolicy", () => {
  it("refuses the issue's reproduction", () => {
    // "Abcdef12" — 8 chars under a 12-char policy. Four of five rows went
    // green and the button stayed enabled.
    const e = evaluatePolicy(policy(), "Abcdef12");
    expect(e.satisfied).toBe(false);
    expect(e.rules.filter((r) => !r.ok).map((r) => r.label)).toEqual([
      "At least 12 characters",
    ]);
  });

  it("is satisfied by a password that meets every checkable rule", () => {
    const e = evaluatePolicy(policy(), "Abcdefghij12");
    expect(e.satisfied).toBe(true);
    expect(e.rules.every((r) => r.ok)).toBe(true);
  });

  it("keeps password history out of the rules entirely", () => {
    // The old code pushed it in with `ok: candidate.length > 0`, so one
    // character ticked it — which is most of why a failing password read as
    // nearly complete.
    const e = evaluatePolicy(policy({ history_count: 5 }), "x");
    expect(e.rules.map((r) => r.label)).not.toContain(
      expect.stringContaining("last 5"),
    );
    expect(e.notes).toHaveLength(1);
    expect(e.notes[0]).toContain("last 5 passwords");
  });

  it("does not let the history note affect the gate", () => {
    const withHistory = evaluatePolicy(
      policy({ history_count: 5 }),
      "Abcdefghij12",
    );
    const without = evaluatePolicy(
      policy({ history_count: 0 }),
      "Abcdefghij12",
    );
    expect(withHistory.satisfied).toBe(true);
    expect(without.satisfied).toBe(true);
    expect(without.notes).toEqual([]);
  });

  it("only lists the rules the policy actually turns on", () => {
    const e = evaluatePolicy(
      policy({
        require_uppercase: false,
        require_lowercase: false,
        require_digit: false,
        require_symbol: false,
        history_count: 0,
      }),
      "",
    );
    expect(e.rules.map((r) => r.label)).toEqual(["At least 12 characters"]);
    expect(e.notes).toEqual([]);
  });

  it("checks a required symbol", () => {
    const p = policy({ require_symbol: true });
    expect(evaluatePolicy(p, "Abcdefghij12").satisfied).toBe(false);
    expect(evaluatePolicy(p, "Abcdefghij1!").satisfied).toBe(true);
  });

  it("reports the operator's configured minimum, not a hardcoded one", () => {
    // The number 8 came from a server-side validator nobody could configure.
    expect(evaluatePolicy(policy({ min_length: 20 }), "").rules[0].label).toBe(
      "At least 20 characters",
    );
  });
});

describe("parsePasswordError", () => {
  const FALLBACK = "generic";

  it("reads the policy 400's error list", () => {
    const parsed = parsePasswordError(
      {
        reason: "password_policy",
        errors: ["Password must be at least 12 characters"],
      },
      FALLBACK,
    );
    expect(parsed.fieldErrors).toEqual([
      "Password must be at least 12 characters",
    ]);
    expect(parsed.message).toBe("");
  });

  it("reads a plain string detail", () => {
    const parsed = parsePasswordError(
      "Current password is incorrect",
      FALLBACK,
    );
    expect(parsed.message).toBe("Current password is incorrect");
    expect(parsed.fieldErrors).toEqual([]);
  });

  it("reads a pydantic 422 array — the shape that used to fall through", () => {
    // An array IS an object in JS, so the old `detail.errors` check read
    // `undefined`, both branches missed, and the page said "check your
    // current password". The current password was fine.
    const parsed = parsePasswordError(
      [
        {
          type: "value_error",
          loc: ["body", "new_password"],
          msg: "Value error, Password cannot be empty",
        },
      ],
      FALLBACK,
    );
    expect(parsed.fieldErrors).toEqual(["Password cannot be empty"]);
    expect(parsed.message).toBe("");
  });

  it("keeps every entry of a multi-error 422", () => {
    const parsed = parsePasswordError(
      [{ msg: "Value error, one" }, { msg: "Value error, two" }],
      FALLBACK,
    );
    expect(parsed.fieldErrors).toEqual(["one", "two"]);
  });

  it("falls back for shapes it cannot read", () => {
    for (const detail of [
      undefined,
      null,
      42,
      {},
      [],
      [{}],
      { errors: "nope" },
    ]) {
      const parsed = parsePasswordError(detail, FALLBACK);
      expect(parsed.message).toBe(FALLBACK);
      expect(parsed.fieldErrors).toEqual([]);
    }
  });
});

describe("history note singular (#4612)", () => {
  it("does not say '1 passwords'", () => {
    const note = evaluatePolicy(policy({ history_count: 1 }), "x").notes[0];
    expect(note).toContain("your last password");
    expect(note).not.toContain("1 passwords");
    expect(
      evaluatePolicy(policy({ history_count: 5 }), "x").notes[0],
    ).toContain("last 5 passwords");
  });
});
