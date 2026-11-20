import type { PasswordPolicy } from "@/lib/api";

/**
 * Evaluating the password policy in the browser (#1004).
 *
 * The Change Password screen used to render its rule list and gate its submit
 * button from two different places: the list computed five rows, the button
 * checked only whether the confirm field matched. So an 8-character password
 * under a 12-character policy showed four green ticks and an enabled button,
 * and the server refused it — the browser had already computed the answer and
 * threw it away.
 *
 * Both now come from `evaluatePolicy`, which is the point of the module: one
 * evaluation, used for the display AND the gate, so they cannot disagree.
 *
 * The server stays authoritative. This only avoids a round trip whose outcome
 * the page can already predict — it never *permits* anything, and the rules it
 * cannot check (history) are deliberately not part of the gate.
 */

/** A rule this page can actually evaluate as the operator types. */
export interface PolicyRule {
  ok: boolean;
  label: string;
}

export interface PolicyEvaluation {
  /** Evaluated rules, in display order. */
  rules: PolicyRule[];
  /**
   * Rules the server enforces that the browser cannot check — today just
   * password history, which needs the stored hashes.
   *
   * Kept OUT of `rules` rather than given a permissive `ok`. The old code
   * pushed history in as a rule whose test was `candidate.length > 0`, so any
   * single character ticked it: an 8-character password read as four-of-five
   * done when it was one-of-four, which is most of why the screen looked
   * satisfied. A note renders differently and counts for nothing.
   */
  notes: string[];
  /** True when every EVALUATED rule passes. Never gates on `notes`. */
  satisfied: boolean;
}

export function evaluatePolicy(
  policy: PasswordPolicy,
  candidate: string,
): PolicyEvaluation {
  const rules: PolicyRule[] = [
    {
      ok: candidate.length >= policy.min_length,
      label: `At least ${policy.min_length} characters`,
    },
  ];
  if (policy.require_uppercase) {
    rules.push({
      ok: /[A-Z]/.test(candidate),
      label: "Contains an uppercase letter",
    });
  }
  if (policy.require_lowercase) {
    rules.push({
      ok: /[a-z]/.test(candidate),
      label: "Contains a lowercase letter",
    });
  }
  if (policy.require_digit) {
    rules.push({ ok: /\d/.test(candidate), label: "Contains a digit" });
  }
  if (policy.require_symbol) {
    rules.push({
      ok: /[^A-Za-z0-9]/.test(candidate),
      label: "Contains a symbol",
    });
  }

  const notes: string[] = [];
  if (policy.history_count > 0) {
    notes.push(
      `Cannot match your last ${policy.history_count === 1 ? "password" : `${policy.history_count} passwords`} — checked when you submit`,
    );
  }

  return { rules, notes, satisfied: rules.every((r) => r.ok) };
}

/**
 * Pull human-readable messages out of whatever shape the API returned.
 *
 * Three shapes reach this screen and only two were handled (#1004):
 *
 *  - `{reason, errors: [...]}` — the policy / history path's 400. Handled.
 *  - a plain string — bad current password, generic failure. Handled.
 *  - an ARRAY of pydantic errors — any `field_validator` on the request
 *    model, which is a 422. An array *is* an object in JS, so the first
 *    branch's `Array.isArray(detail.errors)` was `undefined` and both
 *    branches missed; the page fell through to "Check your current password
 *    and try again". The current password was fine. That message pointed the
 *    operator at the wrong field, on the one screen they cannot navigate
 *    away from.
 *
 * Returns `{fieldErrors}` for anything belonging under the new-password
 * field, or `{message}` for a generic failure.
 */
export interface ParsedApiError {
  fieldErrors: string[];
  message: string;
}

interface PydanticError {
  msg?: unknown;
  loc?: unknown;
}

export function parsePasswordError(
  detail: unknown,
  fallback: string,
): ParsedApiError {
  if (typeof detail === "string") {
    return { fieldErrors: [], message: detail };
  }
  if (Array.isArray(detail)) {
    // Pydantic prefixes value-error messages with "Value error, ", which is
    // framework noise in front of a message written for the operator.
    const msgs = (detail as PydanticError[])
      .map((e) => (typeof e?.msg === "string" ? e.msg : ""))
      .filter(Boolean)
      .map((m) => m.replace(/^Value error,\s*/, ""));
    return msgs.length
      ? { fieldErrors: msgs, message: "" }
      : { fieldErrors: [], message: fallback };
  }
  if (detail && typeof detail === "object") {
    const errors = (detail as { errors?: unknown }).errors;
    if (Array.isArray(errors)) {
      const msgs = errors.filter((e): e is string => typeof e === "string");
      if (msgs.length) return { fieldErrors: msgs, message: "" };
    }
  }
  return { fieldErrors: [], message: fallback };
}
