import type { StepUp } from "@/lib/api";

export function stepUpBody(password: string, totp: string): StepUp {
  return { stepup_password: password || null, stepup_totp_code: totp || null };
}

/**
 * True for the server's "this needs your step-up" answer (#1412): a 403
 * carrying ``X-Stepup-Required``. Whether a group or role edit makes someone
 * a superadmin depends on server state the dialog cannot see, so the dialog
 * submits without a step-up, learns from this answer, and asks.
 */
export function isStepUpRequired(err: unknown): boolean {
  const response = (
    err as {
      response?: { status?: number; headers?: Record<string, unknown> };
    }
  )?.response;
  return (
    response?.status === 403 &&
    String(response.headers?.["x-stepup-required"] ?? "") === "true"
  );
}
