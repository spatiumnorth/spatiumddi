import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { isAxiosError } from "axios";
import { authApi } from "@/lib/api";
import { evaluatePolicy, parsePasswordError } from "@/lib/password-policy";
import { cn } from "@/lib/utils";
import { PasswordInput } from "@/components/ui/password-input";

const GENERIC_FAILURE = "Failed to change password — try again.";

export function ChangePasswordPage() {
  const navigate = useNavigate();
  // Account's "Change password…" link says the change is the user's own
  // choice; a forced change arrives by redirect with no such state (#2441).
  const voluntary =
    (useLocation().state as { voluntary?: boolean } | null)?.voluntary === true;
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [policyErrors, setPolicyErrors] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);

  const { data: policy } = useQuery({
    queryKey: ["password-policy"],
    queryFn: () => authApi.passwordPolicy(),
    staleTime: 60_000,
  });

  // Live mismatch feedback (#814) — same pattern as admin/UsersPage. Only
  // flagged once the confirm field is non-empty, so the user isn't yelled
  // at mid-typing on the first character. The submit-time guard below
  // stays as a backstop; it also covers the empty-confirm case.
  const mismatch =
    confirmPassword.length > 0 && newPassword !== confirmPassword;

  // #1004 — one evaluation drives BOTH the rule list and the submit gate.
  // They used to be computed separately, so the page could show a rule
  // failing and still let the operator submit it. Until the policy has
  // loaded there is nothing to gate on, so submit stays enabled and the
  // server remains the authority (which it is regardless).
  const evaluation = policy ? evaluatePolicy(policy, newPassword) : null;
  const unmetPolicy = evaluation ? !evaluation.satisfied : false;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setPolicyErrors([]);

    if (newPassword !== confirmPassword) {
      setError("New passwords do not match.");
      return;
    }
    if (evaluation && !evaluation.satisfied) {
      // Belt to the disabled button's braces: a form can still be submitted
      // by pressing Enter in some browsers, and the rule list is right here.
      setPolicyErrors(
        evaluation.rules.filter((r) => !r.ok).map((r) => r.label),
      );
      return;
    }

    setLoading(true);
    try {
      await authApi.changePassword(currentPassword, newPassword);
      navigate("/dashboard");
    } catch (err) {
      // Three shapes reach here: the policy / history 400's
      // ``{reason, errors: [...]}``, a plain string detail, and a pydantic
      // 422's ARRAY of field errors. The third used to fall through to the
      // generic message, which blamed the current password for a fault in
      // the new one (#1004). parsePasswordError owns all three.
      if (isAxiosError(err)) {
        const parsed = parsePasswordError(
          err.response?.data?.detail,
          GENERIC_FAILURE,
        );
        setPolicyErrors(parsed.fieldErrors);
        setError(parsed.message);
      } else {
        setError("Unexpected error — try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-6 rounded-lg border bg-card p-8 shadow-sm">
        <div className="space-y-1 text-center">
          <h1 className="text-2xl font-bold tracking-tight">Change Password</h1>
          <p className="text-sm text-muted-foreground">
            {voluntary
              ? "Choose a new password for this account."
              : "You must set a new password before continuing."}
          </p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="current-password" className="text-sm font-medium">
              Current Password
            </label>
            <PasswordInput
              id="current-password"
              autoComplete="current-password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="new-password" className="text-sm font-medium">
              New Password
            </label>
            <PasswordInput
              id="new-password"
              autoComplete="new-password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            {evaluation && <PolicyHintList evaluation={evaluation} />}
          </div>
          <div className="space-y-2">
            <label htmlFor="confirm-password" className="text-sm font-medium">
              Confirm New Password
            </label>
            <PasswordInput
              id="confirm-password"
              autoComplete="new-password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className={cn(mismatch && "border-destructive")}
            />
            {mismatch && (
              <p className="text-sm text-destructive">Passwords do not match</p>
            )}
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          {policyErrors.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-sm text-destructive">
              {policyErrors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          )}
          <button
            type="submit"
            disabled={loading || mismatch || unmetPolicy}
            className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? "Updating…" : "Set New Password"}
          </button>
          {voluntary && (
            <Link
              to="/account"
              className="block w-full rounded-md border px-4 py-2 text-center text-sm hover:bg-muted"
            >
              Cancel
            </Link>
          )}
        </form>
      </div>
    </div>
  );
}

function PolicyHintList({
  evaluation,
}: {
  evaluation: import("@/lib/password-policy").PolicyEvaluation;
}) {
  return (
    <div className="space-y-0.5 text-xs">
      <ul className="space-y-0.5">
        {evaluation.rules.map((r) => (
          <li
            key={r.label}
            className={r.ok ? "text-emerald-500" : "text-muted-foreground"}
          >
            {r.ok ? "✓" : "○"} {r.label}
          </li>
        ))}
      </ul>
      {/* Rendered as a note, not a rule: it has no ✓/○ because nothing here
          evaluates it. Given the same green tick as the checkable rules, it
          made a failing password read as nearly-complete (#1004). */}
      {evaluation.notes.map((n) => (
        <p key={n} className="text-muted-foreground/70 italic">
          {n}
        </p>
      ))}
    </div>
  );
}
