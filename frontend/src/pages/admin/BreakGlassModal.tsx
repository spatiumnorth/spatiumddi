/**
 * BreakGlassModal — the mandatory anti-lockout escape hatch (#62).
 *
 * When the self-governance lock (``approvals_protect_controls``) is on, every
 * WEAKENING control change (disable the approval module, disable / delete /
 * lower a policy, turn the lock off) normally routes through the two-person
 * approval queue. If no second superadmin is available you'd be permanently
 * wedged — so a superadmin can force the change IMMEDIATELY here.
 *
 * This is deliberately alarmed: it requires BOTH a password (or TOTP for
 * external-auth accounts with no local password) AND a typed confirmation
 * phrase, and the server writes a HIGH-severity ``approvals.break_glass``
 * audit row + fires the ``governance.break_glass`` event. We surface that
 * loudly in the modal copy so it never feels routine.
 *
 * The backend phrase guard is an EXACT match on "BREAK GLASS" (422 otherwise),
 * mirrored here so the Confirm button stays disabled until it's typed right.
 */

import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";

import {
  type ApprovalControlKind,
  featureModulesApi,
  formatApiError,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { FormError } from "@/components/ui/form-error";

// Must match BREAK_GLASS_PHRASE in backend feature_modules.py.
const BREAK_GLASS_PHRASE = "BREAK GLASS";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const KIND_LABELS: Record<ApprovalControlKind, string> = {
  disable_module: "Disable approval workflows entirely",
  disable_policy: "Disable this approval policy",
  delete_policy: "Delete this approval policy",
  lower_superadmin_gate: "Stop this policy applying to superadmins",
  unlock: "Remove the require-approval-to-disable lock",
};

export function BreakGlassModal({
  kind,
  policyId,
  policyName,
  onClose,
  onDone,
}: {
  kind: ApprovalControlKind;
  policyId?: string | null;
  /** When the kind targets a policy, render its name in the warning copy. */
  policyName?: string | null;
  onClose: () => void;
  /** Fired after a successful force so the caller can refresh its own queries. */
  onDone?: () => void;
}) {
  const qc = useQueryClient();
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [phrase, setPhrase] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setPassword("");
    setTotp("");
    setPhrase("");
    setError(null);
  }, [kind, policyId]);

  const mutation = useMutation({
    mutationFn: () =>
      featureModulesApi.breakGlass({
        kind,
        policy_id: policyId ?? null,
        password: password || null,
        totp_code: totp || null,
        confirm_phrase: phrase,
      }),
    onSuccess: () => {
      // The force mutated a control surface — bust every cache it could touch.
      qc.invalidateQueries({ queryKey: ["feature-modules"] });
      qc.invalidateQueries({ queryKey: ["change-requests"] });
      qc.invalidateQueries({ queryKey: ["approvals-lock"] });
      onDone?.();
      onClose();
    },
    onError: (err) =>
      setError(formatApiError(err, "Break-glass failed. Check the audit log.")),
  });

  const phraseOk = phrase === BREAK_GLASS_PHRASE;
  // Either a password OR a TOTP code is required (the server picks based on the
  // account); require at least one to be present client-side.
  const credOk = password.trim() !== "" || totp.trim() !== "";
  const disabled = !phraseOk || !credOk || mutation.isPending;

  const target =
    policyName != null
      ? `${KIND_LABELS[kind]} (${policyName})`
      : KIND_LABELS[kind];

  return (
    <Modal title="Break glass — force control change" onClose={onClose} wide>
      <div className="space-y-4">
        <div className="flex items-start gap-2 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-700 dark:text-rose-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
          <div className="space-y-1">
            <p className="font-medium">
              This bypasses the two-person approval gate.
            </p>
            <p className="text-xs">
              You're about to force: <strong>{target}</strong>. This is the
              anti-lockout escape hatch — it executes immediately under your
              identity, writes a high-severity audit row, and fires a{" "}
              <span className="font-mono">governance.break_glass</span> alert.
              Use it only when no second superadmin can approve.
            </p>
          </div>
        </div>

        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Confirm with your password
          </label>
          <input
            type="password"
            autoComplete="current-password"
            className={inputCls}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Local password"
          />
          <p className="text-[11px] text-muted-foreground/80">
            External-auth accounts with no local password: enter your TOTP code
            below instead.
          </p>
        </div>

        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            TOTP code (if your account uses MFA without a local password)
          </label>
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            className={inputCls}
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
            placeholder="123456"
          />
        </div>

        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Type{" "}
            <span className="font-mono font-semibold">
              {BREAK_GLASS_PHRASE}
            </span>{" "}
            to confirm
          </label>
          <input
            type="text"
            autoCapitalize="characters"
            className={cn(
              inputCls,
              phrase !== "" &&
                !phraseOk &&
                "border-destructive focus:ring-destructive",
            )}
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder={BREAK_GLASS_PHRASE}
          />
        </div>

        {error && (
          <FormError className="text-xs text-destructive">{error}</FormError>
        )}

        <div className="flex justify-end gap-2">
          <HeaderButton
            variant="secondary"
            onClick={onClose}
            disabled={mutation.isPending}
          >
            Cancel
          </HeaderButton>
          <HeaderButton
            variant="destructive"
            icon={AlertTriangle}
            disabled={disabled}
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending ? "Forcing…" : "Break glass & force"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}
