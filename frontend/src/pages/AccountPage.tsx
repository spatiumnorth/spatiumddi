import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, KeyRound, ShieldCheck, Smartphone, Loader2 } from "lucide-react";
import { authApi, formatApiError, type MfaEnrolBeginResponse } from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { useSecretCloseGuard } from "@/hooks/useSecretCloseGuard";
import { Modal } from "@/components/ui/modal";
import { QrCode } from "@/components/QrCode";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

export function AccountPage() {
  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-3xl space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Account</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            Manage your password and two-factor authentication. Password changes
            apply to local accounts only — SSO users (LDAP / OIDC / SAML /
            RADIUS / TACACS+) manage credentials in their identity provider.
            Two-factor authentication is available to every account, and SSO
            superadmins must enrol it to re-confirm sensitive reveals (appliance
            kubeconfig, pairing codes, agent bootstrap keys).
          </p>
        </div>

        <PasswordPanel />
        <MfaPanel />
      </div>
    </div>
  );
}

function PasswordPanel() {
  return (
    <div className="rounded-lg border bg-card">
      <div className="border-b px-4 py-2">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold">Password</span>
        </div>
      </div>
      <div className="space-y-3 p-4 text-sm">
        <p className="text-xs text-muted-foreground">
          Local users only. Use the link below to rotate the password on this
          account.
        </p>
        <Link
          to="/change-password"
          state={{ voluntary: true }}
          className="inline-flex rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted"
        >
          Change password…
        </Link>
      </div>
    </div>
  );
}

function MfaPanel() {
  const qc = useQueryClient();
  const { data: status, isLoading } = useQuery({
    queryKey: ["mfa-status"],
    queryFn: authApi.mfaStatus,
  });
  const [enrolling, setEnrolling] = useState<MfaEnrolBeginResponse | null>(
    null,
  );
  const [showDisable, setShowDisable] = useState(false);
  const [showRegen, setShowRegen] = useState(false);
  const [askPassword, setAskPassword] = useState(false);

  const enrollBegin = useMutation({
    mutationFn: (password?: string) => authApi.mfaEnrollBegin(password),
    onSuccess: (data) => {
      setAskPassword(false);
      setEnrolling(data);
    },
  });
  // #1241 / #1354 — starting an enrolment needs a step-up: a password
  // (local, or checked at the account's own LDAP / RADIUS / TACACS+
  // provider), a forced re-login at the OIDC / SAML IdP, or — only when the
  // provider is gone or off — a recent sign-in.
  const needsPassword =
    status?.enrol_requires === "password" ||
    status?.enrol_requires === "provider_password";
  const needsReauth = status?.enrol_requires === "provider_reauth";
  const providerName = status?.enrol_provider_name ?? null;
  const reauth = useMutation({
    mutationFn: () => authApi.mfaEnrollReauth(),
    // Leaves the app for the IdP; the callback brings the browser back here.
    onSuccess: (data) => window.location.assign(data.authorize_url),
  });
  // Back from the IdP: ok means the re-login is proven, so carry straight on
  // into the enrolment; failed says so. The param is cleared at once so a
  // reload does not repeat it, and the ref keeps strict-mode's second effect
  // from spending the single-use proof twice. It waits for the status and
  // acts only for an account that re-authenticates at an IdP: the param is
  // just a URL, so a crafted ``?mfa_reauth=ok`` link must not send a local or
  // directory account's begin without its password, which would spend one of
  // its step-up attempts per click (the server still gates every begin).
  const [params, setParams] = useSearchParams();
  const reauthResult = params.get("mfa_reauth");
  const handled = useRef(false);
  const [reauthFailed, setReauthFailed] = useState(false);
  useEffect(() => {
    if (!reauthResult || handled.current || !status) return;
    handled.current = true;
    setParams(
      (p) => {
        p.delete("mfa_reauth");
        return p;
      },
      { replace: true },
    );
    if (status.enrol_requires !== "provider_reauth" || status.enabled) return;
    if (reauthResult === "ok") enrollBegin.mutate(undefined);
    else setReauthFailed(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reauthResult, status]);
  const signInTooOld =
    status?.enrol_requires === "recent_sign_in" && !status.enrol_sign_in_recent;
  // With no status there is no way to know which step-up applies, so the
  // button stays disabled rather than guessing "none" and sending a local
  // user's begin without a password.

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold">
            Two-factor authentication
          </span>
        </div>
        {!isLoading && status && (
          <span
            className={
              status.enabled
                ? "rounded bg-emerald-500/15 px-1.5 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300"
                : "rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground"
            }
          >
            {status.enabled ? "Enabled" : "Disabled"}
          </span>
        )}
      </div>

      <div className="space-y-3 p-4 text-sm">
        <p className="text-xs text-muted-foreground">
          Adds a one-time code from an authenticator app (Authy, 1Password,
          Google Authenticator, etc.) on top of your password. Recovery codes
          let you sign in if you lose access to your phone.
        </p>

        {isLoading ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
          </div>
        ) : !status?.enabled ? (
          <div className="space-y-2">
            {status?.enrolment_pending && (
              <p className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
                A previous enrolment was started but never verified. Starting
                again will replace it.
              </p>
            )}
            {signInTooOld && (
              <p className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
                Setting up two-factor authentication needs a recent sign-in.
                Sign out, sign in again through your identity provider, and
                start within {status?.enrol_sign_in_window_minutes} minutes.
              </p>
            )}
            {needsReauth && (
              <p className="text-xs text-muted-foreground">
                To set up two-factor authentication you will be sent to{" "}
                {providerName ? (
                  <strong>{providerName}</strong>
                ) : (
                  "your identity provider"
                )}{" "}
                to sign in again, then brought back here.
              </p>
            )}
            {reauthFailed && (
              <p className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                Re-authentication did not complete, so nothing was changed. Try
                again.
              </p>
            )}
            <button
              type="button"
              onClick={() => {
                setReauthFailed(false);
                if (needsReauth) reauth.mutate();
                else if (needsPassword) setAskPassword(true);
                else enrollBegin.mutate(undefined);
              }}
              disabled={
                !status ||
                enrollBegin.isPending ||
                reauth.isPending ||
                signInTooOld
              }
              className="rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {enrollBegin.isPending
                ? "Generating…"
                : needsReauth
                  ? reauth.isPending
                    ? "Redirecting…"
                    : `Re-authenticate${providerName ? ` with ${providerName}` : ""} to set up`
                  : "Set up authenticator"}
            </button>
            {reauth.isError && (
              <p className="text-xs text-destructive">
                {formatApiError(
                  reauth.error,
                  "Could not start re-authentication",
                )}
              </p>
            )}
            {!askPassword && enrollBegin.isError && (
              <p className="text-xs text-destructive">
                {formatApiError(enrollBegin.error, "Could not start set-up")}
              </p>
            )}
          </div>
        ) : (
          <div className="space-y-2 text-xs">
            <p className="text-muted-foreground">
              {status.recovery_codes_remaining} recovery code
              {status.recovery_codes_remaining === 1 ? "" : "s"} remaining.
              {status.recovery_codes_remaining <= 2 && (
                <span className="ml-1 text-amber-700 dark:text-amber-300">
                  Generate a fresh set before they run out.
                </span>
              )}
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setShowRegen(true)}
                className="rounded-md border bg-background px-3 py-1.5 hover:bg-muted"
              >
                Regenerate recovery codes…
              </button>
              <button
                type="button"
                onClick={() => setShowDisable(true)}
                className="rounded-md border border-destructive/40 bg-background px-3 py-1.5 text-destructive hover:bg-destructive/10"
              >
                Disable two-factor…
              </button>
            </div>
          </div>
        )}
      </div>

      {askPassword && (
        <EnrolPasswordModal
          providerName={
            status?.enrol_requires === "provider_password" ? providerName : null
          }
          pending={enrollBegin.isPending}
          error={
            enrollBegin.isError
              ? formatApiError(enrollBegin.error, "Could not start set-up")
              : ""
          }
          onClose={() => {
            setAskPassword(false);
            enrollBegin.reset();
          }}
          onSubmit={(password) => enrollBegin.mutate(password)}
        />
      )}
      {enrolling && (
        <EnrollModal
          data={enrolling}
          onClose={() => setEnrolling(null)}
          onVerified={() => {
            setEnrolling(null);
            qc.invalidateQueries({ queryKey: ["mfa-status"] });
          }}
        />
      )}
      {showDisable && (
        <DisableModal
          onClose={() => setShowDisable(false)}
          onDisabled={() => {
            setShowDisable(false);
            qc.invalidateQueries({ queryKey: ["mfa-status"] });
          }}
        />
      )}
      {showRegen && (
        <RegenerateRecoveryModal
          onClose={() => setShowRegen(false)}
          onRegenerated={() => {
            qc.invalidateQueries({ queryKey: ["mfa-status"] });
          }}
        />
      )}
    </div>
  );
}

function EnrollModal({
  data,
  onClose,
  onVerified,
}: {
  data: MfaEnrolBeginResponse;
  onClose: () => void;
  onVerified: () => void;
}) {
  const [acknowledgedRecovery, setAcknowledgedRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const qc = useQueryClient();

  const verify = useMutation({
    mutationFn: () => authApi.mfaEnrollVerify(code.trim()),
    onSuccess: () => onVerified(),
    onError: (err: unknown) => {
      setError(formatApiError(err, "Verification failed."));
      // #1354 — an expired enrolment is discarded server-side, so the
      // "previous enrolment" banner behind this modal is now stale.
      qc.invalidateQueries({ queryKey: ["mfa-status"] });
    },
  });

  return (
    <Modal title="Set up two-factor authentication" onClose={onClose}>
      <div className="space-y-4 text-sm">
        <ol className="list-decimal space-y-3 pl-5 text-xs">
          <li>
            <p>
              Scan this QR code with your authenticator app (Authy, 1Password,
              Google Authenticator, …) or copy the secret manually.
            </p>
            <div className="mt-2 flex flex-col items-center gap-2 sm:flex-row sm:items-start">
              {/* Rendered here, never fetched: the URI carries the TOTP
                  secret, and an image service would receive it (#1353). */}
              <QrCode
                value={data.otpauth_uri}
                size={160}
                title="Authenticator QR code"
                className="rounded border bg-white"
              />
              <div className="flex-1 space-y-1">
                <span className="block text-[11px] font-medium text-muted-foreground">
                  Manual secret
                </span>
                <div className="flex items-center gap-2 rounded border bg-muted/30 px-2 py-1">
                  <code className="flex-1 break-all font-mono text-[11px]">
                    {data.secret}
                  </code>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(data.secret)}
                    title="Copy"
                    className="text-muted-foreground hover:text-foreground"
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>
          </li>
          <li>
            <p>
              <strong>Save these recovery codes</strong> in a password manager
              or print them. Each code works once if you lose access to your
              authenticator. They cannot be retrieved again after this screen.
            </p>
            <div className="mt-2 grid grid-cols-2 gap-1 rounded border bg-muted/30 p-2 font-mono text-[11px]">
              {data.recovery_codes.map((c) => (
                <div key={c}>{c}</div>
              ))}
            </div>
            <button
              type="button"
              onClick={() => copyToClipboard(data.recovery_codes.join("\n"))}
              className="mt-1 inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
            >
              <Copy className="h-3 w-3" /> Copy all codes
            </button>
            <label className="mt-2 flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={acknowledgedRecovery}
                onChange={(e) => setAcknowledgedRecovery(e.target.checked)}
              />
              I have saved these recovery codes somewhere safe.
            </label>
          </li>
          <li>
            <p>Enter the 6-digit code from your authenticator to confirm:</p>
            <input
              autoFocus
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              value={code}
              onChange={(e) =>
                setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
              }
              placeholder="000000"
              className={`${inputCls} mt-1 text-center font-mono text-lg tracking-[0.3em]`}
            />
          </li>
        </ol>

        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => {
              setError(null);
              verify.mutate();
            }}
            disabled={
              !acknowledgedRecovery || code.length !== 6 || verify.isPending
            }
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {verify.isPending ? "Verifying…" : "Enable"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function PasswordCodePrompt({
  title,
  cta,
  destructive,
  onSubmit,
  onClose,
  isPending,
  error,
  successContent,
}: {
  title: string;
  cta: string;
  destructive?: boolean;
  onSubmit: (password: string, code: string) => void;
  onClose: () => void;
  isPending: boolean;
  error: string | null;
  successContent?: React.ReactNode;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");

  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-4 text-sm">
        {successContent ?? (
          <>
            <p className="text-xs text-muted-foreground">
              <Smartphone className="mr-1 inline h-3 w-3" />
              Confirm with a current authenticator code. Local accounts also
              enter their password; SSO accounts can leave it blank.
            </p>
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">
                Current password{" "}
                <span className="font-normal">(local accounts)</span>
              </label>
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={inputCls}
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">
                Authenticator code
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={code}
                onChange={(e) =>
                  setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                }
                placeholder="000000"
                className={`${inputCls} text-center font-mono text-lg tracking-[0.3em]`}
              />
            </div>
            {error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                {error}
              </div>
            )}
          </>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            {successContent ? "Done" : "Cancel"}
          </button>
          {!successContent && (
            <button
              type="button"
              onClick={() => onSubmit(password, code)}
              disabled={code.length !== 6 || isPending}
              className={
                destructive
                  ? "rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
                  : "rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              }
            >
              {isPending ? "Working…" : cta}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function DisableModal({
  onClose,
  onDisabled,
}: {
  onClose: () => void;
  onDisabled: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: ({ password, code }: { password: string; code: string }) =>
      authApi.mfaDisable(password, code),
    onSuccess: () => onDisabled(),
    onError: (err: unknown) => {
      setError(formatApiError(err, "Disable failed."));
    },
  });
  return (
    <PasswordCodePrompt
      title="Disable two-factor authentication"
      cta="Disable"
      destructive
      onSubmit={(password, code) => {
        setError(null);
        mut.mutate({ password, code });
      }}
      onClose={onClose}
      isPending={mut.isPending}
      error={error}
    />
  );
}

export function RegenerateRecoveryModal({
  onClose,
  onRegenerated,
}: {
  onClose: () => void;
  onRegenerated: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [newCodes, setNewCodes] = useState<string[] | null>(null);
  const mut = useMutation({
    mutationFn: ({ password, code }: { password: string; code: string }) =>
      authApi.mfaRegenerateRecoveryCodes(password, code),
    onSuccess: (data) => {
      setNewCodes(data.recovery_codes);
      onRegenerated();
    },
    onError: (err: unknown) => {
      setError(formatApiError(err, "Regeneration failed."));
    },
  });
  // #3222 — the old codes are revoked and the new ones are shown once, so
  // closing before copying them asks first.
  const codeValues = useMemo(() => newCodes ?? [], [newCodes]);
  const guard = useSecretCloseGuard({
    onClose,
    secrets: codeValues,
    noun: "set of recovery codes",
    active: newCodes !== null,
  });

  const successContent = newCodes ? (
    <div className="space-y-2" {...guard.copyProps}>
      <p className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
        Save these codes now. Each one works once. Old codes have been revoked.
      </p>
      <div className="grid grid-cols-2 gap-1 rounded border bg-muted/30 p-2 font-mono text-[11px]">
        {newCodes.map((c) => (
          <div key={c}>{c}</div>
        ))}
      </div>
      <button
        type="button"
        onClick={async () => {
          if (await copyToClipboard(newCodes.join("\n"))) guard.markTaken();
        }}
        className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
      >
        <Copy className="h-3 w-3" /> Copy all codes
      </button>
    </div>
  ) : undefined;

  return (
    <>
      <PasswordCodePrompt
        title="Regenerate recovery codes"
        cta="Generate new codes"
        onSubmit={(password, code) => {
          setError(null);
          mut.mutate({ password, code });
        }}
        onClose={guard.requestClose}
        isPending={mut.isPending}
        error={error}
        successContent={successContent}
      />
      {guard.confirm}
    </>
  );
}

/** #1241 — a local account confirms its password before an authenticator
 *  is attached to it, so a hijacked session cannot enrol its own. */
function EnrolPasswordModal({
  providerName,
  pending,
  error,
  onClose,
  onSubmit,
}: {
  providerName?: string | null;
  pending: boolean;
  error: string;
  onClose: () => void;
  onSubmit: (password: string) => void;
}) {
  const [password, setPassword] = useState("");
  return (
    <Modal title="Confirm your password" onClose={onClose}>
      <form
        className="space-y-3 text-sm"
        onSubmit={(e) => {
          e.preventDefault();
          if (password) onSubmit(password);
        }}
      >
        <p className="text-xs text-muted-foreground">
          {providerName
            ? `Enter your ${providerName} password to set up two-factor authentication. It is checked with ${providerName}, not stored here.`
            : "Enter your current password to set up two-factor authentication."}
        </p>
        <input
          type="password"
          autoComplete="current-password"
          autoFocus
          className={inputCls}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!password || pending}
            className="rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {pending ? "Checking…" : "Continue"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
