import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { authApi, type PublicAuthProvider } from "@/lib/api";
import { KeyRound, ShieldCheck } from "lucide-react";

import { BrandLogo } from "@/components/BrandLogo";
import { EnvironmentBanner } from "@/components/layout/EnvironmentBanner";
import {
  usePublicSettings,
  DEFAULT_APP_TITLE,
} from "@/hooks/usePublicSettings";

function humanizeError(code: string | null): string {
  if (!code) return "";
  if (code === "account_disabled")
    return "Your account is disabled. Contact an administrator.";
  if (code === "oidc_rejected")
    return "OIDC login rejected: your account could not be provisioned (group mapping, username collision, or auto-create disabled).";
  // Defensive: the backend allowlist (`_LOGIN_ERROR_REASONS`) only emits the
  // bare `oidc_rejected` above, but keep the per-reason rendering in case a
  // suffixed code is ever added to that set.
  if (code.startsWith("oidc_rejected_")) {
    const reason = code.slice("oidc_rejected_".length);
    if (reason === "no_group_mapping_match") {
      return "OIDC login rejected: your groups do not match any configured mapping.";
    }
    if (reason === "username_collision") {
      return "OIDC login rejected: a local user with the same username already exists.";
    }
    if (reason === "auto_create_disabled") {
      return "OIDC login rejected: auto-creating users is disabled for this provider.";
    }
    return `OIDC login rejected (${reason}).`;
  }
  if (code === "oidc_exchange_failed")
    return "OIDC token exchange failed. Check provider configuration.";
  if (
    code === "oidc_state_missing" ||
    code === "oidc_state_invalid" ||
    code === "oidc_state_mismatch"
  )
    return "OIDC flow state was invalid or expired. Please try again.";
  if (code === "oidc_no_code")
    return "OIDC provider returned no authorization code.";
  if (code === "oidc_discovery_failed")
    return "OIDC discovery failed — the provider's metadata URL is unreachable.";
  if (code === "oidc_misconfigured")
    return "OIDC provider is misconfigured. Contact an administrator.";
  if (code.startsWith("oidc_idp_"))
    return `Identity provider returned: ${code.slice(9)}`;
  if (code === "saml_requires_https")
    return "SAML login requires HTTPS. The identity provider posts the assertion back cross-site, and browsers only carry the flow cookie across that POST over a secure connection — serve SpatiumDDI over TLS and set the external URL in Settings to its https:// address.";
  if (
    code === "saml_state_missing" ||
    code === "saml_state_invalid" ||
    code === "saml_state_mismatch"
  )
    return "SAML flow state was invalid or expired. Please try again.";
  if (code === "saml_assertion_rejected")
    return "The SAML assertion was rejected. Check the SP/IdP certificate and entity ID configuration.";
  if (code === "saml_rejected")
    return "SAML login rejected: your account could not be provisioned (group mapping, username collision, or auto-create disabled).";
  if (code === "saml_build_failed")
    return "Could not build the SAML authentication request. Check provider configuration.";
  if (code === "saml_misconfigured")
    return "SAML provider is misconfigured. Contact an administrator.";
  return "Login failed.";
}

/** Two-step state machine — start on the password form, switch to the
 * TOTP form when /auth/login returns ``mfa_required=true`` with a
 * challenge token. The challenge is short-lived (5 min) so we don't
 * persist it; if the operator backgrounds the tab too long they
 * re-enter their password. */
type Step =
  | { kind: "password" }
  | { kind: "mfa"; challengeToken: string; forcePasswordChange: boolean };

export function LoginPage() {
  const { login, completeMfa } = useAuth();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialError = humanizeError(searchParams.get("error"));

  const [step, setStep] = useState<Step>({ kind: "password" });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(initialError);
  const [loading, setLoading] = useState(false);
  const [providers, setProviders] = useState<PublicAuthProvider[]>([]);

  // MFA prompt state.
  const [mfaMode, setMfaMode] = useState<"code" | "recovery">("code");
  const [mfaCode, setMfaCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");

  // Branding (#885 / #886 / #887 / #888) — served unauthenticated so it can
  // render here, before any session exists.
  const { settings, settled: brandingSettled } = usePublicSettings();
  const appTitle = settings.app_title.trim() || DEFAULT_APP_TITLE;
  const loginBanner = settings.login_banner;
  const bannerText = loginBanner.text.trim();
  const showBanner = loginBanner.enabled && !!bannerText;
  const [acknowledged, setAcknowledged] = useState(false);
  // The acknowledgement gate is a consent affordance, not an auth control:
  // it exists so the operator can say the notice was displayed and accepted.
  // The API never sees it, and deliberately so — a client-side checkbox
  // would be security theatre if we pretended otherwise.
  const ackRequired = showBanner && loginBanner.require_ack;
  // Hold the sign-in affordances until the branding payload has settled.
  // Until then the fallback says "no banner", so an autofilled form
  // submitted on the first keypress would skip a notice the operator
  // configured as mandatory. Gated on ``settled`` rather than ``ready``
  // deliberately: a failing /settings/public must still let people log in.
  const ackSatisfied = brandingSettled && (!ackRequired || acknowledged);

  useEffect(() => {
    authApi
      .publicProviders()
      .then(setProviders)
      .catch(() => setProviders([]));
  }, []);

  function dismissErrorBanner() {
    setError("");
    if (searchParams.get("error")) {
      searchParams.delete("error");
      setSearchParams(searchParams, { replace: true });
    }
  }

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const resp = await login(username, password);
      if (resp.mfa_required && resp.mfa_token) {
        setStep({
          kind: "mfa",
          challengeToken: resp.mfa_token,
          forcePasswordChange: resp.force_password_change,
        });
        setMfaCode("");
        setRecoveryCode("");
        setMfaMode("code");
      } else if (resp.force_password_change) {
        navigate("/change-password");
      } else {
        navigate("/dashboard");
      }
    } catch {
      setError("Invalid username or password.");
    } finally {
      setLoading(false);
    }
  }

  async function handleMfaSubmit(e: FormEvent) {
    e.preventDefault();
    if (step.kind !== "mfa") return;
    setError("");
    setLoading(true);
    try {
      const body =
        mfaMode === "code"
          ? { code: mfaCode.trim() }
          : { recovery_code: recoveryCode.trim() };
      const resp = await completeMfa(step.challengeToken, body);
      if (resp.force_password_change || step.forcePasswordChange) {
        navigate("/change-password");
      } else {
        navigate("/dashboard");
      }
    } catch (err: unknown) {
      // Common cases: bad code, expired challenge. Either way: nudge
      // the operator back to the password step rather than letting
      // them guess endlessly.
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      const expired =
        typeof detail === "string" &&
        /expired|invalid mfa challenge/i.test(detail);
      if (expired) {
        setError("MFA challenge expired — please sign in again.");
        setStep({ kind: "password" });
      } else {
        setError(typeof detail === "string" ? detail : "Invalid MFA code.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      {/* Which environment this is matters most at the sign-in prompt —
          it is the last point before someone starts making changes. */}
      <EnvironmentBanner edge="top" />
      <div className="flex flex-1 items-center justify-center p-4">
        <div className="w-full max-w-sm space-y-6 rounded-lg border bg-card p-8 shadow-sm">
          <div className="space-y-2 text-center">
            <BrandLogo className="mx-auto h-10 w-10" />
            <h1 className="text-2xl font-bold tracking-tight">{appTitle}</h1>
            <p className="text-sm text-muted-foreground">
              {step.kind === "mfa"
                ? "Two-factor verification"
                : "Sign in to your account"}
            </p>
          </div>

          {showBanner && (
            <div className="max-h-64 overflow-y-auto rounded-md border bg-muted/40 px-3 py-2 text-xs">
              {loginBanner.title.trim() && (
                <div className="mb-1 font-semibold uppercase tracking-wide">
                  {loginBanner.title.trim()}
                </div>
              )}
              {/* Rendered as plain text with newlines preserved — the field
                  is operator-authored but shown to anonymous visitors, so it
                  never becomes markup. */}
              <p className="whitespace-pre-wrap text-muted-foreground">
                {bannerText}
              </p>
              {ackRequired && (
                <label className="mt-2 flex items-start gap-2 font-medium text-foreground">
                  <input
                    type="checkbox"
                    checked={acknowledged}
                    onChange={(e) => setAcknowledged(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>I acknowledge and accept these terms</span>
                </label>
              )}
            </div>
          )}

          {error && (
            <div className="flex items-start justify-between gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              <span>{error}</span>
              <button
                onClick={dismissErrorBanner}
                className="font-semibold hover:underline"
                type="button"
              >
                ×
              </button>
            </div>
          )}

          {step.kind === "password" ? (
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="username" className="text-sm font-medium">
                  Username
                </label>
                <input
                  id="username"
                  type="text"
                  autoComplete="username"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <button
                type="submit"
                disabled={loading || !ackSatisfied}
                className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {loading ? "Signing in…" : "Sign in"}
              </button>
            </form>
          ) : (
            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <p className="text-xs text-muted-foreground">
                {mfaMode === "code"
                  ? "Enter the 6-digit code from your authenticator app."
                  : "Enter one of your recovery codes (e.g. ABCD-EF12). Each code works once."}
              </p>
              {mfaMode === "code" ? (
                <div className="space-y-2">
                  <label htmlFor="mfa-code" className="text-sm font-medium">
                    Authenticator code
                  </label>
                  <input
                    id="mfa-code"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    autoComplete="one-time-code"
                    required
                    autoFocus
                    value={mfaCode}
                    onChange={(e) =>
                      setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                    }
                    className="w-full rounded-md border bg-background px-3 py-2 text-center font-mono text-lg tracking-[0.3em] focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="000000"
                    maxLength={6}
                  />
                </div>
              ) : (
                <div className="space-y-2">
                  <label
                    htmlFor="recovery-code"
                    className="text-sm font-medium"
                  >
                    Recovery code
                  </label>
                  <input
                    id="recovery-code"
                    type="text"
                    autoComplete="off"
                    required
                    autoFocus
                    value={recoveryCode}
                    onChange={(e) =>
                      setRecoveryCode(e.target.value.toUpperCase())
                    }
                    className="w-full rounded-md border bg-background px-3 py-2 text-center font-mono text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                    placeholder="ABCD-EF12"
                  />
                </div>
              )}
              <button
                type="submit"
                disabled={
                  loading ||
                  (mfaMode === "code"
                    ? mfaCode.length !== 6
                    : recoveryCode.trim().length === 0)
                }
                className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {loading ? "Verifying…" : "Verify"}
              </button>
              <div className="flex items-center justify-between text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setMfaMode((m) => (m === "code" ? "recovery" : "code"));
                    setError("");
                  }}
                  className="text-muted-foreground hover:text-foreground hover:underline"
                >
                  {mfaMode === "code"
                    ? "Use a recovery code instead"
                    : "Use my authenticator code"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStep({ kind: "password" });
                    setError("");
                    setPassword("");
                  }}
                  className="text-muted-foreground hover:text-foreground hover:underline"
                >
                  Sign out
                </button>
              </div>
            </form>
          )}

          {step.kind === "password" && providers.length > 0 && (
            <>
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">or</span>
                </div>
              </div>
              <div className="space-y-2">
                {providers.map((p) => (
                  <a
                    key={p.id}
                    // The SSO buttons honour the acknowledgement gate too —
                    // otherwise the notice is trivially skipped by signing in
                    // through the identity provider instead.
                    href={
                      ackSatisfied
                        ? `/api/v1/auth/${p.id}/authorize`
                        : undefined
                    }
                    aria-disabled={!ackSatisfied}
                    className={
                      ackSatisfied
                        ? "flex w-full items-center justify-center gap-2 rounded-md border bg-background px-4 py-2 text-sm font-medium transition-colors hover:bg-accent"
                        : "pointer-events-none flex w-full items-center justify-center gap-2 rounded-md border bg-background px-4 py-2 text-sm font-medium opacity-50"
                    }
                  >
                    {p.type === "oidc" ? (
                      <KeyRound className="h-4 w-4" />
                    ) : (
                      <ShieldCheck className="h-4 w-4" />
                    )}
                    Sign in with {p.name}
                  </a>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
      <EnvironmentBanner edge="bottom" />
    </div>
  );
}
