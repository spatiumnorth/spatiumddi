import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  markBooted,
  setAccessToken,
  setMustChangePassword,
} from "@/lib/authToken";

/**
 * Landing route that consumes the access token delivered by the OIDC/SAML
 * callback as a URL hash fragment (#access_token=…&force_password_change=…).
 *
 * Hash fragments are never sent to the server, so the token stays on the
 * client. We lift the short-lived access token into JS memory (same store the
 * password flow uses) and redirect into the app. The refresh token is NOT in
 * the fragment — the backend set it as an HttpOnly cookie on the redirect
 * response, invisible to script (#484).
 */
export function LoginCallbackPage() {
  const navigate = useNavigate();

  useEffect(() => {
    const hash = window.location.hash.replace(/^#/, "");
    const params = new URLSearchParams(hash);
    const access = params.get("access_token");
    const forcePwd = params.get("force_password_change") === "true";

    if (!access) {
      navigate("/login?error=oidc_no_tokens", { replace: true });
      return;
    }

    setAccessToken(access);
    setMustChangePassword(forcePwd);
    markBooted();

    // Clear the hash so the token doesn't linger in the URL bar.
    window.history.replaceState(
      null,
      "",
      window.location.pathname + window.location.search,
    );

    navigate(forcePwd ? "/change-password" : "/dashboard", { replace: true });
  }, [navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <p className="text-sm text-muted-foreground">Finishing sign-in…</p>
    </div>
  );
}
