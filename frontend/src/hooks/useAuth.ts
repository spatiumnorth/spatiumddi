import { useCallback, useEffect, useSyncExternalStore } from "react";
import { authApi, type LoginResponse } from "@/lib/api";
import {
  broadcastLogout,
  initCrossTabAuth,
  sharedRefresh,
} from "@/lib/crossTabAuth";
import {
  getAccessToken,
  getAuthSnapshot,
  markBooted,
  setAccessToken,
  setMustChangePassword,
  subscribe,
} from "@/lib/authToken";

// SECURITY (#484 / #400 L1): the JWT access token lives ONLY in JS memory
// (lib/authToken.ts), never localStorage — so an XSS foothold can't exfiltrate
// a durable credential. The long-lived refresh token is an HttpOnly +
// Secure + SameSite=Strict cookie the backend sets on /auth/login and rotates
// on /auth/refresh; it's invisible to script entirely. On a full page reload
// the in-memory access token is gone, so the app runs one silent
// /auth/refresh at boot (the cookie rides that request) to restore the
// session — see ``bootstrapAuth`` below.

// Module-level so the boot-time refresh fires exactly once no matter how many
// components mount useAuth(). The promise is memoised; ``markBooted`` flips
// the shared ``booted`` flag when it settles either way.
//
// KNOWN TRADEOFF (multi-tab reload): /auth/refresh rotates + revokes the old
// session server-side. Because the access token is now memory-only, a reload
// always boot-refreshes, so reloading two tabs at once makes both present the
// same cookie — the loser's token is already revoked and that tab is bounced
// to /login (fail-closed: a spurious re-login, never a privilege leak). The
// pre-#484 localStorage flow avoided this only by not refreshing on reload at
// all. A proper fix (cross-tab Web Locks / a short rotation grace window) is
// tracked separately; single-tab and staggered-tab use is unaffected.
let bootstrapPromise: Promise<void> | null = null;

function bootstrapAuth(): Promise<void> {
  if (bootstrapPromise) return bootstrapPromise;
  // Shared across tabs (#2960): reloading several tabs makes one refresh,
  // which supersedes the tradeoff above wherever Web Locks + BroadcastChannel
  // exist. A boot refresh may adopt a token another tab already minted: it is
  // what this tab's own refresh would return from the shared cookie.
  bootstrapPromise = sharedRefresh((signal) => authApi.refresh(signal), null, {
    allowAdoptWithoutToken: true,
  })
    .then((resp) => {
      // Only adopt the refreshed token if nothing else set one meanwhile.
      // An explicit login() racing this boot refresh always wins — its token
      // is at least as fresh, and we must never clobber it (nor, in the
      // failure branch below, null it out).
      if (resp.access_token && !getAccessToken()) {
        setAccessToken(resp.access_token);
        setMustChangePassword(!!resp.force_password_change);
      }
    })
    .catch(() => {
      // ANY refresh failure — a missing/expired cookie (401) but also a
      // network error or 5xx — just means "couldn't restore a session on
      // boot", so we stay logged out. Leave the store untouched (it starts
      // null; a concurrent login must not be wiped). A protected route
      // redirects to /login once ``booted`` is true; a real request the user
      // then makes re-drives auth through the 401 interceptor.
    })
    .finally(() => {
      markBooted();
    });
  return bootstrapPromise;
}

export function useAuth() {
  const snapshot = useSyncExternalStore(subscribe, getAuthSnapshot);
  const isAuthenticated = !!snapshot.accessToken;
  const mustChangePassword = snapshot.mustChangePassword;

  // Fire the one-shot boot refresh. Skip it if we already have a token in
  // memory (a fresh login this tab) — there's nothing to restore.
  useEffect(() => {
    // Hear sign-outs + rotated tokens from the other tabs (#2960).
    initCrossTabAuth();
    if (getAccessToken()) {
      markBooted();
      return;
    }
    void bootstrapAuth();
  }, []);

  /** Run the password step. Returns the raw LoginResponse so the caller
   * can inspect ``mfa_required`` and route to the TOTP prompt without
   * establishing a session on a half-completed login. */
  const login = useCallback(
    async (username: string, password: string): Promise<LoginResponse> => {
      const resp = await authApi.login(username, password);
      if (!resp.mfa_required && resp.access_token) {
        setAccessToken(resp.access_token);
        setMustChangePassword(!!resp.force_password_change);
        markBooted();
      }
      return resp;
    },
    [],
  );

  /** Complete a TOTP-gated login. ``code`` is the authenticator's
   * 6-digit number; ``recovery_code`` is the one-time recovery code.
   * Submit one or the other, not both. */
  const completeMfa = useCallback(
    async (
      mfa_token: string,
      body: { code?: string; recovery_code?: string },
    ): Promise<LoginResponse> => {
      const resp = await authApi.loginMfa(mfa_token, body);
      if (resp.access_token) {
        setAccessToken(resp.access_token);
        setMustChangePassword(!!resp.force_password_change);
        markBooted();
      }
      return resp;
    },
    [],
  );

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setAccessToken(null);
      // Every other tab signs out too (#2960).
      broadcastLogout();
    }
  }, []);

  return {
    isAuthenticated,
    mustChangePassword,
    // True until the boot-time silent refresh resolves. A protected route
    // renders a loader while this is true so a real session isn't mistaken
    // for a logged-out one on reload.
    bootstrapping: !snapshot.booted,
    login,
    completeMfa,
    logout,
  };
}
