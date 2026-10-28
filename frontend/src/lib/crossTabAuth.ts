/**
 * One refresh for every tab of a browser (#2960).
 *
 * /auth/refresh rotates the session, so two tabs each refreshing on their own
 * kept killing each other's access token: A rotates, B's token dies once the
 * server's rotation grace (#2941) lapses, B rotates, A's dies, and so on. Now
 * a single tab refreshes at a time (Web Locks, ``spatium-refresh``) and
 * broadcasts the new access token + expiry to the others over a
 * BroadcastChannel; a tab that wins the lock after someone else already
 * refreshed adopts that token instead of rotating again.
 *
 * SECURITY: the token still lives only in JS memory (lib/authToken.ts). The
 * BroadcastChannel is same-origin by specification, so the token never
 * reaches another origin; it is not written to localStorage/sessionStorage. A
 * message for a different user (JWT ``sub``) is ignored. Where Web Locks or
 * BroadcastChannel is missing we fall back to the pre-#2960 behaviour: each
 * tab refreshes on its own.
 */
import {
  getAccessToken,
  setAccessToken,
  setMustChangePassword,
} from "@/lib/authToken";

export const REFRESH_LOCK = "spatium-refresh";
export const AUTH_CHANNEL = "spatium-auth";

export type RefreshResult = {
  access_token: string;
  force_password_change?: boolean;
};

type Message =
  | {
      type: "token";
      token: string;
      expiresAt: number;
      mustChange: boolean;
    }
  | { type: "logout" };

type Known = { token: string; expiresAt: number; mustChange: boolean };

let channel: BroadcastChannel | null = null;
let channelTried = false;
let lastKnown: Known | null = null;

/** Decode the unverified payload of a JWT (identity + expiry hints only; the
 *  server remains the authority on whether the token is valid). */
function claims(token: string | null): { sub?: string; exp?: number } {
  if (!token) return {};
  try {
    const part = token.split(".")[1];
    if (!part) return {};
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const c = JSON.parse(json) as { sub?: unknown; exp?: unknown };
    return {
      sub: typeof c.sub === "string" ? c.sub : undefined,
      exp: typeof c.exp === "number" ? c.exp : undefined,
    };
  } catch {
    return {};
  }
}

function expiryMs(token: string): number {
  const { exp } = claims(token);
  // No readable exp: treat as short-lived rather than trusting it forever.
  return exp ? exp * 1000 : Date.now() + 60_000;
}

/** Same user, or at least not demonstrably a different one. */
function sameUser(incoming: string): boolean {
  const mine = claims(getAccessToken()).sub;
  if (mine === undefined) return true; // nothing to compare against (booting)
  return claims(incoming).sub === mine;
}

function handleMessage(data: unknown): void {
  if (!data || typeof data !== "object") return;
  const msg = data as Partial<Message>;
  if (msg.type === "logout") {
    lastKnown = null;
    if (getAccessToken()) {
      setAccessToken(null);
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return;
  }
  if (msg.type !== "token") return;
  const { token, expiresAt, mustChange } = msg as Extract<
    Message,
    { type: "token" }
  >;
  if (typeof token !== "string" || typeof expiresAt !== "number") return;
  if (expiresAt <= Date.now() || !sameUser(token)) return;
  lastKnown = { token, expiresAt, mustChange: !!mustChange };
  // A tab holding a token moves to the fresh one right away (its old one is
  // about to be, or already is, rotated away). A tab with none (logged out,
  // or booting) only remembers it for its own refresh to adopt.
  if (getAccessToken()) {
    setAccessToken(token);
    setMustChangePassword(!!mustChange);
  }
}

function getChannel(): BroadcastChannel | null {
  if (channelTried) return channel;
  channelTried = true;
  try {
    if (typeof BroadcastChannel === "undefined") return null;
    channel = new BroadcastChannel(AUTH_CHANNEL);
    channel.onmessage = (ev: MessageEvent) => handleMessage(ev.data);
  } catch {
    channel = null;
  }
  return channel;
}

function post(msg: Message): void {
  try {
    getChannel()?.postMessage(msg);
  } catch {
    // Channel closed/unusable: other tabs just refresh for themselves.
  }
}

/** Start listening (idempotent). Called at app start so a tab that never
 *  refreshes itself still hears sign-outs and rotated tokens. */
export function initCrossTabAuth(): void {
  getChannel();
}

/** Tell every other tab to sign out. */
export function broadcastLogout(): void {
  lastKnown = null;
  post({ type: "logout" });
}

function adoptable(staleToken: string | null): Known | null {
  if (!lastKnown) return null;
  if (lastKnown.token === staleToken) return null;
  if (lastKnown.expiresAt <= Date.now()) return null;
  if (!sameUser(lastKnown.token)) return null;
  return lastKnown;
}

/**
 * Refresh the session once for the whole browser.
 *
 * ``doRefresh`` performs the real POST /auth/refresh. ``staleToken`` is the
 * access token the caller just found rejected (null at boot).
 */
export async function sharedRefresh(
  doRefresh: () => Promise<RefreshResult>,
  staleToken: string | null,
): Promise<RefreshResult> {
  initCrossTabAuth();

  const run = async (): Promise<RefreshResult> => {
    const fresh = adoptable(staleToken);
    if (fresh) {
      return {
        access_token: fresh.token,
        force_password_change: fresh.mustChange,
      };
    }
    const res = await doRefresh();
    if (res.access_token) {
      const expiresAt = expiryMs(res.access_token);
      lastKnown = {
        token: res.access_token,
        expiresAt,
        mustChange: !!res.force_password_change,
      };
      post({
        type: "token",
        token: res.access_token,
        expiresAt,
        mustChange: !!res.force_password_change,
      });
    }
    return res;
  };

  const locks =
    typeof navigator !== "undefined"
      ? (navigator as Navigator & { locks?: LockManager }).locks
      : undefined;
  if (!locks || typeof locks.request !== "function") return run();
  return await locks.request(REFRESH_LOCK, run);
}

/** Test seam: forget module state so a fresh "tab" can be simulated. */
export function _resetCrossTabAuthForTests(): void {
  try {
    channel?.close();
  } catch {
    // ignore
  }
  channel = null;
  channelTried = false;
  lastKnown = null;
}
