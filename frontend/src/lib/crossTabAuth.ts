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
 *
 * The channel adds no reach beyond what the origin already had: any script
 * running on this origin could already read the token out of this module, or
 * call /auth/refresh itself with the cookie the browser attaches. The HttpOnly
 * refresh cookie is never on the channel (script cannot read it). Messages are
 * still shape-checked (a well-formed JWT with ``sub`` + ``exp``, typed
 * fields, not expired) so a stray or garbled message is never adopted.
 *
 * Adoption rules:
 *  - a tab holding a token moves to a broadcast token for the same user;
 *  - a tab holding NO token (signed out, sitting on /login) never adopts one
 *    from a broadcast, and its own 401-path refresh does not adopt one either
 *    - it refreshes for itself as before. Only the boot refresh (a reload) may
 *    take a token another tab already minted, which is exactly what its own
 *    refresh would have returned from the shared cookie;
 *  - a sign-out heard while a refresh is in flight voids that refresh.
 *
 * What is NOT broadcast, deliberately:
 *  - the idle sign-out (IdleLogout). Interaction is already shared across
 *    tabs (lib/activity.ts, localStorage) and the server refuses an idle
 *    session on its own (core/session_idle.py), so every tab of an idle
 *    browser times out together; a tab that idles out on its own (storage
 *    blocked) only means the operator is not using THAT tab, while the
 *    session the others report activity for is still live server-side.
 *  - ``forceLogin`` after a failed refresh. The failure may be a network
 *    error or a 5xx, and signing every tab out on a transient fault is worse
 *    than each tab finding a genuinely dead session on its next request.
 *
 * Every refresh is bounded (``REFRESH_TIMEOUT_MS``) and aborted on timeout,
 * so a hung request cannot hold the browser-wide lock and stall every tab.
 * Web Locks releases a lock when its callback settles or its tab closes.
 */
import {
  getAccessToken,
  setAccessToken,
  setMustChangePassword,
} from "@/lib/authToken";

export const REFRESH_LOCK = "spatium-refresh";
export const AUTH_CHANNEL = "spatium-auth";
/** Upper bound on one /auth/refresh while holding the browser-wide lock. */
export const REFRESH_TIMEOUT_MS = 30_000;
/** A token this close to expiry is not worth adopting. */
const EXPIRY_SKEW_MS = 5_000;
/** Far above any real access token; guards against absurd messages. */
const MAX_TOKEN_LENGTH = 8192;
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

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
// Bumped by every sign-out sent or heard; a refresh that spans one is void.
let logoutEpoch = 0;

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

/** A compact JWT carrying ``sub`` + ``exp`` (unverified: shape only). */
function wellFormedJwt(token: unknown): token is string {
  if (typeof token !== "string") return false;
  if (token.length > MAX_TOKEN_LENGTH || !JWT_SHAPE.test(token)) return false;
  const { sub, exp } = claims(token);
  return typeof sub === "string" && sub !== "" && typeof exp === "number";
}

/** Same user, or at least not demonstrably a different one. */
function sameUser(incoming: string): boolean {
  const mine = claims(getAccessToken()).sub;
  if (mine === undefined) return true; // nothing to compare against (booting)
  return claims(incoming).sub === mine;
}

function handleMessage(data: unknown): void {
  if (!data || typeof data !== "object") return;
  const msg = data as Record<string, unknown>;
  if (msg.type === "logout") {
    lastKnown = null;
    logoutEpoch += 1;
    if (getAccessToken()) {
      setAccessToken(null);
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return;
  }
  if (msg.type !== "token") return;
  const { token, expiresAt, mustChange } = msg;
  if (
    !wellFormedJwt(token) ||
    typeof expiresAt !== "number" ||
    !Number.isFinite(expiresAt) ||
    typeof mustChange !== "boolean"
  ) {
    return;
  }
  // Trust the token's own exp over the sender's figure, whichever is sooner.
  const effective = Math.min(expiresAt, expiryMs(token));
  if (effective <= Date.now() + EXPIRY_SKEW_MS || !sameUser(token)) return;
  lastKnown = { token, expiresAt: effective, mustChange };
  // A tab holding a token moves to the fresh one right away (its old one is
  // about to be, or already is, rotated away), including a forced password
  // change: the route guard sends it to /change-password like the tab that
  // refreshed. A tab with none (signed out, or booting) only remembers it,
  // for its boot refresh to adopt.
  if (getAccessToken()) {
    setAccessToken(token);
    setMustChangePassword(mustChange);
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
  logoutEpoch += 1;
  post({ type: "logout" });
}

function adoptable(staleToken: string | null): Known | null {
  if (!lastKnown) return null;
  if (lastKnown.token === staleToken) return null;
  if (lastKnown.expiresAt <= Date.now() + EXPIRY_SKEW_MS) return null;
  if (!sameUser(lastKnown.token)) return null;
  return lastKnown;
}

/** Thrown when a sign-out arrives while a refresh is in flight. */
export class SignedOutDuringRefresh extends Error {
  constructor() {
    super("signed out in another tab during refresh");
    this.name = "SignedOutDuringRefresh";
  }
}

export type SharedRefreshOptions = {
  /** May adopt another tab's token while this tab holds none. Only the
   *  boot refresh sets this: a reload would get that very token from the
   *  shared cookie anyway. */
  allowAdoptWithoutToken?: boolean;
  /** Override ``REFRESH_TIMEOUT_MS`` (tests). */
  timeoutMs?: number;
};

/** Run ``doRefresh`` with an abort signal that fires after ``ms``. */
async function bounded(
  doRefresh: (signal: AbortSignal) => Promise<RefreshResult>,
  ms: number,
): Promise<RefreshResult> {
  const ctrl = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      ctrl.abort();
      reject(new Error(`/auth/refresh timed out after ${ms} ms`));
    }, ms);
  });
  try {
    return await Promise.race([doRefresh(ctrl.signal), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Refresh the session once for the whole browser.
 *
 * ``doRefresh`` performs the real POST /auth/refresh and should honour the
 * abort signal. ``staleToken`` is the access token the caller just found
 * rejected (null when it held none). Rejects on failure, timeout, or a
 * sign-out heard meanwhile; the lock is released in every case.
 */
export async function sharedRefresh(
  doRefresh: (signal: AbortSignal) => Promise<RefreshResult>,
  staleToken: string | null,
  opts: SharedRefreshOptions = {},
): Promise<RefreshResult> {
  initCrossTabAuth();
  const epoch = logoutEpoch;
  const mayAdopt = staleToken !== null || !!opts.allowAdoptWithoutToken;

  const run = async (): Promise<RefreshResult> => {
    if (logoutEpoch !== epoch) throw new SignedOutDuringRefresh();
    const fresh = mayAdopt ? adoptable(staleToken) : null;
    if (fresh) {
      return {
        access_token: fresh.token,
        force_password_change: fresh.mustChange,
      };
    }
    const res = await bounded(doRefresh, opts.timeoutMs ?? REFRESH_TIMEOUT_MS);
    if (logoutEpoch !== epoch) throw new SignedOutDuringRefresh();
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
  logoutEpoch = 0;
}
