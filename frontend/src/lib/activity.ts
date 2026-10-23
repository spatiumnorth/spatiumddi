/**
 * When the operator last touched the console — the clock the Session
 * Timeout runs on.
 *
 * The console polls in the background (dashboards, status chips), so
 * "a request reached the server" does not mean anyone is at the keyboard.
 * This module records real interaction (pointer, keyboard, wheel, touch,
 * scroll) and every API request reports how long ago that was in
 * ``X-Spatium-Idle-Seconds``. The server records the session's activity at
 * that time rather than at the request, so an open page nobody touches
 * still runs out (``backend/app/core/session_idle.py``).
 *
 * Shared across tabs through localStorage, so working in one tab keeps the
 * others signed in. Storage can be unavailable (private window, blocked site
 * data); every access is guarded and the in-memory value still works for
 * the tab it lives in.
 */

export const IDLE_HEADER = "X-Spatium-Idle-Seconds";

const STORAGE_KEY = "spatium.lastInteractionAt";
// Interaction events fire constantly (mousemove); write storage at most this
// often. A second is far below any timeout granularity.
const WRITE_THROTTLE_MS = 1000;
const EVENTS = [
  "pointerdown",
  "mousemove",
  "keydown",
  "wheel",
  "touchstart",
  "scroll",
] as const;

// A page load is the operator's doing.
let lastInteraction = Date.now();
let lastWrite = 0;
// The interaction time the most recent API request reported to the server.
let lastReported = 0;
let tracking = false;

function readShared(): number {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const n = raw ? Number(raw) : NaN;
    return Number.isFinite(n) ? n : 0;
  } catch {
    // Storage blocked: this tab's own clock is all there is.
    return 0;
  }
}

/** Record that the operator interacted with the page just now. */
export function noteInteraction(now: number = Date.now()): void {
  lastInteraction = now;
  if (now >= lastWrite && now - lastWrite < WRITE_THROTTLE_MS) return;
  lastWrite = now;
  try {
    window.localStorage.setItem(STORAGE_KEY, String(now));
  } catch {
    // Storage blocked: the other tabs just don't see this one's activity.
  }
}

/** The most recent interaction in this tab or any other. */
export function lastInteractionAt(): number {
  // A time later than now (the clock moved backwards) is ignored rather
  // than read as "active right now", which would keep the operator signed
  // in until the clock caught up.
  const now = Date.now();
  const candidates = [lastInteraction, readShared()].filter((t) => t <= now);
  return candidates.length ? Math.max(...candidates) : now;
}

/** Seconds since the operator last interacted, in this tab or any other. */
export function idleSeconds(now: number = Date.now()): number {
  return Math.max(0, Math.floor((now - lastInteractionAt()) / 1000));
}

/** The header every API request carries; also notes what it reported. */
export function idleHeader(): Record<string, string> {
  const now = Date.now();
  lastReported = Math.max(lastReported, lastInteractionAt());
  return { [IDLE_HEADER]: String(idleSeconds(now)) };
}

/** Milliseconds of interaction the server has not been told about yet. */
export function unreportedInteractionMs(): number {
  return Math.max(0, lastInteractionAt() - lastReported);
}

/** Start listening for interaction. Idempotent. */
export function startActivityTracking(): void {
  if (tracking || typeof window === "undefined") return;
  tracking = true;
  const onActivity = () => noteInteraction();
  for (const ev of EVENTS) {
    window.addEventListener(ev, onActivity, { capture: true, passive: true });
  }
}

/** When the warning appears and when the console signs out, in seconds of
 *  idle time. ``null`` when the Session Timeout is disabled. */
export function idleSchedule(
  timeoutMinutes: number | undefined,
  warningMinutes: number | undefined,
): { warnAt: number | null; logoutAt: number } | null {
  const timeout = Math.floor((timeoutMinutes ?? 0) * 60);
  if (timeout <= 0) return null;
  const warn = Math.floor((warningMinutes ?? 0) * 60);
  if (warn <= 0) return { warnAt: null, logoutAt: timeout };
  // A warning as long as the timeout itself would be on screen from the
  // first idle second; cap it at half the timeout.
  return { warnAt: timeout - Math.min(warn, timeout / 2), logoutAt: timeout };
}
