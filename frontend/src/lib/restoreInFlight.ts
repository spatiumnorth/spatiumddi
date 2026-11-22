/** sessionStorage note left by a console restore. A restore revokes every
 *  session, so the browser's next call 401s and the page jumps to sign-in;
 *  the sign-in page reads this to say why (#4676).
 *
 *  The note is a timestamp, read WITHOUT consuming it. The 401 handler sets
 *  `window.location.href = "/login"` while the old page's protected-route
 *  redirect may already have mounted a LoginPage; a read that removed the key
 *  would let that doomed mount eat the notice before the real /login load.
 *  So the note ends three ways instead: a successful sign-in clears it, a
 *  restore that did not run clears it, and it expires after RESTORE_NOTE_TTL_MS
 *  so a stale note cannot haunt a later sign-in. Reloading the sign-in page
 *  keeps the notice for the same reason. */
export const RESTORE_IN_FLIGHT_KEY = "spatium.restoreInFlight";

export const RESTORE_NOTE_TTL_MS = 10 * 60 * 1000;

export function markRestoreInFlight(): void {
  try {
    sessionStorage.setItem(RESTORE_IN_FLIGHT_KEY, String(Date.now()));
  } catch {
    // storage blocked: the sign-in page just loses its explanation.
  }
}

/** True while a restore note is fresh. Does not consume it. */
export function hasRestoreInFlight(): boolean {
  try {
    const raw = sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY);
    if (raw === null) return false;
    const at = Number(raw);
    // An unparseable value (e.g. a legacy "1") is treated as expired.
    if (!Number.isFinite(at)) return false;
    const age = Date.now() - at;
    return age >= 0 && age < RESTORE_NOTE_TTL_MS;
  } catch {
    return false;
  }
}

export function clearRestoreInFlight(): void {
  try {
    sessionStorage.removeItem(RESTORE_IN_FLIGHT_KEY);
  } catch {
    // nothing to clear.
  }
}
