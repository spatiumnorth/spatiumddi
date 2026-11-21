/** sessionStorage flag set while a console restore is in flight. A restore
 *  revokes every session, so the browser's next call 401s and the page jumps
 *  to sign-in; the sign-in page reads this to say why (#4676). */
export const RESTORE_IN_FLIGHT_KEY = "spatium.restoreInFlight";

/** True once if a restore was in flight; consumes the flag. */
export function consumeRestoreInFlight(): boolean {
  try {
    const hit = sessionStorage.getItem(RESTORE_IN_FLIGHT_KEY) !== null;
    if (hit) sessionStorage.removeItem(RESTORE_IN_FLIGHT_KEY);
    return hit;
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
