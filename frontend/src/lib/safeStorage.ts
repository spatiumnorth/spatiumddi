/**
 * Web storage that never throws (#3231).
 *
 * Each caller keeps a preference in web storage: the theme, the sidebar's
 * collapse, a module's last URL, the dashboard's tab, a dismissed advisory.
 * A browser can refuse storage, and then these calls must not take the page
 * down with them:
 *
 * - With site data blocked for the console's origin (a privacy setting or an
 *   organisation's browser policy), Chrome and Edge throw a ``SecurityError``
 *   from the ``window.localStorage`` / ``window.sessionStorage`` getters
 *   themselves, so even naming the store throws.
 * - With the quota full, every ``setItem`` throws a ``QuotaExceededError``.
 *
 * A refused read is "nothing saved" (``null``) and a refused write is dropped:
 * the preference still applies to the page in front of the user, it just is
 * not remembered. With storage working these are the browser's own reads and
 * writes.
 */

type Area = "localStorage" | "sessionStorage";

function guarded(area: Area) {
  return {
    getItem(key: string): string | null {
      try {
        return window[area].getItem(key);
      } catch {
        return null;
      }
    },
    setItem(key: string, value: string): void {
      try {
        window[area].setItem(key, value);
      } catch {
        // Storage refused: the preference is not remembered, nothing else.
      }
    },
  };
}

export const safeLocalStorage = guarded("localStorage");
export const safeSessionStorage = guarded("sessionStorage");
