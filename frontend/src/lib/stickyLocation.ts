import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { safeSessionStorage } from "@/lib/safeStorage";

/**
 * Remembers the last visited URL (path + search) under a key in sessionStorage
 * and restores it when the user lands on the same module with a "bare" URL
 * (i.e. no query params). This makes switching between IPAM ↔ DNS (or any
 * other sidebar module) feel like each module has its own persistent state.
 *
 * - Only restores when the current URL has no search params, so deep-links
 *   (e.g. `/ipam?subnet=abc` from global search) always win.
 * - Also skips restoration when the current navigation carried router
 *   state — otherwise GlobalSearch's ``navigate("/ipam", { state })``
 *   would be silently clobbered by ``navigate(saved, { replace: true })``
 *   below (the replace drops ``location.state``), wiping the
 *   ``highlightAddress`` before ``SubnetDetail`` ever reads it.
 * - Uses `sessionStorage` so reloading restores but closing the tab clears.
 * - Only writes when search params are non-empty; bare visits don't overwrite
 *   a meaningful saved location.
 */
export function useStickyLocation(key: string): void {
  const location = useLocation();
  const navigate = useNavigate();

  // Restore saved URL on first mount if current is bare.
  useEffect(() => {
    if (location.search !== "") return;
    if (location.state != null) return;
    const saved = safeSessionStorage.getItem(key);
    if (saved && saved.startsWith(location.pathname + "?")) {
      navigate(saved, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Save current URL whenever it has params.
  useEffect(() => {
    if (location.search === "") return;
    safeSessionStorage.setItem(key, location.pathname + location.search);
  }, [key, location.pathname, location.search]);
}
