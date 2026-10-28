### Fixed

- **Console tabs no longer re-rotate each other's session on every refresh
  (#2960).** Each tab refreshed on its own, so one tab's rotation killed the
  others' access tokens once the #2941 grace passed, and they rotated back in
  turn. One tab now refreshes at a time (Web Locks, `spatium-refresh`) and
  broadcasts the new access token and its expiry over a same-origin
  BroadcastChannel; a tab that gets the lock after another already refreshed
  adopts that token instead of calling `/auth/refresh`, and a request that
  failed on a token the tab has since replaced is retried with the new one
  rather than refreshing again. Sign-out in one tab signs out every tab, and
  voids a refresh in flight elsewhere. A forced password change carried by a
  broadcast sends every tab to Change Password. Broadcasts are shape-checked
  (a JWT with `sub` and `exp`, typed fields, not expired), a token for a
  different user is ignored, and a signed-out tab never picks one up. Each
  refresh is aborted after 30 s so a hung request cannot stall every tab
  behind the lock. The idle sign-out and the sign-out after a failed refresh
  are not broadcast: idle state is already shared across tabs and enforced by
  the server, and a failed refresh may be a transient error. The token stays
  in memory only, and where Web Locks or BroadcastChannel is missing each tab
  refreshes on its own as before.
