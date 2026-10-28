### Fixed

- **Console tabs no longer re-rotate each other's session on every refresh
  (#2960).** Each tab refreshed on its own, so one tab's rotation killed the
  others' access tokens once the #2941 grace passed, and they rotated back in
  turn. One tab now refreshes at a time (Web Locks, `spatium-refresh`) and
  broadcasts the new access token and its expiry over a same-origin
  BroadcastChannel; a tab that gets the lock after another already refreshed
  adopts that token instead of calling `/auth/refresh`. Sign-out in one tab
  signs out every tab. A token for a different user is ignored. The token stays
  in memory only, and where Web Locks or BroadcastChannel is missing each tab
  refreshes on its own as before.
