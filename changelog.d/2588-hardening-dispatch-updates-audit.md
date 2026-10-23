### Changed

- **Celery publishes from async handlers run off the event loop.** Every
  inline `task.delay()` in an `async def` under `backend/app/api` now goes
  through `app.core.celery_dispatch.dispatch`, which publishes from a worker
  thread, so a slow or unreachable broker no longer stalls other requests. A
  guard test fails on a bare publish in async API code.
- **A failed release check is shown.** The stored error appears next to the
  version in the sidebar and under Settings, Application, Updates. The same
  already-documented daily check also runs once when beat starts; no new
  connection is made.
- **`POST /alerts/evaluate` is audited.**

### Fixed

- **Every alerts read requires `read` on `alert`.** `GET /alerts/rules`,
  `/alerts/rules/{id}`, `/alerts/rule-types` and `/alerts/events` answered any
  signed-in user, and the events carry resource names. `alert` is now a grant
  type in the Roles dialog and in `docs/PERMISSIONS.md`. The builtin Viewer
  (read on everything) and superadmin are unaffected. The builtin IPAM, DNS,
  DHCP and Network Editors, Auditor and Compliance Editor gain `read:alert`
  (re-applied at startup), so the dashboard's alert panels keep working for
  them. Address Set Editor, Change Approver, Requester and Appliance Operator
  do not get it. A custom role with no alert read grant now gets 403 and needs
  `read` on `alert` added.
