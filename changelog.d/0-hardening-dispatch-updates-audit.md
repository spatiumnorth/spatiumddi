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

- **`GET /alerts/rules` and `GET /alerts/events` require read permission on
  alerts.** They answered any signed-in user. The builtin Viewer role (read
  on everything) and superadmin are unaffected; a custom role with no alert
  read grant now gets 403 and needs one added.
