### Fixed

- `POST /held` no longer lets a read-scoped API token grow the E911
  lookup trail without bound (#3514): each caller gets a per-minute
  budget of logged HELD lookups (past it the lookup is still answered,
  just not logged, and the api logs `e911_lookup_trail_skipped`), and
  a daily task prunes `e911_resolution_log` rows past a retention
  window. Both are settings under Settings → Data Retention:
  `e911_lookup_log_budget_per_minute` (default 120, 1–6000) and
  `e911_resolution_log_retention_days` (default 90, 7–3650).

### Migrations

- `d8f3b6a41e52` — #3514, adds `e911_lookup_log_budget_per_minute` and
  `e911_resolution_log_retention_days` to `platform_settings`.
