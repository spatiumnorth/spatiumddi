### Fixed

- `POST /held` no longer lets a read-scoped API token grow the E911
  lookup trail without bound (#3514). Past a per-caller budget of
  logged HELD lookups a minute, a lookup is still answered and is
  counted in one trail row per caller per minute ("N lookups not
  individually logged", naming the last identity looked up and its
  answer) instead of getting a row of its own. A daily task prunes
  `e911_resolution_log` rows past a retention window. Both are settings
  under Settings → Data Retention: `e911_lookup_log_budget_per_minute`
  (default 120, 1–6000) and `e911_resolution_log_retention_days`
  (default 90, 7–3650).

### Migrations

- `d8f3b6a41e52` — #3514, adds `e911_lookup_log_budget_per_minute` and
  `e911_resolution_log_retention_days` to `platform_settings`.
- `e2a9c5d71f30` — #3514, adds the per-caller per-minute counter
  columns (`caller_key`, `window_start`, `suppressed_count`) to
  `e911_resolution_log`, with a CHECK and the partial unique index the
  counter upsert conflicts on.
