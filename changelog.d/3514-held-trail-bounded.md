### Fixed

- `POST /held` no longer lets a read-scoped API token grow the E911 lookup trail without bound: each caller gets a per-minute budget of logged lookups (past it the lookup is still answered, just not logged), and a daily task prunes `e911_resolution_log` rows older than 90 days.
