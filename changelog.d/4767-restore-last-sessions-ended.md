### Fixed

- `GET /api/v1/backup/restore/last` now reports `sessions_ended`, the number of sessions the restore ended, instead of always answering `null` after a Full restore (#4767).
