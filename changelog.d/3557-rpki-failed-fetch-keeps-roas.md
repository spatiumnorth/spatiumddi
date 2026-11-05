### Fixed

- A failed or unreachable RPKI ROA fetch no longer deletes the stored ROAs of an AS and reports success: the refresh now tells "the source answered and this AS has none" apart from "the source could not be read", keeps the stored rows on failure, and reports it (the scheduled sweep returns `status: failed` with the reason, "Refresh RPKI" answers 502). The `ripe` ROA source pointed at a retired RIPE endpoint that answers 404; it now uses `https://rpki-validator.ripe.net/api/export.json` (same host) (#3557).
