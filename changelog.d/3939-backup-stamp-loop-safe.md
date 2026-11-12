### Fixed

- A scheduled backup whose database session is ended mid-run (a restore, a failover, an upgrade's migrate guard) now records its end on a connection bound to the sweep's own event loop, so the run reads `success` or `failed` instead of staying `in_progress` for 2 hours while its target is skipped (#3939).
