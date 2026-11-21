### Fixed

- Building a DNS agent bundle read every enabled blocklist's entries and exceptions with one database query per list; it now reads each with a single query across all of them, in the same order, so the bundle and its ETag are unchanged (#1109).
