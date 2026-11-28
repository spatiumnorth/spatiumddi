### Fixed

- DNS pool member health no longer reads stale between on-time checks when the check timeout is long next to its interval; the stale mark is now three intervals plus the timeout.
