### Fixed

- The upgrade that makes server-delete keep client history now validates its new foreign keys in a separate commit, so log ingest no longer waits for the validation scan on large query-log tables. (#4449)
