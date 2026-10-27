### Fixed

- **A timeout on one log table no longer undoes the whole nightly
  prune (#2872).** The retention sweep deleted from the DNS query log,
  the DHCP activity log, the RPZ hits and the ingest receipts in one
  transaction, so when the big query-log delete hit the command
  timeout, the other tables were rolled back with it and none was
  pruned, which made the next night's delete larger and likelier to
  time out again. Each table is now deleted and committed on its own;
  a table that fails is rolled back alone, logged, and reported as -1
  (and listed in `failed_tables`) instead of 0, and the others still
  run. Reported by @AlexeyShalaev.
