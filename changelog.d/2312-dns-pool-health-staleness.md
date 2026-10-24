### Fixed

- **DNS pool member health had no staleness bound (#2312).** Pools still
  serve fail-open, but a member whose last health check is older than 3
  check intervals now shows `stale · <age> ago` (s / m / h / d) in the members table, and a
  new default-on `dns_pool_health_stale` alert fires per pool whose
  health checks have stopped.
