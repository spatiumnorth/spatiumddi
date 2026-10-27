### Fixed

- **A PostgreSQL standby that is not streaming now degrades Cluster
  health and raises an alert (#2856).** CNPG counts a standby that is
  Ready but not replicating as healthy, so the database row read
  healthy 3/3 while standbys looped on removed WAL for 10+ minutes, and
  nothing alerted. The row now carries one entry per instance and reads
  degraded when an instance is not Ready, a standby has no streaming
  WAL sender on the primary (`pg_stat_replication`), or a supervisor
  reports it looping or stuck. A new default-on
  `postgres_instance_unhealthy` alert opens after 5 minutes (warning),
  goes critical after 15, names the instance and its node, and
  resolves on recovery. `find_cluster_metrics` returns the same
  per-instance view.
