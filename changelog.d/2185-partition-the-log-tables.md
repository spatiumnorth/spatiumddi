### Changed

- **The DNS query log, DHCP activity log and RPZ hit tables are
  time-partitioned, and retention is a partition drop (#2185).**
  `dns_query_log_entry`, `dhcp_log_entry` and `dns_rpz_hit` are
  `PARTITION BY RANGE (ts)`, so aging out data no longer runs a mass
  `DELETE`: no WAL burst, no table or index bloat, no long autovacuum
  competing with config reads and writes.
  - A beat task, `maintain_log_partitions`, runs every 15 minutes. It
    creates partitions ahead (hourly for the DNS query log while
    `log_retention_hours` is 48 or less, daily above that, daily for
    the other two tables) and drops the ones past the window. Creating
    attaches a plain table, and retiring uses `DETACH ... CONCURRENTLY`,
    so neither waits for a long reader or queues the agents' inserts.
    A per-table advisory lock keeps two workers from racing.
  - Retention is applied at the grain of the partitions: a row can
    outlive `log_retention_hours` by up to an hour, or a day.
  - There is no default partition. The agent ingest endpoints count a
    line dated beyond what the partitions cover as `expired`, with the
    lines that are already older than the window.
  - `prune_log_entries` now only retires agent ingest receipts.
  - The setting's cap of 168 hours is unchanged.
  - A selective restore of the `logs` or `dns_threat` section loads
    these tables through the parent: a custom-format archive keeps their
    rows under the partitions, so `pg_restore --table <parent>` would
    have emptied the table and loaded nothing. Rows dated outside every
    partition the install has now are dropped, not failed on.
  - DNS query log, DHCP activity and RPZ hit history start fresh after
    the upgrade. The previous rows are kept in `<table>_legacy` for one
    release.

### Migrations

- `e5a93c1b7d24` — #2185, renames each of the three tables to
  `<table>_legacy` and creates the partitioned table under the old name
  (same columns, foreign key and indexes; primary key `(id, ts)`), moves
  the `id` sequence to it, and creates daily partitions covering the
  retention window. The previous release's pods keep reading and writing
  the same table name during the rolling upgrade. The `_legacy` tables
  are dropped in the next release. Downgrade parks the partitioned
  tables as `<table>_partitioned` and restores the old ones.
