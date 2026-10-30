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
  - Because of the foreign key, attaching and detaching a partition also
    locks `dns_server` / `dhcp_server` for a few milliseconds. Every step
    waits at most 500 ms for a lock and is otherwise retried next tick.
  - There is no default partition. The agent ingest endpoints count a line
    inside the window that no partition covers as `no_partition`, apart
    from `expired`, and log `log_lines_without_partition`. The
    `log-partitions` component of `/health/platform` warns when the
    partitions ahead of now run short and errors when none covers the
    present. The task is also queued when beat or a worker starts, and a
    backup restore runs it before it returns.
  - `prune_log_entries` now only retires agent ingest receipts.
  - The setting's cap of 168 hours is unchanged.
  - A selective restore of the `logs` or `dns_threat` section loads
    these tables through the parent: a custom-format archive keeps their
    rows under the partitions, so `pg_restore --table <parent>` would
    have emptied the table and loaded nothing. Rows dated outside every
    partition the install has now are dropped, not failed on.
  - The upgrade copies the RPZ hits of the last 30 days. The DNS query log
    and DHCP activity history start fresh.

### Migrations

- `e5a93c1b7d24` — #2185, swaps each of the three tables for a
  partitioned one under the same name (same columns, foreign key and
  indexes; primary key `(id, ts)`), moves the `id` sequence to it, creates
  daily partitions covering the retention window, copies the RPZ hits
  inside it and drops the old tables. All locks are taken first under a
  3 s `lock_timeout` and the swap is retried, so a long reader makes the
  migration wait rather than queue the previous release's inserts behind
  it. The previous release's pods keep reading and writing the same table
  names during the rolling upgrade. Downgrade swaps back to plain tables,
  copying the RPZ hits.
