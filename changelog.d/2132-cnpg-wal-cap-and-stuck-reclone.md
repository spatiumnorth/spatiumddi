### Fixed

- **Postgres no longer fills a node's /var after a failover, and an instance
  that cannot rejoin is re-cloned instead of looping for ever (#2317, #2132).**
  - **Slot WAL is capped:** the CNPG Cluster sets
    `max_slot_wal_keep_size: 3GB` (it was PostgreSQL's unlimited `-1`). After
    a failover the new primary holds CNPG's HA slots for standbys that may
    never follow it, and one lab primary's `pg_wal` grew to 26 GB on its
    node's `/var` while CNPG read healthy. PostgreSQL keeps the larger of
    this cap and `wal_keep_size` (2GB), plus up to `max_wal_size` (1GB), so
    `pg_wal` now stays near 4GB, half the instance volume. Applied by a
    reload, not a restart.
  - **Stuck instances are re-cloned:** with no WAL archive, a former primary
    whose `pg_rewind` needs WAL that is gone, or a standby whose slot the cap
    invalidated, looped until someone deleted its PVC by hand. The seed
    supervisor now reads each non-primary instance's log; after 10 minutes of
    the same never-ending loop under the same primary it annotates the pod
    `alpha.cnpg.io/unrecoverable`, and CNPG rebuilds that instance from the
    primary. One at a time, never the primary, never during a failover. The
    `supervisor.heartbeat.postgres_instance_stuck` log line names the loop
    and the manual fix.
  - **Upgrade:** the appliance chart grants the supervisor `get` on
    `pods/log` and `patch` on `pods` in the `spatium` namespace.
