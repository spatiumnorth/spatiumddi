### Fixed

- **An instance that cannot rejoin is re-cloned instead of looping for ever (#2132).**
  - **Stuck instances are re-cloned:** with no WAL archive, a former primary
    whose `pg_rewind` needs WAL that is gone, or a standby whose slot was
    invalidated, looped until someone deleted its PVC by hand. The seed
    supervisor now reads each non-primary instance's log; after 10 minutes of
    the same never-ending loop under the same primary, repeating on every
    read (a replica that logs a line or two while it joins is not counted),
    it annotates the pod
    `alpha.cnpg.io/unrecoverable`, and CNPG rebuilds that instance from the
    primary. One at a time, never the primary, never during a failover. The
    `supervisor.heartbeat.postgres_instance_stuck` log line names the loop
    and the manual fix.
  - **Upgrade:** the appliance chart grants the supervisor `get` on
    `pods/log` and `patch` on `pods` in the `spatium` namespace.
