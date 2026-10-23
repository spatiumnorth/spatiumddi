### Fixed

- **A cluster sizes its Postgres, api and worker limits from the node,
  and a DNS bundle render's time limits from its group (#2240, #2132).**
  A 7-node cluster at 1M devices (2M records, 20,000 zones) hit fixed
  limits, not its hardware.
  - **Postgres and api CPU:** now sized from the node's cores. Postgres gets
    `cores ÷ 2` (1-8; it was a fixed 1 core, throttled 89% under the load);
    the api gets `cores ÷ 4` (1-4).
  - **Worker memory:** now 0.40 of the budget, capped at 16 GiB (it was
    0.25, capped at 4 GiB). It never takes more than the api and Postgres
    leave over.
  - **Bundle renders:** the render's time limits scale with the group's
    record count (soft `120 s + 1.5 s per 1,000 records`, floor 900 s), and
    a render under-sized for its data resizes itself. The fleet-wide render
    slot can be raised (`DNS_AGENT_BUNDLE_RENDER_SLOTS`, 1 by default).
  - **CNPG:** keeps `wal_keep_size: 2GB`, so a former primary can rewind
    after a partition instead of looping on `pg_rewind`.
  - **Upgrade cost:** an existing cluster takes one rolling restart of
    Postgres and the api/worker on the first heartbeat after upgrading.
