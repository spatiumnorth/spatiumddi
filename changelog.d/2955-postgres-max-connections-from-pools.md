### Fixed

- **Postgres `max_connections` now holds the api, worker and beat pools on
  the Helm chart and the raw manifests (#2955).** Each api pod opens up to 30
  request-pool connections, 2 for the after-commit hooks and 1 for its
  readiness probe, and the HPA runs up to 10 of them: 330 connections against
  the standalone image's default of 100 and CloudNativePG's 200, so scaled-out
  api pods were refused connections under load. The umbrella chart now derives
  `max_connections` for both the standalone StatefulSet
  (`postgresql.maxConnections`) and the CNPG Cluster
  (`postgresql.cnpg.parameters.max_connections`, now empty by default) from
  `api.databasePool` x the HPA's `maxReplicas` (or `api.replicas` with the HPA
  off), the worker replicas x concurrency, beat, the CNPG WAL senders and a
  10-connection reserve: the rule the appliance's supervisor already applies.
  A value set explicitly still wins, so the appliance is unchanged. At the
  chart defaults that is 369 (standalone) and 371 (CNPG). `k8s/ha` now sets
  371, with the formula in `k8s/README.md`. **Upgrade note: on a standalone
  Postgres the new setting restarts the Postgres pod once** (a brief outage
  of the database); on CNPG the instances roll as for any parameter change.
  `make charts-lint` renders several HPA / pool shapes on both kinds and fails
  when the pools can exceed `max_connections`.
