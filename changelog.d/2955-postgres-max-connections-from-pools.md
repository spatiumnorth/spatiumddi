### Fixed

- **Postgres `max_connections` now holds the api, worker and beat pools on
  the Helm chart and the raw manifests, and the chart's Postgres memory limit
  holds those connections (#2955).** Each api pod opens up to 30
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
  At the chart defaults that is 369 (standalone) and 371 (CNPG). `k8s/ha` now
  sets 371, with the formula in `k8s/README.md`.
  Raising the connection limit alone would have traded refused connections
  for an out-of-memory kill of the database: a busy backend costs ~14 MiB
  (measured in #2156), so 370 of them do not fit the chart's 1Gi Postgres
  limit. While the chart derives `max_connections` it now also raises
  `postgresql.resources.limits.memory` to shared_buffers + 256 MiB +
  max_connections x (14 + shared_buffers / 512) MiB, the appliance's rule:
  **5919Mi standalone and 6077Mi on CNPG at the defaults** (was 1Gi). Only the
  limit moves; the request stays 256Mi, so scheduling is unchanged. A
  `max_connections` set explicitly still wins and leaves the memory limit as
  configured, so the appliance, which always sets both, is unchanged.
  **Upgrade note: a chart install that never set `max_connections` restarts
  its database once.** On a standalone Postgres the pod restarts (a brief
  outage of the database); on CNPG, which was at 200, the instances roll
  (replicas first, then a switchover). To keep the old numbers, set
  `postgresql.maxConnections` / `postgresql.cnpg.parameters.max_connections`
  explicitly, with pools small enough to fit them. `make charts-lint` renders
  several HPA / pool shapes on both kinds and fails when the pools can exceed
  `max_connections` or the memory limit cannot hold it.
