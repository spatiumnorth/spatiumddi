### Fixed

- Helm chart: new opt-in `postgresql.cnpg.synchronous` values render CloudNativePG synchronous replication (`method`, `number`, `dataDurability`) for zero data loss on failover; default stays asynchronous, and the render fails with fewer than two instances.
- Appliance: **Appliance → Cluster → Database** opts the multi-node control plane in to synchronous Postgres replication (superadmin; needs at least 2 control-plane members). Required durability blocks writes while too few synchronous replicas are available; preferred falls back to asynchronous. The supervisor lowers the replica count when the cluster shrinks instead of failing the chart render; the setting is also readable through the `find_postgres_synchronous` Copilot tool. New migration `d4a8c27e91f3`.
