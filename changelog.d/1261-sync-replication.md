### Fixed

- Helm chart: new opt-in `postgresql.cnpg.synchronous` values render CloudNativePG synchronous replication (`method`, `number`, `dataDurability`) for zero data loss on failover; default stays asynchronous, and the render fails with fewer than two instances. The appliance has no setting for it yet.
