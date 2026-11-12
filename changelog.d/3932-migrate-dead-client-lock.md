### Fixed

- An upgrade no longer hangs for hours behind a database session whose client has died. PostgreSQL now drops a session idle in a transaction for 15 minutes and probes silent peers with TCP keepalives (CloudNativePG, the in-chart Postgres, Docker Compose and `k8s/ha`; all reload-only for CNPG), and the migrate command ends stale idle-in-transaction sessions of the app's role, bounds each lock wait with `lock_timeout`, and retries while logging which session holds the lock.
