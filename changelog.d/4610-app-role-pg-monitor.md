### Fixed

- The appliance's database role is now a member of PostgreSQL's read-only `pg_monitor` role (granted through CloudNativePG `managed.roles`, so existing clusters pick it up on upgrade), so the rolling-upgrade preflight's `replication_lag` check can read each replica's streaming state instead of warning that it is unverifiable. Where the grant is withheld (`postgresql.cnpg.appRoleMonitor=false`) or not yet reconciled, the check now says plainly that it could not verify, not measured lag, and names the remedy.
