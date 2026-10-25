### Fixed

- **Every data-retention window is a setting (#2273).** Four retention
  columns (trash, DHCP lease history, packet captures, revoked
  appliances) were honoured by their prune tasks but reachable only by
  SQL; `metric_retention_days` was read by the metric prune but never
  existed, so metrics were always kept 7 days; and DNS query / DHCP
  activity logs were kept a hard-coded 24 hours. All six are now on
  `GET/PUT /settings` and a new Settings → Data Retention section,
  superadmin-only, range-checked (log retention is capped at 168 hours
  until #2185) and audited with old and new values. The agent log
  ingest skips lines by the same configured window. The docs no longer
  claim an audit-log retention period or S3 archive, which never
  existed. New read-only `find_retention_settings` copilot tool.

### Migrations

- `a3c7e91f2d58` — #2273, adds `platform_settings.metric_retention_days`
  (default 7) and `log_retention_hours` (default 24).
