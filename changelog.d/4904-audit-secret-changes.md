### Fixed

- The Audit Log no longer shows the `secret_changes` list (for example `password_set`, `token_cleared`) as "[redacted]" on InfluxDB target changes; it lists field names, never values, so it is shown as stored. Real secret values stay redacted.
