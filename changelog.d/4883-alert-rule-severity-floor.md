### Fixed

- Alert rules now honour their Severity for every rule type: twelve types (appliance /var filling, node pressure, cluster DNS degraded, agent spool trimmed, DNS memory pressure, DNSSEC multi-signer, uncoordinated DHCP scope, stale blocklist feed, stale DNS pool health, agent bundle render failed, appliance heartbeat stale, Postgres instance unhealthy) ignored it and always opened at their own fixed level. The rule's Severity is now the floor of its alerts; a type that escalates still can, but never below it (#4883).
