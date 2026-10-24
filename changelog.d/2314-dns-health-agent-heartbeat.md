### Fixed

- **DNS health task judged agent freshness by its own timestamp
  (#2314).** An active agent-based server renewed its own
  `last_health_check_at` every sweep and never reached the probe, so a
  wedged agent whose `named` still answered flapped between active and
  unreachable. Freshness now comes from `last_seen_at`, which only the
  agent writes; a stale agent stays unreachable, the SOA probe is only
  the fallback for an agent that has never reported, and a server in
  maintenance mode is skipped as DHCP already does.
