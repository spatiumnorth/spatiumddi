### Fixed

- **A disabled DNS server stays disabled (#2853).** The agent
  heartbeat wrote `active` on every check-in whatever `is_enabled`
  said, so a disabled server flipped back to active until the next
  health check. The heartbeat now keeps it `disabled` while still
  recording `last_seen_at`; re-enabling returns it to `active` on the
  next heartbeat. The zone sync pill also leaves a disabled server out
  of the in-sync verdict and lists it as disabled, instead of
  reading the zone as out of sync until re-enable.
