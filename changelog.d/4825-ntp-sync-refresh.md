### Fixed

- Appliance NTP: the chrony sync state shown on the NTP tab is now refreshed every minute by a host timer, instead of only when a config was applied, so it no longer sticks on a stale "No time source" (#4825).
- Appliance NTP: the sync-status timer reads chrony over its Unix socket first and records `unknown` (exit 0) when no read works, so it no longer fails every minute when `chronyd-restricted.service` is the running daemon (#4825).
