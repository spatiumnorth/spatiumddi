### Fixed

- PowerDNS catalog zone is now created as kind Master with the group's also-notify targets and a 5-minute SOA refresh, so consumers are notified of added or removed member zones within seconds instead of at the next 24-hour refresh. An existing Native catalog zone is migrated on the next sync, and an unchanged catalog is no longer re-published (and re-notified) on every sync (#4574).
