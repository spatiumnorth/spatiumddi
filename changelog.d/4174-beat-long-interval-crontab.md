### Fixed

- Daily beat jobs (DNS / DHCP log prune, metric-sample prune, subnet utilisation snapshot, E911 log prune, update check) and the 12-hourly ACME renewal sweep no longer use an interval that restarts whenever celery-beat restarts, so a beat that restarts more than once a day can no longer leave them unrun for days (the DNS query log once held two days of rows). They now run at fixed UTC times (the log prune hourly, at :05), and a test rejects any new beat interval longer than an hour.
