### Fixed

- **Alerts: percentage-threshold rules no longer flap around their threshold** (#2778). `appliance_disk_usage`, `subnet_utilization` and `dhcp_pool_exhaustion` now keep an already-open event until the value falls 5 points below the threshold, instead of resolving and re-firing (and re-delivering) every time it crosses the line. Opening is unchanged, and an open critical stays critical until it resolves.
