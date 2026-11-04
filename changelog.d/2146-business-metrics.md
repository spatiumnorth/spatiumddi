### Added

- `/metrics` now carries IPAM and DHCP business series: per-subnet allocated, total and utilization percent, and per-DHCP-scope active leases (distinct addresses, so a Kea HA pair counts once) and enabled state. They come from the same collectors as the InfluxDB export, are cached for 15 s, capped at 10,000 series per family, and are served only on an authenticated scrape (omitted when `PROMETHEUS_METRICS_REQUIRE_AUTH=false`, or off with `PROMETHEUS_BUSINESS_METRICS_ENABLED=false`).
