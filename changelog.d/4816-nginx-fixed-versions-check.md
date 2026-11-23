### Changed

- **Weekly check of the pinned nginx against nginx.org's list of
  affected and fixed versions (#4816).** The image scan cannot see
  nginx.org's own packages, so a new weekly job reads that list and
  files one issue when the pin is in an affected range
  (`make nginx-fixed-check`). `versions.json` now marks nginx, BIND,
  Kea, PowerDNS and PostgreSQL as `network_facing`, and
  `make versions-upstream` lists those first when they are behind.
