### Fixed

- **DHCP pool ranges are validated (#2500).** `start_ip` / `end_ip`
  must be valid IPs, ordered, and inside the scope's subnet (and its
  address family) on create and update. A malformed address is now a
  422 instead of a 500, and an out-of-subnet pool is refused instead of
  making Kea reject the whole group's config.
