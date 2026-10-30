### Fixed

- **A DHCP import can create the IPv6 /64 subnet for a scope again
  (#3093).** The commit set the new subnet's address count to 2^64,
  which the database refuses, so every Kea DHCPv6 scope whose /64 was not
  yet in IPAM failed with "the database refused this scope's data" and
  nothing was created. The import now counts addresses the way every other
  subnet-creating path does, capped at the database limit.
