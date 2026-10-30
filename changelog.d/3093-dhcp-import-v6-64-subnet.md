### Fixed

- **A DHCP import can create the IPv6 /64 subnet for a scope again
  (#3093).** The commit set the new subnet's address count to 2^64,
  which the database refuses, so every DHCPv6 scope whose /64 was not
  yet in IPAM failed with "the database refused this scope's data" and
  nothing was created. The import now counts addresses the way every other
  subnet-creating path does, capped at the database limit. An IPv4 subnet
  the import creates now also leaves its network and broadcast addresses
  out of its size, as IPAM does (a /24 reads 254, not 256); subnets an
  earlier import created keep the size they were given.
