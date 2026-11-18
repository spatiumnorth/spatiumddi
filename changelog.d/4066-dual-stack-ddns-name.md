### Fixed

- A dual-stack DHCP client now keeps its own hostname on both address families. Its IPv4 lease's A record was treated as another host holding the name, so the IPv6 lease (or the reverse) fell back to a generated `dhcp-<address>` name in IPAM and DNS even with the `client_or_generated` policy (#4066).
