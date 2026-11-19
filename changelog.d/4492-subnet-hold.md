### Added

- IPAM: a CIDR can be held for a future project with a reason, owner and expiry date (`/api/v1/ipam/holds`, plus `find_subnet_holds` / `propose_subnet_hold` for the copilot). A hold creates no subnet, placeholder addresses, reverse zone or DHCP scope, subnet creation refuses held space, and an expired hold keeps holding until it is released or converted to a subnet.
