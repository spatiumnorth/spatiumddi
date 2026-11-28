### Added

- IPAM: a CIDR can be held for a future project with a reason, owner and expiry date (`/api/v1/ipam/holds`, a Holds panel on the block view, and `find_subnet_holds` / `propose_subnet_hold` for the copilot). A hold creates no subnet, placeholder addresses, reverse zone or DHCP scope. Subnet create, restore, allocate-next, resize, split and merge refuse held space, and a new `subnet_hold_expiring` alert rule fires as a hold nears its expiry. An expired hold keeps holding until it is released or converted to a subnet.
