### Fixed

- New Subnet's Find by size no longer reports "No available /64 subnets" on a large IPv6 block whose first candidates are taken. `GET /ipam/blocks/{id}/available-subnets` now walks the block's free ranges instead of giving up after 4,000 candidates, so it lists free subnets however far into the block they start (#3849).
