### Added

- A nearly-full DHCP pool can now suggest free ranges to extend it or add beside it: `GET /dhcp/pools/{id}/expansion-suggestions` (and a lightbulb button on the pool row, and the `find_dhcp_pool_expansion` copilot tool) lists the ranges touching the pool first, then the largest other free runs, leaving out IPAM-allocated addresses, reservations, leases, other pools and the gateway, and flags addresses discovery has seen answering. It changes nothing; choosing a range opens the pool dialog pre-filled. IPv4 only. (#4489)
