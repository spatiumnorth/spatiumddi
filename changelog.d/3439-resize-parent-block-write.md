### Fixed

- IPAM: growing a subnet now requires `write` on its parent block, not only on the subnet. The resize preview lists the refusal as a conflict, and the resize itself is refused with a 403 before anything changes (#3439).
