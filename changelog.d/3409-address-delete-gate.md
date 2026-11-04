### Fixed

- IPAM: an address's Delete (the row button, the right-click item and the detail pane's button) is now offered only with the `delete` permission the server asks for, instead of to any role that can write. Without it the row button and the right-click item are disabled and say why, and the detail pane shows no Delete. A `delete` grant on any address set is enough, as it is for the server, while Clean Orphans now needs `delete` on subnets, which is what its route checks.
