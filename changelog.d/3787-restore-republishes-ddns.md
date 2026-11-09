### Fixed

- Restoring a subnet, block, space or DHCP scope from the Trash now re-publishes the A and PTR records of the active DHCP lease mirrors that come back with it (when the subnet's DDNS is on), instead of leaving them without names until each client renews (#3787).
