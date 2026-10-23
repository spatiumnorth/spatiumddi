### Fixed

- The IPAM zone pickers (Allocate IP, Edit address, Bulk edit, block and subnet DNS settings) tell reverse zones by their `in-addr.arpa` / `ip6.arpa` suffix, so a forward zone whose name merely contains "arpa" (such as `scarpa.example`) is offered (#2472).
