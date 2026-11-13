### Fixed

- The DHCP agent no longer loses lease rows Kea writes just before its hourly lease-file cleanup: it keeps the lease CSV open, reads the old file to its end when Kea rotates it, and only then starts the new one, so every row is sent once (DHCPv4 and DHCPv6).
