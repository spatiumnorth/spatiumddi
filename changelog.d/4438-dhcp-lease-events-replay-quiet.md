### Fixed

- A re-posted DHCP lease-event batch no longer takes the DNS zone locks for renewals that write nothing; the replay applies the same quiet-renewal skip as the first pass (#4438).
