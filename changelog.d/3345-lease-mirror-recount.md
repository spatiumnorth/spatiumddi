### Fixed

- Subnet and block utilization now follows DHCP lease mirrors. Kea lease events, the Windows DHCP lease pull (including its absence-delete), the lease expiry sweep, the orphaned-mirror sweep, single-lease and scope or server lease deletes all recount the touched subnets and their block chains once per batch, instead of leaving the figures stale until the next full recount.
- Concurrent utilization recounts (both peers of a Kea HA pair, the lease sweeps, address edits and the hourly recount) now lock subnet and block rows in one fixed order, so two of them touching the same block tree wait for each other instead of deadlocking. A lease renewal that changes no address status skips the recount entirely.
