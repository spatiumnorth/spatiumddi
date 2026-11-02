### Fixed

- Subnet and block utilization now follows DHCP lease mirrors. Kea lease events, the Windows DHCP lease pull (including its absence-delete), the lease expiry sweep, the orphaned-mirror sweep, single-lease and scope or server lease deletes all recount the touched subnets and their block chains once per batch, instead of leaving the figures stale until the next full recount.
