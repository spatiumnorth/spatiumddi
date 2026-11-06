### Fixed

- The DHCP lease expiry sweep no longer deadlocks with a Kea lease-events batch on the same leases or addresses. It now locks the leases it expires and the IPAM mirror rows it deletes first, in the same order the lease-events handler uses, and only then revokes DDNS and deletes, so a 500 on the agent's lease report is no longer possible from that clash. It also no longer deletes the mirror of an address a failover or HA partner renewed while the sweep was waiting for it, and no longer marks a lease `expired` that its server renewed in that same window (#3605).
