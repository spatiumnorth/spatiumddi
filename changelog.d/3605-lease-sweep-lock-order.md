### Fixed

- The DHCP lease expiry sweep no longer deadlocks with a Kea lease-events batch on the same addresses. It now locks the IPAM mirror rows it deletes first, in the same (subnet, address) order the lease-events handler uses, and only then revokes DDNS and deletes, so a 500 on the agent's lease report is no longer possible from that clash (#3605).
