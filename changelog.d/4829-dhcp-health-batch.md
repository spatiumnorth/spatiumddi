### Fixed

- The worker's event outbox and periodic sweeps no longer stall behind DHCP health checks of unreachable Windows servers: agentless servers are now probed concurrently in one task, so N dead hosts cost one connect timeout, not N.
