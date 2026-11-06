### Fixed

- DHCP: a lease renewal that landed while the expiry sweep held the lease no longer leaves the lease `expired`. The lease-events batch and the agentless lease pull now lock the lease rows and re-read them before deciding, so the renewed lease is `active` again and its IPAM entry and DNS records are cleaned up when it later runs out (#3624).
