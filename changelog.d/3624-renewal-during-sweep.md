### Fixed

- DHCP: a lease renewal that landed while the expiry sweep held the lease no longer leaves the lease `expired`. The lease-events batch and the agentless lease pull now lock the lease rows and re-read them before deciding, so the renewed lease is `active` again and its IPAM entry and DNS records are cleaned up when it later runs out. A renewal of a lease the sweep deleted meanwhile now lands as a fresh lease instead of failing, and renewing a lease long past its expiry, or a pull renewing a lease the sweep holds, no longer deadlocks with the sweep (#3624).
