### Added

- **DNS and DHCP agents report their actual memory use (#4193).** Each
  heartbeat now carries the container's memory used, peak and limit
  (from the cgroup) plus the resident memory of the daemon (`named`,
  `pdns_server`, Technitium, Kea) and of the agent. The DNS and DHCP
  server lists show used against limit (amber above 80%), the server
  modal shows the breakdown and a sparkline, and the DNS Blocking Lists
  tab shows each server's real `named` memory next to the estimate.
  Servers whose agent predates this show "—". The figures are also on
  the server read endpoints, `GET .../servers/{id}/memory-history`, and
  the Copilot's server tools. An alert on memory use is not part of this.

### Migrations

- `e5b1c7a94d20` — #4193, nullable `memory_status` on `dns_server` and
  `dhcp_server`, and `mem_*` columns on the two metric-sample tables.
