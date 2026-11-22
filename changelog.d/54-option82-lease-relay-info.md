### Added

- DHCP leases record the relay agent information (option 82) a relay sent: the circuit-id and remote-id are stored on the lease and kept in lease history, returned by the lease and lease-history APIs (as hex, plus text when printable) and by the copilot's lease tools, and searchable with `relay_circuit_id=` / `relay_remote_id=`. `GET /dhcp/server-groups/{id}/relay-agent-observations` lists the values a group's relays actually send. Kea stores option 82 only for groups with an option-82 client class (#54).

### Migrations

- `b9b98b65f49c` — #54, `dhcp_lease.relay_agent_info` / `relay_circuit_id` /
  `relay_remote_id` and `dhcp_lease_history.relay_circuit_id` /
  `relay_remote_id` (all nullable, hex), with partial indexes on the two
  lease columns.
