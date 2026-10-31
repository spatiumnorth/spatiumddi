### Fixed

- **Two DHCP agents on one identity no longer trade re-registrations
  forever (#3143).** A cloned Kea VM, or two DHCP agent containers
  given one state directory, keeps the same agent id, so both
  authenticated as one server against its one token: each registration
  or token rotation made the other's token stale, the pair took turns
  getting `401 Stale token` and re-registering, and the server row
  flapped between them. The DHCP agent now sends a random per-process
  id on its config polls, heartbeats and registrations, and the control
  plane follows the DNS agent's rules (#2044, #2219): the newest process
  owns the server, and the one it displaced is answered `409` on its
  polls and registrations while the owner is live, is never issued or
  rotated a token, keeps Kea serving the config it already has, and
  asks again every 30 seconds. It takes the server back by itself once
  the owner has been silent for 5 minutes. Its heartbeats still count
  for liveness, but its daemon, config-apply and spool reports stay off
  the server row. An episode lasting over 2 minutes shows a **Duplicate
  agent** chip on the DHCP server row and detail, sets `duplicate_agent`
  on the `list_dhcp_servers` Copilot tool, and raises the new
  default-on **Two DHCP agents on one server** alert. Kea HA peers have
  their own identities and are unaffected, and an older agent that
  sends no process id registers and polls exactly as before.

### Migrations

- `833ee80c8c6b` — #3143, adds the nullable `dhcp_server.agent_instance`,
  `agent_instance_seen_at`, `agent_instances_displaced`,
  `duplicate_agent_first_at`, `duplicate_agent_last_at` and
  `duplicate_agent_ip` columns, and seeds the enabled
  `dhcp_agent_duplicate_instance` alert rule once (only when no rule of
  that type or name exists). No backfill.
