### Fixed

- **A scope change on a Kea HA group resets the HA pair for less time
  (#3779).** The DHCP agent now reloads only the Kea daemon whose
  configuration changed, so a v6-only change leaves dhcp4 and its HA
  state alone. The HA heartbeat delay defaults to 2 s instead of 10 s,
  which cuts the hot-standby outage of a reload from about 21 s to about
  4 s; existing groups still at 10 s move to 2 s on upgrade, and any
  other value is kept.

### Migrations

- `ede3bcd2aff4` — #3779, sets `dhcp_server_group.heartbeat_delay_ms`
  to 2000 on rows still at the old 10000 default. The downgrade leaves
  the values as they are.
