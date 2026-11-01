### Fixed

- **A DHCP server that leaves its HA relationship no longer keeps
  showing its old HA state (#3241).** A Kea server moved out of a
  hot-standby or load-balancing group, or whose group became
  standalone, whose partner left, or whose peer URL was cleared, kept
  the `ha_state` and `ha_last_heartbeat_at` it last reported, so
  `GET /api/v1/dhcp/servers` and the DHCP page's "HA v4" pill still said
  `hot-standby` for a standalone server whose Kea had unloaded the HA
  hook. Both are now cleared as soon as the server's config carries no
  HA hook (at its agent's next config poll, which also clears a row
  left stale by an earlier build), and a late HA report from a server
  that takes part in no HA relationship stores nothing.
