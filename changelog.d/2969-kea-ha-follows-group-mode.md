### Fixed

- **Kea HA now follows the DHCP group's mode (#2969).** The HA
  renderer, the appliance HA firewall rule (#1167) and the
  `kea_ha_version_skew` pre-flight (#2195) decided HA from the
  members' `ha_peer_url` values alone, so a `standalone` group with
  peer URLs rendered an HA relationship with `"mode": "standalone"`,
  which Kea refuses, stopping that server. Only `hot-standby` and
  `load-balancing` groups render HA now; a standalone group never does,
  and the firewall rule and pre-flight agree. The bundle ETag already
  carries the HA block, so changing the mode shifts it and the group
  channel is woken as before. A `standalone` group with two or more
  Kea members and a scope is now reported by the existing default-on
  "DHCP scope served uncoordinated" alert, naming the group; nothing
  is refused.
