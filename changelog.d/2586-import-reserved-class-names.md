### Fixed

- **The DHCP importer no longer creates client classes under reserved
  names, and a stored `DROP` class no longer switches the MAC blocklist
  off.** The importer's commit now skips any class whose name the
  client-class API refuses (Kea built-ins such as `DROP`, Kea's `HA_` /
  `VENDOR_CLASS_` / `SPAWN_` prefixes, and names SpatiumDDI generates)
  and lists each skip in the commit's warnings; the Kea and ISC previews
  mark such classes as not importable and say why. A client class named
  `DROP` stored before the API refused the name used to make the agent
  leave the MAC blocklist out of the rendered Kea config, so blocked
  MACs were served. The agent now renders one `DROP` class matching
  either the stored class's test or a blocked MAC, on both DHCPv4 and
  DHCPv6, and logs `mac_blocklist_merged_into_operator_drop_class` when
  it does. The stored class keeps dropping what it dropped before.
