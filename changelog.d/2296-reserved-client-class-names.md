### Fixed

- **Client-class names the renderer owns are refused (#2296).** A
  class named `DROP` made the agent skip the generated MAC-blocklist
  class, so the blocklist silently stopped blocking. Create and rename
  now return 422 for Kea's built-ins (`DROP`, `ALL`, `KNOWN`,
  `UNKNOWN`, `BOOTP`, `HA_*`, `VENDOR_CLASS_*`, `SPAWN_*`) and the
  generated `spatium-device-*`, `pxe-<hex>-<hex>` and `voip-<hex>`
  names. A row already stored with such a name keeps rendering and is
  flagged `reserved_name`; the agent logs
  `mac_blocklist_shadowed_by_drop_class` when it shadows the blocklist.
