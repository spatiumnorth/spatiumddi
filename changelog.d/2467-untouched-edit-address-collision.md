### Fixed

- **An untouched Edit address Save no longer asks for a collision
  confirmation (#2467).** The dialog sends hostname, MAC and zone on
  every Save and the collision check treated each one present as a
  change, so an address stored with a confirmed shared MAC or hostname
  was refused again with "Save anyway" on a Save that changed nothing.
  The checks now run only for a hostname, zone, MAC or extra-zone list
  that actually differs from what is stored.
