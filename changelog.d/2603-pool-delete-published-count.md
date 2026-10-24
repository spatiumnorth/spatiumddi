### Fixed

- **DNS pool "Delete pool" counts what the zone publishes (#2603).**
  The dialog called every member "currently published"; a disabled
  pool, or members not yet healthy, publish nothing. It now counts the
  enabled, healthy members of an enabled pool and says when deleting
  withdraws nothing from the zone.
