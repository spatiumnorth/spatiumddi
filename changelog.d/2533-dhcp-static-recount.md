### Fixed

- **A DHCP static assignment moves its subnet's Allocated count at
  once (#2533).** Creating, re-addressing or deleting a reservation
  changed its IPAM mirror row but left the subnet's and block's cached
  counts stale until the hourly recount; the statics API now
  recounts both.
