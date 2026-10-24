### Fixed

- **Subnet split refuses hosts that would land on a child's network or
  broadcast address (#2415).** The preview names each such host as a
  conflict and the commit refuses it, instead of leaving an
  "allocated" host on an address no client can use. The preview also
  warns that clients need the new netmask.
