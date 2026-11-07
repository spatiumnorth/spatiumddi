### Fixed

- **Edit Subnet and Resize's gateway move follow one free-slot rule
  (#3709).** Edit Subnet refused as the gateway an `available` address
  that Next available offers, with a 409 calling it held, and Resize's
  "Move gateway to new first-usable IP" refused any row at the new
  address, including an `available` one and a `reserved` row that Edit
  Subnet keeps as the gateway's own. Both now accept an address with no
  row, an `available` row (taken over as the gateway's reserved row, as
  Bulk allocate takes a free slot over) and a `reserved` row (kept), and
  refuse a host, a lease or a discovered row. The subnet import's
  overwrite and the integration mirror's gateway sync follow the same rule.
