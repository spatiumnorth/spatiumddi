### Fixed

- **A role scoped to one subnet now works in IPAM (#2438).** A `read`
  and `write` grant on a single subnet lets its holder read and edit
  that subnet, list and create its addresses, and see it in the subnet
  list; every other subnet, the space / block routes, delete, resize
  and re-parenting stay refused.
