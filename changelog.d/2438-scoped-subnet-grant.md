### Fixed

- **A role scoped to one subnet now works in IPAM (#2438).** A `read`
  and `write` grant on a single subnet lets its holder read and edit
  that subnet, list and create its addresses, and see it in the subnet
  list. It cannot reach any other subnet, the space / block routes,
  delete, resize, split, merge, the DNS drift report or NAT mappings,
  re-point the subnet at another block, customer, site, VLAN, DHCP or
  DNS server group, or publish records into a DNS zone the subnet does
  not already use. Users without scoped grants see no change.
