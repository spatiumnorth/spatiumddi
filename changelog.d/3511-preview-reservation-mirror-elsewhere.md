### Fixed

- **A block or space delete's approval preview leaves out the records
  of a reservation's IPAM mirror in another subnet (#3511).** Before it
  trashes anything, the delete removes the IPAM mirror of each
  reservation of the DHCP scopes it takes, with the mirror's DNS
  records, whatever subnet the mirror sits in. The preview left those
  records out only for a mirror in its scope's own subnet, so for a
  reservation whose mirror sat in another subnet of the same block or
  space it counted records the delete never trashes.
