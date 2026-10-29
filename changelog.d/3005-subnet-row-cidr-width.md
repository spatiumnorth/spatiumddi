### Fixed

- **A subnet's CIDR in the IPAM tree now keeps its width beside a long
  customer name (#3005, #2993).** #2995 marked the CIDR `shrink-0`, but the
  CIDR sat in a flex column, where `shrink-0` acts on the height: the column
  still collapsed to 0 px and the CIDR was drawn across the customer chip.
  The CIDR is now a direct child of the row, as the block row's is, and the
  subnet's name and the customer, site and BGP chips (capped, ellipsised,
  full text in the tooltip) give way instead.
