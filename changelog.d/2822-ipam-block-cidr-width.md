### Fixed

- **A block's CIDR is shown in full in the IPAM tree (#2822).**
  A block row gave its CIDR only the room its name and its customer,
  site and BGP chips left over. A block with a long name or a site chip
  showed its CIDR cut (`10.10…`, which could be 10.10.0.0/16 or
  10.100.0.0/16) or not at all. The CIDR now keeps its full width and
  it is the name that is cut with an ellipsis when the row is too
  narrow.
