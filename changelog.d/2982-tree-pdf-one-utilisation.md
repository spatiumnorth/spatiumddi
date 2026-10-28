### Fixed

- **The IPAM tree PDF states one utilisation per block and keeps
  address families apart (#2982, #2983).** The Summary computed its
  own ratio over the scope's subnets (a full /30 subnet read 100%)
  while the Blocks row printed the block's stored figure over the whole
  CIDR (50%), and it added IPv6 sizes, clamped at 2^63 - 1, to the IPv4
  totals. The Summary now has per-family rows (IPv4 / IPv6 addresses,
  allocated, utilization) taken from the scope's top-level blocks and
  computed with the same helper as the API's block utilization, and an
  IPv6 subnet prints its true size instead of the clamp.
