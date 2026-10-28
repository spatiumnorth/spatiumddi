### Changed

- **A block's utilisation is the share of its CIDR in use: its subnets'
  network and broadcast addresses now count as used (#2982).** Since
  #2411 a block's allocated count left those addresses out while its
  total kept them, so a /30 block holding one full /30 subnet read
  2 / 4, 50%, with no free address left. The block now reads 4 / 4,
  100%. Each descendant subnet adds its non-usable addresses to the
  block's `allocated_ips`: network and broadcast for IPv4 below /31, the
  network address for IPv6 below /127, nothing for /31, /32, /127 and
  /128. An address is never counted twice, and a block is clamped to its
  CIDR size, so it cannot read over 100%. A subnet's own count and
  utilisation are unchanged. Stored block counters are corrected by the
  hourly utilisation recount, or sooner by any write under the block. No
  migration is needed.

### Fixed

- **The IPAM tree PDF states one utilisation per block and keeps
  address families apart (#2982, #2983).** The Summary computed its
  own ratio over the scope's subnets (a full /30 subnet read 100%)
  while the Blocks row printed the block's stored figure over the whole
  CIDR (50%). It also added IPv6 sizes, clamped at 2^63 - 1, to the
  IPv4 totals. The Summary now has per-family rows (IPv4 / IPv6
  addresses, allocated, utilization), taken from the scope's top-level
  blocks. An IPv6 subnet prints its true size instead of the clamp: in
  full on the subnet report, and as a power of two (`2^64`) in the
  narrow Total column of the tree report. The JSON export's block rows
  gain `allocated_ips`, which the importer ignores.
