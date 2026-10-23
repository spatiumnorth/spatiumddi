### Fixed

- **Sync DNS no longer offers, or deletes, another subnet's orphaned
  records (#2577).** An auto-generated A or AAAA record whose IPAM
  address was deleted keeps no link back to it, and the stale scan
  reported every such orphan in a subnet's forward zone as that
  subnet's own. On a zone shared by several subnets or spaces, one
  subnet's Sync DNS listed all of their orphans, already ticked, and
  auto-sync with "delete stale" on deleted them. The scan now reports
  a forward orphan only when its address lies inside the subnet, as
  #1840 already did for PTRs; a record whose value is not an address
  is not reported. The subnet, block and space commits recompute their
  own stale set on the server and delete only IDs that set lists: any
  other ID in the request is ignored, never deleted, and returned in
  the new `skipped_stale_record_ids` response field. The Sync DNS
  dialog no longer pre-selects stale records. Missing and mismatched
  rows are still selected by default, but a deletion must be ticked.
  One case stays ambiguous: an orphan whose address lies in two
  subnets with the same CIDR in different spaces records nothing that
  says which it came from, so both subnets report it.
