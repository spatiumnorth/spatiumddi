### Fixed

- **A block's allocated count no longer goes stale after tree writes
  (#2412).** Move to Trash of a subnet or block left the parent
  block counting the trashed addresses, and a New Block that adopts
  existing subnets (or a plan apply) read 0 allocated and 0 total
  until the hourly recount. The cross-space block move and a trash
  restore skipped the recount the same way. Each now recomputes the
  affected block chain inline, as #509 did for the other writes.
