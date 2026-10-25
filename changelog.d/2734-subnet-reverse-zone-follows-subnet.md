### Fixed

- **A subnet's auto-created reverse zone now follows it through a block or
  space delete and every purge (#2734).** Deleting a block or an IP space left
  the reverse zones its subnets had auto-created live and served, linked to a
  subnet in the Trash; purging the block, the space or a lone subnet left the
  zone behind (live and unlinked, or in the Trash and restorable for a subnet
  that no longer exists). A block or space delete now moves those zones to the
  Trash in the same batch (one restore brings them back; a zone still shared
  with a live subnet outside the batch is re-linked and stays), and a purge
  removes them. A zone left live by an earlier delete is removed by the purge
  too; it is not cleaned up on its own.
- **A subnet created with `skip_reverse_zone` no longer gets its reverse zone
  from its first named address (#2735).** The flag was consumed at create and
  not stored, so the catch-up every address sync runs created the zone it had
  opted out of. It is now a column on the subnet (`skip_reverse_zone` on the
  subnet response and update), honoured by the address sync, a resize and the
  bulk backfills; the per-subnet backfill endpoint still creates the zone when
  asked. Existing subnets read as not opted out. Migration `c6d2e84f1a97`.
