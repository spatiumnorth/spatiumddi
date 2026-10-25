### Fixed

- **Restoring a DNS zone no longer publishes the records of a subnet
  that is in the Trash, or was purged since (#2732).** A zone deleted
  before a subnet whose hosts it published took those auto-generated
  A / AAAA / PTR records into its own Trash batch, and the subnet's
  later delete only retracts records that are still live. Restoring
  the zone then brought them back and the DNS servers answered them
  while the subnet was still in the Trash. If the subnet had been
  purged, the records came back owned by nothing, and nothing would
  ever withdraw them. A zone restore now leaves those records in the
  Trash with their subnet: they move to the subnet's deletion batch,
  come back when it is restored and go if it is purged. The restore
  response lists them under `held_back`, one entry per subnet. Purging
  a subnet now also deletes the trashed records bound to its addresses,
  whichever batch holds them. Records already orphaned by an earlier
  purge are not repaired.
