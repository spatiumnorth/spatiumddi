### Fixed

- Delete permanently on a shared auto-created reverse zone's own Trash row no longer destroys another trashed subnet's PTR records. While the zone still holds the trashed records of a subnet in another Trash batch, the purge is refused with a 409 that names that subnet and the way out (purge it first, or purge or restore the subnet the zone was deleted with), so that subnet's restore still brings back its reverse zone and PTRs. The Trash dialog for a DNS zone now says so.
