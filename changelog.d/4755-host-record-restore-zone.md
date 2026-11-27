### Fixed

- Restoring an IPAM-managed DNS record from the Trash is refused (a bulk restore reports it as skipped) when its address has since moved to another DNS zone, instead of bringing the record back into the zone the address left beside the live one in its new zone.
