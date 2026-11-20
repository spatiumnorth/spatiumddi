### Fixed

- Restoring an IPAM-managed DNS record from the Trash (one the record API had deleted) is refused when its address was renamed or blanked meanwhile, instead of bringing back, and pushing to the zone's servers, a name IPAM gave up beside the new one. A bulk restore reports it as skipped; delete it from the Trash and IPAM publishes the address under its current name.
