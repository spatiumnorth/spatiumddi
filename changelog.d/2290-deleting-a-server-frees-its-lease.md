### Fixed

- **Deleting a DHCP server stranded its IPAM mirrors and DDNS records
  (#2290).** Leases cascade with the server, and the expiry sweep walks
  leases, so the `status="dhcp"` rows and their A/PTR records were never
  freed. The delete now runs the normal per-lease teardown first
  (honouring an HA peer that still holds the address), and the hourly
  mirror sweep also frees lease mirrors that no lease row backs, so
  installs already stranded heal themselves.
