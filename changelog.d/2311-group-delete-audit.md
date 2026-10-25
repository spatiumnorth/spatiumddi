### Fixed

- Deleting a DNS or DHCP server group now writes one audit row for each trashed zone or scope it purges (name, view and record count for a zone), as a Trash purge does, instead of only the group's own row (#2311).
