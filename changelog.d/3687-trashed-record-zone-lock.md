### Fixed

- A permanent DNS zone delete could deadlock with the orphan lease mirror sweep, a DHCP server delete, a reservation delete that hands its address to a lease, or the DNS auto-sync's DDNS re-apply (and, narrowly, a lease-events batch): each deleted an address's trashed DNS record in the zone before locking that zone, while the zone delete locks the zone first and then deletes its records. These now lock the zones of the trashed records too, in the same order as the zones they write, before the first delete (#3687).
