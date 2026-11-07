### Fixed

- A permanent DNS zone delete, and a permanent delete of one or several DNS records, no longer deadlocks with a DHCP lease report: the delete now locks the IPAM address rows it detaches from the deleted records before it takes the zone, in the same order the lease path uses, so neither side answers a 500. The Trash purge of a zone does the same.
