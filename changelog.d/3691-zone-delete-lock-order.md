### Fixed

- A permanent DNS zone delete no longer deadlocks with a DHCP lease report: the delete now locks the IPAM address rows it detaches from the zone's records before it takes the zone, in the same order the lease path uses, so neither side answers a 500. The Trash purge of a zone does the same.
