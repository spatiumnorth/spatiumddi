### Fixed

- Deleting a subnet, block, space or DHCP server group no longer holds every lease row of its scopes until it commits. The delete now puts them in the Trash and commits first, then tears the leases down in committed batches (as the scope delete does since #3733), so lease-events batches renewing them keep answering and the DELETE no longer runs into the proxy timeout (#3744).
