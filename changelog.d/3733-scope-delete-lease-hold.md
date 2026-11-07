### Fixed

- **Deleting a DHCP scope no longer holds up its leases' lease events
  (#3733).** The delete tore the scope's leases down inside its own
  transaction, which locks every lease row of the scope first, then
  purges them one by one, revoking each lease's DDNS records: about
  100 ms a lease. Every lease-events batch renewing one of those leases
  waited for the whole delete, so with about 1,000 leases the API
  refused those batches with a 503 at its 30 s statement timeout, and
  the delete answered 504 at the proxy's 60 s while it went on to
  commit. The scope now goes to the Trash first, and its leases are torn
  down after, in batches that each commit, for up to 20 s in the
  request (the server delete's bound) and in a background task after
  that. The lease sweep finishes any scope in the Trash whose task was
  lost.
- **A lease-events batch no longer writes leases back into a deleted
  scope (#3733).** The agent resends the batches the API refused while
  a scope delete ran, and those, or a batch that read the scope before
  the delete committed, inserted the deleted leases again, with their
  IPAM mirrors and live DDNS records, since the subnet itself stays
  live. Events for an address of a scope in the Trash are now
  acknowledged and not written.
