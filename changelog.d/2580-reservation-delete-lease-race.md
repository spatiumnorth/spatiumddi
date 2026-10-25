### Fixed

- **Deleting a DHCP reservation seconds after its client's grant no longer
  leaves the address `available` beside the live lease (#2580).** The
  reservation DELETE decided the address's new status from the lease table,
  and the lease report decided from the address's status, each on a plain
  read. When the two overlapped, each read the other's state from before it
  committed: the DELETE found no lease and freed the address, the lease
  report found a reservation and left it alone, and IPAM offered a live
  device's address to next-free allocation until the DHCP agent next re-sent
  its leases. Both now decide while holding the address row's lock, so the
  second to arrive waits and sees what the first committed, and the address
  becomes the lease's `dhcp` row in either order. The five-minute lease
  cleanup also hands any `available` address that an active lease holds in
  the same subnet to that lease. That repairs addresses already left in this
  state, and the case no lock can prevent: a lease report the agent dropped
  after the control plane refused it. An address an operator set `available`
  after the lease was last reported is left alone, and an operator-edited
  hostname is kept. Each repair is audited as `dhcp-lease-remirror`.
