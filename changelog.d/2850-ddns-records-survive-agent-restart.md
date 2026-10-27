### Fixed

- **A record added by RFC 2136 survives a BIND9 agent restart and a
  re-render (#2850).** A record a domain controller or DHCP server
  added by dynamic update was lost when the dns-bind9 container
  restarted (a reboot, a pod restart, a rolling upgrade) unless its
  ingest mirror existed when the agent last fetched its bundle: the
  start rendered each zone from the cached bundle and set named's own
  zone file and journal aside. A structural re-render on a running
  named dropped it the same way. Before the swap, the agent now reads
  each dynamic zone back as named would load it (file plus journal)
  and carries every record set the control plane does not account for
  into the new file. A record the control plane deleted while the
  agent was down is not brought back: each dynamic zone's file has a
  `.owned` sidecar of what the control plane rendered or sent by
  record op. A merge `named-checkzone` refuses holds the zone back on
  named's own copy instead of dropping the records.
  A record a third party deleted after the ingest had mirrored it is
  not brought back either: the bundle marks each mirror row `learned`,
  and at a start or re-render the agent leaves out a mirrored record
  named held and no longer does, so the next sweep removes the mirror
  instead of reading the record back and keeping it forever.
