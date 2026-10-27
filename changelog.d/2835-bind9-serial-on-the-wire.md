### Fixed

- **A BIND9 zone without views serves the control plane's serial, and its
  sync state reads the serial named serves (#2835).** In a group without
  views a record change reaches named as an RFC 2136 update, and one with
  no SOA in it is numbered by named itself (1, 2, 3, …), while the agent
  reported the op's own serial as reached. So the zone read in sync at
  `2026102601` while `dig SOA` answered `3`, and two servers of one group
  could serve different serials for the same zone, both reading in sync.
  Each update now carries the op's serial as the zone's SOA, in the same
  message as the records, whenever it is later than the one named serves
  (never lower); verified against BIND 9.20, named then serves exactly that
  serial. The agent reports the serial named serves after each op and after
  each reload, and every two minutes for each zone whose served serial has
  changed since it last reported (a third party's update, a DNSSEC key
  event), so a zone named numbered itself reads out of sync instead of in
  sync. The bundle renderer revision moves to 15, so every agent re-renders
  at the upgrade rather than at its group's first change. An inline-signed zone is compared and reported at its signed
  serial, the one on the wire: when re-signing has moved it past the op's
  serial, the zone reads out of sync rather than in sync at a raw serial
  nothing answers with. An op that changes the apex NS set now also removes
  the name servers the render will no longer write (the zone's first NS, or
  the placeholder and its glue), which an RFC 2136 update otherwise leaves
  beside the new ones, and deleting the last declared NS puts back the one
  the render falls back to. A re-render of data named already holds keeps
  named's serial rather than moving one past it, so a zone can no longer
  climb one serial per structural apply. A new primary zone starts at today's
  `YYYYMMDD00` instead of 0, which named served as 1. In a fine-grained
  (`update-policy`) zone the group's own key is granted `ANY`, since BIND's
  default type list leaves out SOA (and NS); an operator key standing in
  where a group has no key of its own keeps its old grant, and its updates
  go without the SOA as before. Groups with views are unchanged: they
  re-render each change and report as before. A zone that also takes
  third-party dynamic updates (AD, a DHCP server's DDNS) can now read out
  of sync after the upgrade, because named serves a serial those clients
  moved and BIND9 does not adopt a served serial; the next record change
  from the control plane realigns it when its serial is later.
