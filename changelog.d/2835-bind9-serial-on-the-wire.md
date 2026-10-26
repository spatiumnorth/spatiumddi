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
  each reload, so a zone named numbered itself reads out of sync instead of
  in sync. A re-render of records named already holds keeps its serial
  rather than moving one past it. A new primary zone starts at today's
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
