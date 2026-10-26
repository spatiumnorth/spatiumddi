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
  `YYYYMMDD00` instead of 0, which named served as 1. The agent's own key
  is granted `ANY` in a fine-grained (`update-policy`) zone, since BIND's
  default type list leaves out SOA (and NS). Groups with views are
  unchanged: they re-render each change and report as before.
