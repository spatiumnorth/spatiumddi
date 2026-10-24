### Fixed

- **A zone's own `allow_query` is enforced on Technitium, and the group
  `blackhole` list is rendered (#2263).** Both restrict who may use the
  server, and both were accepted, stored and enforced nothing. The
  Technitium agent applied only the group's `allow_query`, so a primary,
  secondary or stub zone restricted to internal clients stayed open on a
  Technitium group; it now sets the zone's own list as that zone's query
  access, as BIND does with a zone-level `allow-query` (an empty or unset
  list inherits the group's, and a forward zone keeps the group's, as on
  BIND). A zone list Technitium cannot express (`localnets`, a key, an
  undefined ACL) is refused with a 422 naming `allow_query`, like
  `allow_transfer`; one stored before this is listed in the options
  page's Technitium warnings and left as the daemon has it on an
  existing zone. A primary the agent creates with such a list is released
  from its creation hold to the group's list rather than to `Allow`, and
  moving a zone with such a list into a Technitium group is refused too.
  `blackhole` is now shipped in the agent
  bundle and rendered as `blackhole { … };` in BIND9's `options`, so a
  listed client gets no answer at all. Technitium and PowerDNS have no
  way to drop a client by address, so setting it on a group with either
  is a 422 naming `blackhole`. A group with no blackhole keeps a
  byte-identical `named.conf` and an unchanged bundle.
