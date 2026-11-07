### Fixed

- **A zone's served-apex rows say why the placeholder name server is
  served (#3670).** A Primary NS inside the zone with no A or AAAA
  record made the NS row ask for a Primary NS the zone already had;
  it now names that host and asks for its address record. An apex NS
  record naming `ns1.<zone>` with no address record is served glued
  to 127.0.0.1 and now shows that warning, and a declared in-zone NS
  with no address is flagged too. The records list's `served_apex`
  gains `placeholder_reason`, `unaddressed_primary_ns` and
  `unaddressed_ns`, mirroring the BIND9 agent's own notes.
