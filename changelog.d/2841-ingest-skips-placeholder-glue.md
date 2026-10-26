### Fixed

- **A dynamic zone no longer mirrors the placeholder glue (#2841).**
  A dynamic-update zone that names no name server is rendered with
  the placeholder `ns1.<zone>` and glue `ns1 A 127.0.0.1`. The DDNS
  ingest read that glue back and the control plane stored it as an
  external record nobody created, pushed it to the other servers in
  the group, and stopped warning that the name server had no real
  address. The BIND9 agent now records which zones it gave the
  placeholder glue and leaves exactly that record out of the
  read-back, and the control plane refuses it too when the zone has
  no apex NS and no usable primary NS. A row mirrored by an earlier
  build is removed by the next ingest pass. A zone with a real NS
  naming `ns1` keeps its own `ns1 A 127.0.0.1`.
