### Fixed

- **One stored record with unparseable rdata no longer stops its zone
  reaching BIND9 (#2510).** The BIND9 agent wrote every stored record
  verbatim, so a row that predates the #2502 API check made
  `named-checkzone` refuse the whole zone and #882 quarantine the whole
  bundle. The agent now leaves out a record dnspython cannot read,
  renders the rest of the zone, and reports each skipped record (zone,
  owner, type, value) as a partial apply on the server's config-apply
  status and the log.
