### Fixed

- **A record write in flight when its zone is deleted answers 404, not
  a bare 500 (#3535).** A record create, update or delete (one record or
  in bulk) that read the zone just before a permanent zone delete took it
  went on, and its zone serial bump then matched no row once the delete
  committed (StaleDataError). An update or delete caught between the
  delete's two steps (the zone's records, then the zone row) deadlocked
  with it instead. Either way the client got a bare 500. Every record
  write now takes the zone row as it reads it, and a zone delete, soft or
  permanent, takes it before the zone's records: the request waits for
  the delete, then answers 404 Zone not found, as a request after the
  delete does. A write caught behind a soft zone delete no longer lands
  in the trashed zone.
