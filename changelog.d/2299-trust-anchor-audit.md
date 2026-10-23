### Fixed

- **DNSSEC trust anchors are audited (#2299).** Adding or deleting a
  group's trust anchor wrote no `audit_log` row, although it changes
  which signatures a validating group accepts. Both now record the zone,
  key tag and algorithm.
