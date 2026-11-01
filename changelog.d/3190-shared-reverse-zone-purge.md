### Fixed

- **Deleting one subnet permanently no longer destroys another trashed subnet's
  reverse records (#3190).** When two subnets share an auto-created reverse
  zone (two /25s of one /24) and both are deleted, the zone rides the second
  subnet's batch while the first subnet's PTRs sit in it. Purging the second
  subnet from the Trash used to purge the zone and, with it, the first
  subnet's PTRs, so its restore came back with no reverse zone and no PTR
  records and no drift reported. The zone is now handed to the first subnet's
  batch instead (and an audit row says so), so its restore brings the zone and
  its PTRs back and its own purge takes them. The daily Trash expiry and the
  permanent subnet delete (`?permanent=true`) follow the same rule.
