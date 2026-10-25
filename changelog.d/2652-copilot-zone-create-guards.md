### Fixed

- **The Copilot's "create DNS zone" no longer writes a duplicate zone (#2652).**
  Apply skipped the existing-zone check the REST create runs, and the
  `(group, view, name)` unique constraint cannot catch a twin when the view
  is NULL, so a repeated or stale proposal stored a second zone that stops a
  BIND group converging. Preview and apply now both refuse an existing name
  and an `admin_email` the REST create would reject, through
  helpers shared with the REST handler.
