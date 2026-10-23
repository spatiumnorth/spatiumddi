### Fixed

- **An untouched Edit Record Save is now a no-op (#2463).** The dialog
  sends every field it shows and the API counted each as a change, so a
  Save with nothing edited bumped the zone serial, queued an "update"
  record op and audited `name`, `value`, `ttl` and `view_id` as changed.
  Only a field whose value differs now counts: an unchanged record
  returns as is, and the audit row of a zone, group, server, view, TSIG
  key or server-options update names only the fields that moved.
