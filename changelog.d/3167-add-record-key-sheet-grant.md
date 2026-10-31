### Fixed

- **The `?` shortcuts sheet no longer lists the Add Record key to a role
  that writes DNS zones but not records (#3167).** Since #3100 a zone's
  Add Record and its `n` key need write on DNS records, but the sheet
  still listed `n` for a write grant on server groups, zones or records,
  so such a role was offered a key that opens nothing. The sheet now asks
  for write on DNS records, as the key does.
