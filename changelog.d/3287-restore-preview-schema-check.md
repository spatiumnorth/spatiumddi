### Fixed

- **The restore card no longer offers an archive from a newer schema
  (#3287).** The backup manifest preview now runs the restore's own
  schema-direction check, so an archive whose schema head this install
  cannot place shows as not restorable, with the reason, and Apply
  stays disabled. The destination "Restore from archive" dialog now
  blocks a Full restore the same way.
