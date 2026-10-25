### Fixed

- **Renaming an InfluxDB target to a taken name is refused in words (#2750).**
  Save answered 400 with the database driver's own text, SQL statement and
  parameters included. It now answers the same 409 Create gives, and any
  other failed create or update says only "create failed" / "update failed"
  (the cause goes to the log).
