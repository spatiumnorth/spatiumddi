### Fixed

- **A LOC record typed as Add Record's own example is no longer drift
  for good (#2925).** The drift and Sync-with-servers comparison keyed
  `37 23 30.900 N 121 59 19.000 W 7m` and the `7.00m` the AXFR reader
  prints as different values, so the record showed as missing on the
  server and extra on it at once while the zone read in sync, and each
  Sync imported the served spelling as a second row. LOC values now
  compare in the form the server reads back: parsed, round-tripped
  through the wire encoding (a typed `15m` size is served as `10.00m`,
  since sizes are one digit times a power of ten) and printed again,
  with lower-case direction letters accepted. TLSA and SSHFP had the
  same bug for hex split by spaces, padded fields (`03`) and long data
  the reader prints in chunks, and compare the same way. A CAA value
  written without quotes (`0 issue letsencrypt.org`) had it against
  the quoted form, and now compares as flags (as a number), tag
  (case-insensitive, RFC 8659) and value, with the value's case kept
  and an unquoted value taken whole, so `ca.org; account=1` and
  `ca.org; account=2` stay two records. Nothing about how a record is
  stored or sent changes.
