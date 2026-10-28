### Fixed

- **A LOC record typed as Add Record's own example is no longer drift
  for good (#2925).** The drift and Sync-with-servers comparison keyed
  `37 23 30.900 N 121 59 19.000 W 7m` and the `7.00m` the AXFR reader
  prints as different values, so the record showed as missing on the
  server and extra on it at once while the zone read in sync. LOC
  values now compare in dnspython's canonical presentation on both
  sides, so any spelling of the same location is one record. A CAA
  value written without quotes (`0 issue letsencrypt.org`) had the
  same permanent mismatch against the quoted form the server reads
  back, and compares canonically now too. Nothing about how a record
  is stored or sent changes.
