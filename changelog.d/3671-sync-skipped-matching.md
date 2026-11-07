### Fixed

- **Sync with server's push section counts the records that already matched
  (#3671).** Its "Skipped, DB already matches server" figure was a fixed 0
  even when every record of the zone was already on the server, beside a pull
  section reading "Already in DB 2". The answer now carries the count, taken
  from the same comparison the push uses, and the dialog shows it.
