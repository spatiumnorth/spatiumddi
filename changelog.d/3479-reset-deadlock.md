### Fixed

- **A factory reset no longer answers 500 when the agents and the
  alert evaluation are reading the tables it wipes (#3479).** The wipe
  runs in one transaction, and its TRUNCATE queued behind any session
  reading those tables. When the minute's alert evaluation then queued
  behind the TRUNCATE while holding another of the section's tables,
  PostgreSQL ended the reset as the deadlock victim, and the page
  showed a bare 500 with nothing wiped. Every lock wait in the wipe is
  now bounded (10 seconds), and a wipe ended by a deadlock or a lock
  timeout runs again from the start, up to three times. If the tables
  stay busy through all three, the reset answers 409, saying nothing
  was deleted and to try again.
