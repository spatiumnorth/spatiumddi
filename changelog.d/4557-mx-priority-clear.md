### Fixed

- **Clearing an MX record's Priority in Edit Record now stores the default (#4557).**
  The dialog closed as saved but kept the old priority. An empty Priority now
  resets the MX record to 10, the value a new MX record gets, and clearing an
  SRV record's priority, weight or port is refused with a 422 instead of being
  ignored.
