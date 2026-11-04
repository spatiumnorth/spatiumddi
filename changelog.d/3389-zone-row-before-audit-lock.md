### Fixed

- **Changing a zone's settings while records are being created on it
  no longer deadlocks into a 500 (#3389).** Saving the Dynamic Updates
  dialog with the "Accept dynamic updates" flag changed, editing the
  zone (PUT on the zone), and `apply-record` wrote the zone row only in
  their commit, after taking the audit log's chain lock, while a record
  create on the same zone holds the zone row from its serial bump and
  takes the chain lock at its own commit. PostgreSQL aborted one of the
  two and it answered 500. Those three now write the zone row before
  the chain lock, the order every record write already takes.
