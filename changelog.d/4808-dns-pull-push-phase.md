### Fixed

- The scheduled DNS server sync no longer holds a database transaction while it pushes missing records to a Windows or cloud DNS server; it commits what the pull wrote, then sends the batch, so a slow provider cannot pin a pooled connection `idle in transaction` ([#4808](https://github.com/spatiumnorth/spatiumddi/issues/4808)).
