### Fixed

- **A re-enabled agent-based DNS server serves the records changed
  while it was disabled (#2281).** A disabled server gets no record
  ops, and its agent keeps serving its last config. In a group
  without views, re-enabling it shipped the current records in the
  bundle, but the agent re-renders zones only when the structural
  etag moves, and records are not part of it. So every record added,
  changed or deleted while the server was off stayed missing or wrong
  on it until an unrelated structural change or an agent restart;
  deleted records kept resolving there. Re-enabling now bumps a
  per-server counter folded into that server's structural etag, so
  its agent re-renders every zone from the current records on the
  next bundle. Record ops still queued from before the disable are
  retired at the same time: each carries the whole RRset as it was
  when queued, and shipped after the re-render it would have put back
  a record deleted in between. Moving a server to another group bumps
  the same counter, since the move drops its queued ops too. Pausing a
  server (maintenance mode) is unaffected: its ops keep queueing and
  ship in order on resume.

### Migrations

- `e4b8c27d91f3` — #2281, adds `dns_server.zone_resync_seq` (Integer,
  NOT NULL, server default 0). Zero adds nothing to the structural
  etag, so no agent re-renders on upgrade. Downgrade drops the column.
