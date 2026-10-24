### Fixed

- **A record a DDNS writer adds to one agent server now reaches the
  group's other servers, and its mirror no longer flaps (#2654).** In a
  group with two or more BIND9 or PowerDNS agents, the ingest-back loop
  (#641) mirrored a record learned from one server without queuing a
  record op, so the other servers never served it; their own reports,
  which lacked it, then deleted the mirror, and the next report from the
  first server added it back, every 180 s, with an audit row each way.
  The reconcile now compares each server's report with its previous one:
  a record that appeared is mirrored and added on the other agent
  servers, a record that vanished is deleted and removed from the
  others, and a server that never had a record (or still holds a
  withdrawn one) is corrected rather than believed. Every op is per
  value, never a whole-RRset replace, so a value a server holds that
  has not been reported yet is never wiped. A paused server's last
  report is kept, so a writer's change made on it during the pause is
  propagated on re-enable rather than undone. A change one of our own
  ops explains waits for the next report, and a correction that fails
  is retried after 6 hours, not every sweep. A managed record taking
  over a mirrored name drops the mirror without a wire delete, as in a
  one-agent group, which behaves exactly as before. Records that *Sync
  with server(s)* or the scheduled pull import from one agent server
  are added on the group's other agent servers too, and a record with
  an op still queued to the server being read is not imported that run.
  See `docs/features/DNS.md` §19.5.

### Migrations

- `c3f8a2d61e94` — #2654, adds `dns_ingest_snapshot`: each agent
  server's last DDNS ingest report per dynamic zone.
