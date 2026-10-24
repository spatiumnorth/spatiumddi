### Fixed

- **A record a DDNS writer adds to one agent server now reaches the
  group's other servers, and its mirror no longer flaps (#2654).** In a
  group with two or more BIND9 or PowerDNS agents, the ingest-back loop
  (#641) mirrored a record learned from one server without queuing a
  record op, so the other servers never served it; their own reports,
  which lacked it, then deleted the mirror, and the next report from the
  first server added it back, every 180 s, with an audit row each way.
  The reconcile now compares each server's report with its previous one:
  a record that appeared is mirrored and queued to the other agent
  servers, a record that vanished is deleted and the delete queued to
  the others, and a server that never had a record (or still holds a
  withdrawn one) is corrected rather than believed. A change one of our
  own queued ops explains waits for the next report. A one-agent group
  behaves exactly as before. Records that *Sync with server(s)* or the
  scheduled pull import from one agent server are queued to the group's
  other agent servers too. See `docs/features/DNS.md` §19.5.

### Migrations

- `c3f8a2d61e94` — #2654, adds `dns_ingest_snapshot`: each agent
  server's last DDNS ingest report per dynamic zone.
