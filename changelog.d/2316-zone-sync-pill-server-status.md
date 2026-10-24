### Fixed

- **Zone sync pill counted an unreachable server as in sync
  (#2316).** `GET .../zones/{id}/server-state` compared only the serial
  a server last reported, so a server that went down after matching the
  target still read "3/3 synced". Each entry now carries `freshness`
  (`ok` / `unreachable` / `paused`) and `counted`; a server that is not
  active is never in sync, and a paused (maintenance) server is left out
  of the count and shown as "paused" in the pill.
