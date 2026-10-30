### Fixed

- **A surviving node's heartbeat no longer goes stale through another
  member's loss (#3020).** On a three-node cluster a member's hard
  power-off could leave the seed's heartbeat 92 s old, past the 90 s
  after which the demote guard calls a voter unhealthy. Two supervisor
  behaviours added up. After each accepted heartbeat the seed ran its
  kube API housekeeping before sending the next one, and every call
  that reached the lost node waited out its 10 s timeout (30 s in one
  tick). And a heartbeat the API answered 5xx, which it does while the
  database is away, waited the whole 30 s interval before the next.
  That housekeeping (and the role lifecycle on every node) now runs on
  its own worker, and a heartbeat waits for it at most 5 s. A 5xx is
  re-sent like a heartbeat that never reached the API: after 5 s,
  doubling while it keeps failing.
