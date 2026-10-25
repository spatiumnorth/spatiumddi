### Fixed

- **A revoked control-plane node whose Fleet row is still live asks
  for a fresh pairing code every few minutes, not on every heartbeat
  (#2789).** Since #2696 the running supervisor asks the
  self-bootstrap for a fresh code while the node is revoked. The
  self-bootstrap refuses while any live appliance row exists, so a
  node whose own row was still there (appliance registration switched
  off, for example) was refused on every heartbeat: each time it wrote
  and removed the self-bootstrap token file, called the api and logged
  four lines. An attempt that brings no code back now waits a minute
  before the next, doubling up to four minutes, and the wait starts
  over once the node is no longer revoked. A node whose row is gone
  still registers again at its first revoked heartbeat, and one whose
  row is deleted while it waits registers again at its next attempt.
