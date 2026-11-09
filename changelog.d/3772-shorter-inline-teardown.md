### Fixed

- Scope, subnet, block, space and server-group deletes spend at most 10 s (was 20 s) tearing down leases inside the request and hand the rest to the background task, so they no longer answer in 23 to 30 s, close to the 30 s statement limit (#3772).
