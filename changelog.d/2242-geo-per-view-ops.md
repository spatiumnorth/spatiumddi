### Fixed

- A DNS server group with geo steering on pools no longer re-renders every server on each record change when its BIND9 agents apply record ops per view: each geo view (and the catch-all) is sent the op with exactly the RRset its copy of the zone serves, and a change to the geo plan itself (a member's scope, an all-geo pool, an unreachable member) still re-renders. Groups holding a DNSSEC-signed zone keep the previous behaviour. (#2242)
