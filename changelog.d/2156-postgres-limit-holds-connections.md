### Fixed

- **The appliance's Postgres limit now holds the connections the cluster can
  open (#2156).** On a nine-node appliance the CloudNativePG primary was
  killed by its memory cgroup at 2479Mi during a bulk record load, on a node
  with 14 GiB free. The limit was sized from the seed's RAM alone, while the
  backends grew with the node count: every node's api pod keeps a pool of up
  to 30 connections, and each backend cost about 15 MiB. The api's pool per
  pod now shrinks past four nodes (10 + 20 up to four, 10 + 3 at nine), and
  the limit is never below shared_buffers + 256 MiB + the connections the
  cluster can open x ~15 MiB, counting the two the after-commit hooks hold
  per api / worker / beat process (#2782). On a 12 GiB seed that is 2479Mi
  at one node (unchanged), 2971Mi at three and 4363Mi at nine.
  `max_connections` stays 200 until the cluster can open more (from five
  nodes with four worker processes, eight with two), then follows it.
  Single nodes of 8 GiB or more render what they did; smaller single nodes
  go from 1024Mi to 1277Mi.
  Upgrading takes one Postgres rolling restart where the limit moves, and a
  promote or demote that moves it is one more. The new chart value
  `api.databasePool.{size,maxOverflow}` sets the api's pool on any install.
