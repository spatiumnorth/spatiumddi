### Fixed

- **A Rolling Upgrade moves the Redis master off a node before draining
  it, and the worker's liveness probe rides out a broker failover
  (#2815).** Draining the node that held the Redis master left the
  failover to a Sentinel election, which on three nodes can split
  (`-failover-abort-not-elected`) and leave the broker with no master
  for about 128 s. The worker driving the upgrade then failed its
  broker-round-trip liveness probe and was restarted with the drive
  inside it. A new `move_redis_master` step, between
  `verify_primary_moved` and `drain`, sends `SENTINEL FAILOVER` when
  the master is on the node and waits until every Sentinel names a
  master on another node. It never fails the node: a master it cannot
  move is a warning in the step log and the drain goes ahead, as
  before. The worker probe is now `python -m app.worker_liveness`: a
  failed ping while the broker is unreachable is not counted for 300 s
  after the last good ping, so a worker is still restarted within
  7.5 min whatever the broker does, and a worker that does not answer
  on a healthy broker still fails at once.
