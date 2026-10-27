### Fixed

- **A Rolling Upgrade fails the Redis master over once, not twice
  (#2870).** The `move_redis_master` step left the choice of the new
  master to Sentinel, which could pick the replica on the next node to
  drain, so that node's turn failed the master over again and dropped
  the broker a second time. The step now lowers `replica-priority` to
  1 (`CONFIG SET`) on the replica of the node that drains last, or of
  a node the roll has finished, waits for Sentinel to read it, sends
  `SENTINEL FAILOVER`, and restores the priority in a `finally`. The
  original is recorded in Redis first, so a drive that dies mid-step
  is cleaned up by the next run of the step. If the priority cannot be
  set or seen (a replica unreachable, `CONFIG` refused, fewer than
  two eligible replicas) the failover is sent as before. Priority 0 is
  never written.
