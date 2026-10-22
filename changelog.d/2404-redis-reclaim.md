### Fixed

- **A dead member's Redis replica no longer stays Pending for good
  after a replace (#2404).** The seed freed the Redis claim a deleted
  node left behind only on the heartbeat that deleted the Node, and
  never looked again. An error answer on that heartbeat was logged
  and never retried, and a Node removed any other way was never
  looked at. The claim stayed Bound to the dead node's volume, the
  replica sat `Pending` ("didn't match PersistentVolume's node
  affinity"), and Redis ran two of three with a sentinel short, so
  the next node loss could leave no failover quorum while the
  cluster read healthy. The seed now sweeps on every heartbeat, as
  it does for Postgres (#1058): the names it evicts that tick go at
  once, as before, and any other `-redis-` claim whose volume is
  pinned to a node that is no longer a Node goes as soon as its pod
  waits to be scheduled. The PV's node affinity decides, and the
  scheduler's `selected-node` annotation only when the PV is gone. A
  claim on a node that is still registered, Ready or not, is never
  touched. A healthy heartbeat costs one list of the namespace's
  Pending pods, and the reclaim logs once per claim freed and once
  per kind of failure.
