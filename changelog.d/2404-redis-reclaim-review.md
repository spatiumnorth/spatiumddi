### Fixed

- **A node back under a name the Redis reclaim still owes keeps its
  replica (#2404).** When a sweep failed, the seed kept the names it
  had evicted owed and freed their claims on a later heartbeat with
  no look at the Node list. A node that rejoined under the same
  hostname in the meantime lost its running replica's claim and pod,
  and the replica resynced from the master. An owed name is now freed
  only while the Node list still lacks it; the names evicted on the
  heartbeat itself still go at once, as before.
