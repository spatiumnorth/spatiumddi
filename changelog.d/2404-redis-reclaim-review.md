### Fixed

- **A node back under a name the Redis reclaim still owes keeps its
  replica (#2404).** When a sweep failed, the seed kept the names it
  had evicted owed and freed their claims on a later heartbeat with
  no look at the Node list. A node that rejoined under the same
  hostname in the meantime lost its running replica's claim and pod,
  and the replica resynced from the master. An owed name is now freed
  only while the Node list still lacks it; the names evicted on the
  heartbeat itself still go at once, as before.
- **A Redis reclaim failure is logged once however the apiserver
  words it (#2404).** The seed logged a failed sweep once per error
  text, and the text quoted the answer's body, so a body that changed
  from one heartbeat to the next was logged every time and the texts
  it kept grew until a sweep succeeded. It now logs once per request
  and status, names that kind in the line, and keeps at most eight
  kinds.
