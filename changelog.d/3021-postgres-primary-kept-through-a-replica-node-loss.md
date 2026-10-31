### Fixed

- **Losing a node that holds only a database replica no longer restarts
  the primary (#3021).** On a three-node appliance, a hard power-off of a
  member that held a Postgres replica could restart the primary on a
  healthy node, so the database was away for 25 to 35 s although no
  failover was needed. Each CloudNativePG instance keeps one long-lived
  connection to the Kubernetes API server through the cluster's
  ``kubernetes`` Service, which may land on any node. When the primary's
  had landed on the node that was lost, the primary lost the API, its
  liveness probe's isolation check then failed on the replica it could not
  reach either, and kubelet restarted it. The appliance now points every
  instance at the API server on its own node (each control-plane node is a
  k3s server), so only the loss of the primary's own node takes its API
  server away. The chart's new ``postgresql.cnpg.nodeLocalApiServer``
  value is off by default and the appliance sets it on; an upgraded
  cluster rolls its database instances once, the primary last by
  switchover.
