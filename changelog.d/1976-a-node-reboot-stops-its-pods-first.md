### Fixed

- **A cluster node's reboot now stops its pods before the node goes
  (#1976).** The Fleet reboot that finishes a per-node upgrade (and any
  other reboot or power-off of a node) stopped the node's containers
  through systemd alone, so Kubernetes was never told. The node's pods
  stayed Ready in their Services until the cluster noticed the node's
  silence about 70 s later, and were moved 30 s after that: requests
  kept going to a node that had gone, and celery-beat had no running
  replica for that time. The kubelet now has a shutdown grace period
  (60 s, of which the last 15 s are kept for system-critical pods): it
  reports the node NotReady at once, stops its pods so their
  controllers replace them on the other nodes, and only then lets the
  reboot go on. It takes effect on the reboots of nodes already running
  this release, so the reboots that finish an upgrade to it still run
  the old way.
