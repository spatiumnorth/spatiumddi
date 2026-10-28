### Fixed

- **Cluster → Overview's restart chip no longer stays amber on a healthy
  cluster (#2945).** It showed each workload's lifetime restart count in
  amber whenever above 0, and every node reboot adds one restart to every
  pod on the node. The health snapshot now also carries `recent_restarts`
  (containers whose previous instance ended in the last 15 minutes, read
  from the pod status's `lastState.terminated.finishedAt`, so it is
  stateless across api replicas) and `last_restart_at` per workload, with
  the same 15-minute window as the appliance console (#2928). The chip is
  amber only for a recent restart; otherwise the lifetime total is shown
  dim, with a tooltip saying so.
