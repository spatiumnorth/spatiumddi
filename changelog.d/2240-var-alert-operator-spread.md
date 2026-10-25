### Added

- **An alert for a filling `/var`, and data-disk sizing for about 1M
  devices (#2240).** A seven-node cluster loaded towards a million
  devices filled `/var` to 88-91% on every node with no alert.
  - **`appliance_disk_usage` rule:** seeded on. It warns when a node's
    `/var` data partition passes its threshold (80% by default) and is
    critical at 87%, a few points before the kubelet starts evicting pods
    at about 90%. A node that reports no `/var` never matches, and a
    reading that disappears or goes stale holds the open alert instead of
    resolving it.
  - **Sizing:** `docs/deployment/APPLIANCE.md` gives the `/var` each disk
    size leaves and recommends 64 GiB or more per control-plane node for
    about 1M devices.

### Fixed

- **The CNPG operator's two replicas no longer share a node from three
  nodes up (#2240).** Firstboot starts both on the seed, and the chart's
  preferred anti-affinity never moved them, so losing the seed took
  Postgres failover with it until they were rescheduled. The seed's
  supervisor now makes the operator's hostname anti-affinity required
  once the cluster has three nodes, and removes it below three. An
  existing cluster takes one rollout of the operator on the first
  heartbeat after upgrading.
