### Fixed

- **Upgrading a cluster node by node from Fleet no longer takes DNS and
  DHCP away from the nodes not yet upgraded (#3136).** With no Rolling
  Upgrade running there was no hold on the cluster's shared agents chart:
  the first node to boot its new slot rewrote it with its own image tag,
  and every node still on the old slot lost its DNS and DHCP pods to
  ErrImageNeverPull until it was upgraded too. While the cluster members
  report different installed versions, the control plane now holds every
  member's writes to that chart, and a node Fleet has scheduled hears of
  it before its reboot; the chart moves once every member runs one
  version. It takes effect for upgrades from this release on: the hold
  is decided by the control plane the cluster runs during the upgrade.
