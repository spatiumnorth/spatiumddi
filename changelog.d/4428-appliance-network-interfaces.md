### Added

- **Appliance: manage additional network interfaces (#4428).** From
  Appliance, Fleet, the node, Network interfaces, and from the API:
  static IPv4 / IPv6 addresses, 802.1Q VLAN sub-interfaces, static
  routes (for example back to a DHCP relay's subnet), MTU and link
  up/down. A change that could cut the node off (the primary interface,
  overlapping subnets, a route covering the cluster's own addresses, a
  default route) is refused with the reason. An applied change that
  leaves the node unable to reach the control plane is rolled back by
  the node itself and reported as `reverted`. The copilot gains
  `find_appliance_network_interfaces` (on) and
  `propose_appliance_network_interfaces` (off by default).

### Migrations

- `f4a7d2c81e59` — #4428, adds `appliance.desired_network_interfaces`.
