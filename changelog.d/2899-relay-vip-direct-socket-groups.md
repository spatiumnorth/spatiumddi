### Fixed

- **A DHCP server group in direct mode can no longer be put behind the
  DHCP relay VIP without a word (#2899).** In direct (raw socket) mode,
  the relays that kube-proxy keeps on the node announcing the MetalLB
  relay VIP got no answer, about one relay in N on an N-node cluster:
  Kea's raw socket drops the frame still addressed to the VIP, and raw
  mode discards the copy kube-proxy hands its UDP socket. No packet
  counter showed it. Relay mode answers them. SpatiumDDI does not switch
  a group's mode on its own, because relay mode stops directly attached
  clients being served. Instead, turning the relay VIP on is refused
  while a group it would front is in direct mode, and so are switching
  such a group to direct and assigning an appliance's DHCP role to a
  direct group while the VIP is set. Each refusal names the group and
  the fix. An install that already has this state keeps working as
  before: a new alert rule, **DHCP group in direct mode behind the relay
  VIP** (on by default, critical), and the MetalLB card both name the
  groups. To fix one, set its client reachability to relay. A group that
  must also serve directly attached clients keeps direct mode, and its
  relays should forward to each DHCP node's own address instead of the
  VIP.
