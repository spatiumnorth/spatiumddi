### Fixed

- **Fleet firewall rules now reach a one-node appliance (#2774).** With
  fleet-firewall enforcement on, the supervisor refused every firewall body
  the control plane rendered for a one-node install, logging
  `supervisor.firewall.refused_self_partition` on each heartbeat. Its guard
  against cutting a live etcd member off from its peers refused any body
  without an etcd peer rule, and a one-node install is an etcd member with no
  peers, so its correct body never has one. The supervisor then fell back to
  its own render, which carries no fleet rules, so an enforced rule never
  applied and the Firewall view reported drift indefinitely. The guard now
  refuses only when this node has live peers the body would shut out, the
  same test the supervisor's own render has used since #610. On a multi-node
  control plane a body missing a live peer is still refused, and the node
  still falls back to a render that admits its peers.
