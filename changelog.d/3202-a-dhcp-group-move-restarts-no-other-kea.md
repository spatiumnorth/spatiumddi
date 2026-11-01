### Fixed

- **Moving one node's DHCP group in Fleet no longer restarts Kea on
  every node of a cluster (#3202).** Every node writes the one shared
  role chart, and its dhcp-kea pod template carried the writing node's
  DHCP group as `AGENT_GROUP`. A Fleet group move of one node therefore
  changed the template, and Kubernetes replaced the Kea pod on every
  node, one at a time, a working hot-standby pair included. The
  template now carries no DHCP group. The agent used it only to pick the
  group of the server row its first registration creates, and the
  control plane now places that row in the DHCP group its appliance is
  assigned in Fleet. An agent no appliance claims (a Compose or
  Kubernetes agent) still joins the group its `AGENT_GROUP` names.
  Registration never moves an existing row, and a group move still
  moves the node's own Kea row, as before.
