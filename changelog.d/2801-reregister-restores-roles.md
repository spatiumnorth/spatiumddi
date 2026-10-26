### Fixed

- **A control-plane node that re-registers after losing its Fleet row
  gets its roles back (#2801).** Since #2786 a lone control-plane node
  whose row goes away (a database restore that lacks it, a manual
  delete) re-registers by itself, but the roles lived on the row: it
  came back approved, heartbeating, with no roles, and its DNS and DHCP
  stayed down until an operator assigned them again. Nothing on the row
  said the roles were lost. The supervisor now reads the roles it was
  serving back from its role env (`role-compose.env`, rewritten by every
  accepted heartbeat, so a role the operator removed is not in it) and
  sends them, with the DNS and DHCP group names, on the re-registration.
  The control plane restores them only on a self-bootstrap registration,
  applies the checks a new Fleet role gets (one DNS engine, its module
  on, a group restored by name only if it still exists), and writes an
  `appliance.roles_restored` audit row naming what it restored and what
  it dropped. A registration with an operator-typed code never takes
  roles from the node; it records them as `roles_not_restored`. The
  revocation teardown also drops the role-apply stamp, so the first
  heartbeat after the node is approved again re-creates the role chart
  the teardown deleted instead of skipping it as unchanged and leaving
  DNS and DHCP down until the watchdog's next pass (up to 5 minutes).
