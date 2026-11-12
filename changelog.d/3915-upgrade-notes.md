### Changed

- **Upgrading to 1.0.0 from 2026.10.02-1 (#3915).** On a multi-node
  appliance cluster still on 2026.10.02-1, do not use the Rolling Upgrade
  tab: its upload answers 502 (#1174) and its Plan answers 409
  `replication_lag` (#1445). Upgrade from Fleet instead: stage every node
  first (Upgrade "From external URL", one node at a time, no reboot),
  wait about 5 minutes, then reboot the members one at a time and the
  seed last. That order kept DNS and DHCP on at least two nodes
  throughout the drill; upgrading and rebooting each member in turn
  instead leaves nodes not yet upgraded without DNS and DHCP (#3136). The
  seed's Fleet Reboot does nothing on 2026.10.02-1, so reboot it from its
  hypervisor, and afterwards the API can show "initialising" for hours
  while the 1.0.0 migration waits on a stale database session; the notes
  give a manual way out. A single appliance (under 10 minutes, DNS down
  about 4 minutes), Compose and Helm upgrade as usual (Helm with DHCP
  agents: #3907). The steps are in `docs/deployment/APPLIANCE.md`,
  "Upgrading to 1.0.0".
