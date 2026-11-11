### Changed

- **Upgrading to 1.0.0 from 2026.10.02-1 (#3915).** On a multi-node
  appliance cluster still on 2026.10.02-1, do not use the Rolling Upgrade
  tab: its upload answers 502 (#1174) and its Plan answers 409
  `replication_lag` (#1445). Upgrade each node from Fleet instead, with
  Upgrade "From external URL" and then Reboot, members first and the seed
  last. Nodes still on 2026.10.02-1 serve no DNS or DHCP once the first
  node boots 1.0.0 (#3136), so plan another resolver and DHCP path, and
  about 47 minutes for three nodes. A single appliance, Compose and Helm
  upgrade as usual (Helm with DHCP agents: #3907). The steps are in
  `docs/deployment/APPLIANCE.md`, "Upgrading to 1.0.0".
