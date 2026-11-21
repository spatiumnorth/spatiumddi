### Fixed

- A scope create, delete, restore or pool / reservation edit on a Kea hot-standby pair (or a standalone Kea) no longer reloads Kea, so it causes no HA state change and no gap in service. The image now carries Kea's `subnet_cmds` and `host_cmds` hooks, the agent applies a subnet-only change through them and falls back to the full reload on any failure, and the control plane orders the two members so neither carries a subnet its partner lacks. Upgrading the agent image still reloads each member once (upgrade the standby first); load-balancing groups keep the full reload.
