### Fixed

- A Helm upgrade from `2026.10.02-1` or older with DHCP agents no longer leaves Kea on the old image and times out `helm upgrade --wait` (#3907). A `pre-upgrade` hook now deletes a DHCP agent StatefulSet (its volumes are kept) whose pod is Running but has been not Ready for 2 minutes, so the upgrade recreates it from the new template; Ready StatefulSets are never touched. Opt out with `dhcpAgents.upgradeUnstickPods: false`.
