### Fixed

- A Helm upgrade from `2026.10.02-1` or older with DHCP agents no longer leaves Kea on the old image and times out `helm upgrade --wait` (#3907). A `pre-upgrade` hook now deletes a DHCP agent pod that is Running but has been not Ready for 2 minutes, which the `OrderedReady` StatefulSet would never roll; Ready pods are never touched. Opt out with `dhcpAgents.upgradeUnstickPods: false`.
