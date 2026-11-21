### Fixed

- DNS agent bundle renders are now counted by reason in `dns_agent_bundle_renders_total{reason}`, so the cost of a record change in a split-horizon group can be measured (#2242). No behaviour change.
