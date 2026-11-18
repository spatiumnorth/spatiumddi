### Fixed

- A subnet utilization or DHCP pool exhaustion alert rule with a threshold of 5% or less now resolves once the subnet or pool empties; its resolve floor used to be 0% or below, which no reading is under, so the alert stayed open for ever (#3831).
