### Fixed

- Appliance SNMP: the UDP 161 firewall rule is now limited to the "Allowed source CIDRs" list, for v2c and v3 alike, instead of accepting every source whenever SNMP is on. An empty list still leaves the port open to any source (the Settings text now says so), and a malformed entry refuses the apply rather than opening the port. (#2153)
