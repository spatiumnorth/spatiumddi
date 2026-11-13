### Fixed
- An IPv6 prefix in the SNMP allowed sources now works: snmpd listens on all IPv6 addresses (`udp6:161`) when the list holds an IPv6 source or is empty, instead of only `::1` (#3813).
