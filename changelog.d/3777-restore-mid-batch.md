### Fixed

- Restoring a DHCP scope, or the subnet, block or space holding it, from the Trash while its leases are being torn down now waits for the teardown batch in flight (at most 25 leases) and answers only once the teardown has stopped; no lease goes after the restore answers (#3777).
