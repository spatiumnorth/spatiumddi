### Fixed

- Restoring a DHCP scope from the Trash while its leases are being torn down no longer loses the batch in flight: the restore now waits for that batch (at most 25 leases) and the teardown then stops on the live scope (#3777).
