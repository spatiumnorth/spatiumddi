### Fixed

- Restoring an ALIAS record from the Trash into a PowerDNS group whose plain-DNS (Do53) forwarders were cleared meanwhile is now refused, as creating one is; it used to come back live and answer nothing.
