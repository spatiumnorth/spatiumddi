### Fixed

- The DNS configuration importers (BIND9, Windows DNS, PowerDNS, Technitium, cloud) no longer store a record BIND's check-names refuses, such as an A record under an `_` owner in an `_msdcs` zone, which made the whole imported zone answer SERVFAIL. The preview lists each such record and the import skips it, naming it in the result, like the record API and the zone-file import do (#4155).
