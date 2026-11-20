### Fixed

- A DNSSEC-signed zone that PowerDNS lost (lost volume, replaced node) is signed again on the next reconcile instead of being served unsigned under the old DS, and the DNSSEC card now warns that the DS changed and must be re-published at the parent (#4566).
