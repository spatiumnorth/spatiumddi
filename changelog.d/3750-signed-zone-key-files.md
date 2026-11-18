### Fixed

- On BIND9, a DNSSEC-signed zone of 215 characters or more is now held back on its own with the reason (at most 214 characters), instead of being served unsigned with DNSSEC shown as on and no key (#3750).
