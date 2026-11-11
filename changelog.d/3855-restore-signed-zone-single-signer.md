### Fixed

- Restoring a DNSSEC-signed zone from the Trash is refused, with the single-signer reason, when its group has gained a second DNS server since the zone was deleted. Before, the zone came back signed into a two-server group, which resolvers see as mismatched DNSKEYs (SERVFAIL). Remove the extra server, then restore. (#3855)
