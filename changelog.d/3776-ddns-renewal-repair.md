### Fixed

- DHCP dynamic DNS: a lease renewal with an unchanged hostname now republishes a deleted PTR record and applies a changed DDNS TTL (subnet, block or space `ddns_ttl`) to the existing A/AAAA and PTR records, and a renamed lease is published with the current TTL instead of the old one. The TTL is only rewritten on records DDNS generated; an operator's own record keeps its TTL. An unchanged renewal still writes nothing and takes no zone lock (#3776).
