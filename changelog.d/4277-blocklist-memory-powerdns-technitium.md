### Changed

- Documented blocklist memory for the other DNS drivers: PowerDNS (Authoritative) applies no blocklists, so there is nothing to size, and Technitium costs about 1.9 kB per blocked name with no per-view multiplier, measured on 15.6.2 with the same lists as the BIND9 figures. The memory warning stays BIND9-only. (#4277)
