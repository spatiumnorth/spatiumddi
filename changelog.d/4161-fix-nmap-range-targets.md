### Fixed

- Port-scan targets written as dotted digit ranges (such as `10.0.0.1-20`) are now refused with a validation error instead of being expanded by nmap; use a single address, a CIDR within the size limit, or a hostname.
