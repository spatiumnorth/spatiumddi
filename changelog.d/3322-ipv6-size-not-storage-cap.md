### Fixed

- IPv6 subnet sizes are no longer printed as the 64-bit storage cap: Find Free, the IPAM CSV/JSON/XLSX export and the Resize preview now show a /64 as 2^64 addresses (and a /63 as twice that), and Find Free opened from an IPv6 block starts on IPv6 with a /64 prefix and names the family in an empty result (#3322, #3324).
