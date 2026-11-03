### Fixed

- IPv6 subnet sizes are no longer printed as the 64-bit storage cap: Find Free, the IPAM CSV/JSON/XLSX export and the Resize preview now show a /64 as 2^64 addresses (and a /63 as twice that). The API's integer count fields still saturate at 2^63 - 1 so a generated 64-bit client keeps decoding them; the exact figure is in new `free_addresses_exact` / `total_ips_before_exact` / `total_ips_after_exact` string fields. Find Free opened from an IPv6 block now starts on IPv6 with a /64 prefix, and an empty result names the family it searched (#3322, #3324).
