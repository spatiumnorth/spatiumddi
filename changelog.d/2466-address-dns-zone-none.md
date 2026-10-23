### Fixed

- **DNS Zone "None" now keeps an address out of DNS (#2466).** Allocate
  IP's "None (no DNS record)" sent no zone, which the API reads as "use
  the subnet's zone", so the A and PTR were published anyway. The dialog
  now sends `dns_zone_id: ""`, which Allocate and Next available honour
  with no forward zone and no records (absent or null still means the
  subnet's zone). An untouched Edit address Save on an address with no
  forward zone no longer resolves the subnet's zone and puts back the
  records "None (remove DNS record)" removed.
