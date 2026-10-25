### Fixed

- **DNS Blocklists no longer shows an empty catalog over a refused read
  (#2701).** A user who may not read `dnsbl` (the IPAM, DNS and DHCP
  Editors) saw a catalog with no rows, "Last sweep never", "0 list(s)
  enabled" and "No pinned IPs." while the lists exist. Each section now says
  the user may not see it, using the server's refusal, and keeps its empty
  state only over a read that answered.
