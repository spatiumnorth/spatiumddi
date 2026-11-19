### Changed

- The blocklist memory estimate (the warning on a group's Views and Blocking Lists tabs, and the `dns_memory_pressure` alert) now uses the measured cost of 1.1 kB per RPZ owner per view, down from 1.4 kB, and `DNS.md` documents the figures measured on BIND 9.20.30, including the reload peak, and that DNSRPS is not supported.
