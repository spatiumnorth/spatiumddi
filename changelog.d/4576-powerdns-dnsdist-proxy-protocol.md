### Fixed

- PowerDNS behind the dnsdist front now sees the real client address: set `PDNS_PROXY_PROTOCOL_FROM` (the front's address or compose network CIDR) and the front sends PROXY protocol v2 while pdns trusts it from that source only, so `allow-axfr`, dynamic-update ACLs and the query log work through the front. The front's health check also drops from every second to every 30 seconds with a name that never exists (#4576).
