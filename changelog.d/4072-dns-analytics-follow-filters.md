### Fixed

- Logs > DNS Queries: the analytics strip can now follow the client (address, prefix or CIDR), name, type, view and outcome filters. Turn on "Analytics follow filters" on the strip to see, for example, the busiest hosts and most-asked names for `192.0.2.0/24`; the header names the filters in use. It is off by default, so the strip still covers the whole window until you opt in. `POST /logs/dns-queries/analytics` accepts the same filters as `/logs/dns-queries`.
