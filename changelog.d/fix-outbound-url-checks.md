### Fixed

- The ACME client now connects only to addresses outside loopback, link-local and cloud-metadata ranges (private ranges stay reachable for internal CAs), requires https for every URL a CA directory lists, and no longer stores non-ACME response bodies in an order's error. Network tools (port test, TLS certificate, dig `@server`) and nmap targets now recognise `localhost` and short or numeric IPv4 spellings of the same blocked addresses, and the socket tools connect to the address they checked.
