### Fixed

- A Windows DNS server driven without WinRM credentials now has its zone pulls (AXFR) and RFC 2136 record updates sent to the server's DNS Port, as its health check already was, instead of the API Port field or 53 (#4822).
