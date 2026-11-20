### Fixed

- PowerDNS: AXFR now carries expanded A/AAAA data for ALIAS records (`outgoing-axfr-expand-alias=yes`), so BIND9 and other non-PowerDNS secondaries answer them instead of storing an opaque private-use type.
