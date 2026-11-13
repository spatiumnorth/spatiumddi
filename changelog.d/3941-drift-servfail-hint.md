### Fixed

- A zone's drift no longer tells the operator to check the server's allow-transfer and TCP/53 when the server answered SERVFAIL for a zone it cannot serve; it now points at the zone's primary (secondary zone) or at the zone not being loaded (primary zone) (#3941).
