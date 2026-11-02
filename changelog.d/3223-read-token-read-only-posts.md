### Fixed

- A `read`-scoped API token can now call the POST routes that only read: the DNS query log and its analytics, the DHCP activity log, the MAC-vendor lookup, and the side-effect-free previews and validations. They used to answer 401 because every POST was treated as a write. A token whose scope doesn't cover a request now gets 403 instead of 401, so a client no longer drops a valid token; invalid, revoked and expired tokens still get 401. The Windows Event Log and DHCP audit-log pulls still need a write scope, because they run commands on the Windows server (#3223).
