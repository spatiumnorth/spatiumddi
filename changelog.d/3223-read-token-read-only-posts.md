### Fixed

- A `read`-scoped API token can now call the POST routes that only read: the `/logs/*` queries (Event Log, DHCP audit, DNS queries and analytics, DHCP activity), the MAC-vendor lookup, and the side-effect-free previews and validations. They used to answer 401 because every POST was treated as a write. A token whose scope doesn't cover a request now gets 403 instead of 401, so a client no longer drops a valid token; invalid, revoked and expired tokens still get 401 (#3223).
