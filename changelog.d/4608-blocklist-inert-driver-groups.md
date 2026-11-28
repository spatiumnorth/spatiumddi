### Fixed

- Assigning a blocklist to a group (or a view in it) with no BIND9 or agent-managed Technitium server is now refused with a 422. Only those two drivers render a blocklist, so on a group of PowerDNS, Windows DNS or cloud DNS servers (Route 53, Azure DNS, Cloudflare, Google Cloud DNS and the rest) the list blocked nothing while the console showed it as applied. Existing assignments stay readable and removable and carry an `unapplied_warning`; the blocklist scope dialog shows the same warning. Which drivers apply a blocklist is now a single `blocklist` driver capability.
