### Fixed

- A forward or stub zone can no longer reach a group that has a PowerDNS server by any path: the zone API (create, convert, move), the Copilot's `create_dns_zone`, the DNS importer, and the zone-move preview and commit refuse it, and a PowerDNS server cannot be added to or moved into a group that already holds one. The zone form no longer offers those types. PowerDNS cannot serve a forward zone (it answered REFUSED while the zone showed as applied) and created a stub as a full secondary. Zones already stored that way stay editable (#4570).
