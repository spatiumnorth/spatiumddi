### Fixed

- A forward or stub zone can no longer be created, converted to, or moved onto a group that has a PowerDNS server: the API refuses it with a 422 and the zone form no longer offers those types. PowerDNS cannot serve a forward zone (it answered REFUSED while the zone showed as applied) and created a stub as a full secondary. Zones already stored that way stay editable (#4570).
