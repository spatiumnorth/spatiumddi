### Fixed

- Records at the apex of an RFC 2317 classless reverse zone (NS, TXT at `@` in `64/26.2.0.192.in-addr.arpa`) are accepted again: the zone's own `/` label was read as the record's and refused with a 422, and the zone-file importer silently dropped the apex NS.
