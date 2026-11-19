### Fixed

- The DHCP and Looking Glass agent long-polls no longer rebuild the whole config bundle from the database on every idle tick of every parked agent. A cheap version key (one query fingerprinting the tables the bundle reads) now decides whether to rebuild, the content ETag still decides what ships, and a rebuild is forced at least every five minutes regardless.
