### Fixed

- The Branding audit row now records only the branding fields that changed, with their old and new values, and a branding save that changes nothing writes no row (#3847). The SSH access, DNS resolver, Syslog forwarding and APT sources rows still record a snapshot.
