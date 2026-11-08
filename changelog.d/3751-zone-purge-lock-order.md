### Fixed

- The 30-day Trash sweep and the reverse-zone purge of a deleted subnet now lock every zone's IP address rows in one ascending pass before purging any zone, the order an IPAM to DNS auto-sync batch uses, so the two can no longer deadlock and have one of them rolled back (#3751).
