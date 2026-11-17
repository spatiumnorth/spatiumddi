### Fixed

- The 30-day Trash sweep and the reverse-zone purge of a deleted subnet now lock every zone's IP address rows in one ascending pass before purging any zone, the order an IPAM to DNS auto-sync batch uses, so the two can no longer deadlock and have one of them rolled back (#3751).
- The Trash sweep purges each expired DNS zone in a savepoint. A database error while purging one zone (a deadlock, a lock or statement timeout) used to leave the sweep's transaction aborted, so its closing commit silently rolled back every zone it reported as purged, and its audit row. Now only that zone is skipped and the rest are kept (#3751).
