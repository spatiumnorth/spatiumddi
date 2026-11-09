### Fixed

- A record write to a Windows DNS or cloud-DNS zone whose provider call was still in flight when the zone was permanently deleted could reach the provider after the zone's removal and leave the zone or record there, with no retry. The dispatch now notices its op row was swept, and when the zone no longer exists it re-sends the zone removal (idempotent, logged) (#3688).
