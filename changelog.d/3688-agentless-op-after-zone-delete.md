### Fixed

- A record write to a Windows DNS or cloud-DNS zone whose provider call was still in flight when the zone was permanently deleted could reach the provider after the zone's removal, with no retry. The dispatch now re-sends the zone removal to that server, but only when the zone it was queued for no longer exists at all, the server is still in that zone's group, and no zone of that name is in the group now. A zone move, a server move, a soft delete or a re-created zone never triggers it (#3688).
