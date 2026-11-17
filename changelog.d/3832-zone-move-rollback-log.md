### Fixed
- A DNS zone move that failed at the provider and was rolled back no longer logs `dns_zone_moved_group`; the line is written only once the move has committed, and a rollback logs `dns_zone_move_rolled_back` instead (#3832).
