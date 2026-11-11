### Fixed

- A DNS zone restored from the Trash now answers what IPAM holds today: an address renamed while the zone sat in the Trash gets its record under the new name instead of the old one, and an address added meanwhile gets its record. The restore re-runs the IPAM-DNS sync over the zone's subnets; records created by hand are left as they were (#3924).
