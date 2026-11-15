### Fixed
- DNS: a DDNS renewal no longer reads every record of its forward zone to check who holds the name. A new index on `dns_record (zone_id, lower(name))` serves the name-holder check (#3807).
