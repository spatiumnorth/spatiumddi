### Fixed

- An IP address request in a subnet bound to a forward or secondary DNS zone no longer says it "publishes A host.zone": it now says no record is published, because SpatiumDDI writes records only into primary zones (#3833).
