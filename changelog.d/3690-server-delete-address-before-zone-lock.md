### Fixed

- Deleting a DHCP server could deadlock with a permanent DNS zone delete: the server teardown locked its leases' DNS zones before the address rows it then rewrites, while the zone delete locks those address rows first. The teardown (and the scope / subnet delete paths that share the zone pre-lock) now lock the address rows first, in id order (#3690).
