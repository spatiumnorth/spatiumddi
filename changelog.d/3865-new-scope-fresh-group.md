### Fixed

- New DHCP Scope now reads the subnet's DHCP group and gateway fresh each time it opens, selects the group the subnet has now (it used to keep a cached one and create the scope there), and says it is reading the group instead of claiming none is set (#3865).
