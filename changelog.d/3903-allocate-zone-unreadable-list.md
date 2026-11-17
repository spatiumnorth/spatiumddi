### Fixed

- Allocate IP and Bulk allocate no longer tell a user whose grant names one subnet that the subnet "Requires a DNS zone" (and disable Add alias) when the subnet has one: the zone list is refused to that grant, so the dialogs now follow the subnet's own effective DNS and say the address is published in the subnet's zone, whose name is not shown (#3903).
