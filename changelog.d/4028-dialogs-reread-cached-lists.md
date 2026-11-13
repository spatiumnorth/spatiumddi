### Fixed

- Allocate IP, Bulk allocate, New Subnet's Apply template and New DHCP Scope's Apply template now re-read the zone and template lists they pick from each time they open, and wait for the answer, so a primary zone or template another client changed moments ago is no longer applied from a cached copy (#4028, #4029).
